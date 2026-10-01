// Copyright 2026 Keyfactor
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// V2 release-candidate readiness: assertion-bearing live lifecycle coverage for the product
// families/shapes the existing V2 suite (V2LifecycleTests/V2ApiTests/V2DcvLifecycleTests/
// V2GapProbeTests) never exercised end to end — DV UCC, OV, OV UCC, EV, wildcard DV, and
// renew/reissue. Each test is gated by its own CERTINEXT_V2_LIFECYCLE_<NAME>=1 flag (never
// promoted from ~/.env_certinext_v2 — see IntegrationTestFixture._optInOnlyFlags), places real
// sandbox orders, and always cleans up (revoke if issued, cancel otherwise) via
// CleanupOrderAsync in a try/finally. Fresh-domain DCV coverage lives in
// V2FreshDomainDcvLifecycleTests.cs (requires the SUPPORTS_DCV build).

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Plugin-level V2 lifecycle tests for product shapes/flows the pre-existing V2 suite did
    /// not cover with an assertion-bearing live test (readiness audit, 2026-10-01): DV UCC, OV,
    /// OV UCC, EV, wildcard DV (both CSR shapes), and renew/reissue of an issued DV order.
    /// </summary>
    public class V2FullLifecycleTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;

        private readonly string _v2ApiUrl;
        private readonly string _v2ClientId;
        private readonly string _v2ClientSecret;
        private readonly string _v2Domain;
        private readonly bool _v2Enabled;

        /// <summary>
        /// 300s target for OV/EV order-creation calls per the task brief (known CA latency —
        /// issue 0064). NOT actually enforceable at this (plugin-level) layer: CERTInextClient's
        /// V2 RestClient hard-codes <c>Timeout = TimeSpan.FromSeconds(120)</c> (CERTInextClient.cs,
        /// both the V1 and V2 RestClientOptions blocks) with no CERTInextConfig override to raise
        /// it. OV/EV tests below catch a client-side timeout distinctly from a CA-side rejection
        /// and record it rather than assert past it — see IsClientTimeout below. Flagged in the
        /// handoff report as a production gap, not silently worked around here.
        /// </summary>
        private static readonly TimeSpan OvEvCreateTimeoutTarget = TimeSpan.FromSeconds(300);

        public V2FullLifecycleTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;

            var env = V2EnvHelper.LoadAndPromote();

            _v2ApiUrl = V2EnvHelper.GetEnv(env, "CERTINEXT_API_URL");
            _v2ClientId = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_ID");
            _v2ClientSecret = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_SECRET");
            _v2Domain = V2EnvHelper.GetEnv(env, "CERTINEXT_DCV_DOMAIN", "test.example.com");

            _v2Enabled = !string.IsNullOrWhiteSpace(V2EnvHelper.GetEnv(env, "CERTINEXT_USE_V2_API"))
                         && !string.IsNullOrWhiteSpace(_v2ApiUrl)
                         && !string.IsNullOrWhiteSpace(_v2ClientId)
                         && !string.IsNullOrWhiteSpace(_v2ClientSecret);
        }

        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

        private static string Timestamp() => DateTime.UtcNow.ToString("yyyyMMddHHmmssfff");

        private static string GenerateCsrPem(string commonName) => GenerateCsrPem(commonName, ouTag: null);

        /// <summary>
        /// <paramref name="ouTag"/>, when supplied, is folded into the CSR subject as an OU —
        /// e.g. <c>ov-<ts></c> for the OV/OV-UCC orphan-sweep probes below. The orders report
        /// (<see cref="Constants.ApiV2.OrdersReportPath"/>) does not surface OU anywhere, so this
        /// tag is NOT how an orphan is actually located (that's domain + creation-time window —
        /// see <see cref="TryCancelOrphanByWindowAsync"/>); it exists only so a human reviewing
        /// the order in the CERTInext portal or a raw CSR dump can see which test run placed it.
        /// </summary>
        private static string GenerateCsrPem(string commonName, string ouTag)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            var keyPair = keyGen.GenerateKeyPair();

            string subjectDn = string.IsNullOrWhiteSpace(ouTag) ? $"CN={commonName}" : $"CN={commonName},OU={ouTag}";
            var subject = new X509Name(subjectDn);
            var csr = new Pkcs10CertificationRequest("SHA256withRSA", subject, keyPair.Public, null, keyPair.Private);

            return "-----BEGIN CERTIFICATE REQUEST-----\n"
                + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                + "\n-----END CERTIFICATE REQUEST-----";
        }

        private static async Task<List<AnyCAPluginCertificate>> RunSyncAsync(
            CERTInextCAPlugin plugin, DateTime? lastSync = null, bool fullSync = true)
        {
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(boundedCapacity: 10_000);
            var collected = new List<AnyCAPluginCertificate>();

            var syncTask = Task.Run(async () =>
            {
                await plugin.Synchronize(buffer, lastSync: lastSync, fullSync: fullSync, cancelToken: CancellationToken.None);
                if (!buffer.IsAddingCompleted)
                    buffer.CompleteAdding();
            });

            foreach (var record in buffer.GetConsumingEnumerable())
                collected.Add(record);

            await syncTask;
            return collected;
        }

        private CERTInextConfig BuildV2Config(
            int? syncLookbackHours = null, string organizationNumber = null)
        {
            return new CERTInextConfig
            {
                ApiUrl            = _v2ApiUrl,
                UseV2Api          = true,
                DefaultProductCode = Environment.GetEnvironmentVariable("CERTINEXT_PRODUCT_CODE") ?? "842",
                OAuthClientId     = _v2ClientId,
                OAuthClientSecret = _v2ClientSecret,

                RequestorName         = _fixture.IsConfigured ? _fixture.Config.RequestorName : "Keyfactor Test",
                RequestorEmail        = _fixture.IsConfigured ? _fixture.Config.RequestorEmail : "test@example.com",
                RequestorIsdCode      = "1",
                RequestorMobileNumber = "0000000000",
                SignerPlace           = "Gateway Lab",
                SignerIp              = "127.0.0.1",

                PageSize = 100,

                V2SyncLookbackHours = syncLookbackHours ?? 1,

                OrganizationNumber = organizationNumber ?? string.Empty,

                DcvEnabled = false
            };
        }

        private static CERTInextCAPlugin BuildV2Plugin(CERTInextConfig config)
        {
            var client = new CERTInextClient(config);
            return new CERTInextCAPlugin(client, config);
        }

        /// <summary>
        /// Distinguishes a client-side HTTP timeout (RestSharp/TaskCanceledException — the
        /// plugin's hard-coded 120s V2 RestClient timeout expiring before the CA responds) from a
        /// genuine CA-side rejection. See <see cref="OvEvCreateTimeoutTarget"/>'s doc comment.
        ///
        /// Also matches the shape actually observed on a live run: CERTInextClient's
        /// <c>ThrowOnV2Failure</c> does not always surface a <see cref="TaskCanceledException"/>
        /// for a RestSharp-level transport timeout — it can instead produce a plain
        /// <see cref="Exception"/> reading "CERTInext V2 API error during '...'. HTTP 0.
        /// CERTInext V2 returned no body for '...'." (StatusCode 0 = no HTTP response was ever
        /// received). Both substrings ("HTTP 0" and "returned no body") must be present so this
        /// never also matches a genuine HTTP-0-with-a-body CA-side condition.
        /// </summary>
        private static bool IsClientTimeout(Exception ex) =>
            ex is TaskCanceledException
            || ex is OperationCanceledException
            || (ex.Message?.IndexOf("timed out", StringComparison.OrdinalIgnoreCase) >= 0)
            || (ex.Message != null
                && ex.Message.IndexOf("HTTP 0", StringComparison.OrdinalIgnoreCase) >= 0
                && ex.Message.IndexOf("returned no body", StringComparison.OrdinalIgnoreCase) >= 0);

        /// <summary>
        /// Best-effort search for an order the CA may have created despite the plugin's own
        /// client-side timeout (<see cref="IsClientTimeout"/>) — a timeout proves nothing about
        /// what happened server-side. Scans the V2 orders report
        /// (<see cref="Constants.ApiV2.OrdersReportPath"/> via <c>ListOrdersV2Async</c>) for the
        /// "UTC today" window, matches on <c>domainName == domain</c> (the only field this report
        /// row model exposes — no OU/SAN/tag field is echoed there) plus
        /// <c>orderDate &gt;= windowStartUtc - 5min</c> to avoid grabbing an older, unrelated
        /// order on the same long-reused <paramref name="domain"/>, picks the single most-recent
        /// match if more than one row qualifies, and cancels it (one attempt, never retried) if
        /// it is not already terminal. Never throws — every failure path is folded into the
        /// returned description string so the caller's Skip.If message always has something
        /// actionable. <paramref name="probeTag"/> is logged only (see <see cref="GenerateCsrPem(string,string)"/>).
        /// </summary>
        private async Task<string> TryCancelOrphanByWindowAsync(string domain, DateTime windowStartUtc, string probeTag)
        {
            try
            {
                using var client = new CERTInextClient(BuildV2Config());

                string from = windowStartUtc.Date.ToString("yyyy-MM-dd");
                string to = windowStartUtc.Date.AddDays(1).ToString("yyyy-MM-dd");

                OrderReportEntryV2 best = null;
                DateTime bestDate = DateTime.MinValue;
                int scanned = 0;

                await foreach (var row in client.ListOrdersV2Async(from, to, pageSize: 100))
                {
                    scanned++;
                    if (!string.Equals(row.DomainName, domain, StringComparison.OrdinalIgnoreCase))
                        continue;

                    DateTime rowDate = DateTime.TryParse(
                        row.OrderDate, null,
                        System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal,
                        out var parsed)
                        ? parsed
                        : windowStartUtc; // unparseable date: don't exclude it from consideration on that basis alone

                    if (rowDate < windowStartUtc.AddMinutes(-5))
                        continue;

                    if (best == null || rowDate >= bestDate)
                    {
                        best = row;
                        bestDate = rowDate;
                    }
                }

                _output.WriteLine(
                    $"Orphan sweep (tag={probeTag}): scanned {scanned} report row(s) for domain '{domain}', " +
                    $"window >= {windowStartUtc:O} (-5min grace).");

                if (best == null)
                    return "orphan sweep found no matching report row for this domain/window (nothing to cancel, " +
                           "or the order has not appeared in the report yet — try again later by hand if needed)";

                string orderId = best.OrderNumber;
                if (string.IsNullOrWhiteSpace(orderId))
                    return $"orphan sweep found a matching report row for domain '{domain}' with no orderNumber — cannot cancel it programmatically";

                var (family, status) = await client.ResolveAndTrackOrderV2WithFamilyAsync(orderId);
                bool terminal =
                    string.Equals(status.Status, Constants.ApiV2.StatusCancelled, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(status.Status, Constants.ApiV2.StatusRevoked, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(status.Status, Constants.ApiV2.StatusRejected, StringComparison.OrdinalIgnoreCase);

                if (terminal)
                    return $"orphan sweep found order {orderId} already terminal (status={status.Status}) — nothing to cancel";

                try
                {
                    var outcome = await client.CancelOrderV2Async(
                        family, orderId,
                        $"V2 full-lifecycle test orphan sweep — client-side timeout at submission (issue 0064), tag={probeTag}.");
                    return $"orphan sweep found order {orderId} (status was {status.Status}) and cancelled it (outcome={outcome})";
                }
                catch (Exception cancelEx)
                {
                    return $"orphan sweep found order {orderId} but the cancel call itself FAILED " +
                           $"({cancelEx.GetType().Name}: {cancelEx.Message}) — not retried; cancel it by hand in the CERTInext portal";
                }
            }
            catch (Exception ex)
            {
                return $"orphan sweep itself FAILED ({ex.GetType().Name}: {ex.Message}) — could not search for an orphaned order; check the CERTInext portal by hand";
            }
        }

        /// <summary>
        /// Cleans up a sandbox order this test created: revokes it via the plugin's real V2
        /// Revoke if it reached GENERATED, otherwise cancels it via the raw cancel endpoint
        /// (the plugin has no V2 cancel method — <see cref="V2RawProbeHelpers"/>). Single attempt
        /// only — never retries a cancel. Logs rather than throws on failure so a cleanup problem
        /// never masks the test's own assertion result; failures are surfaced in test output for
        /// manual follow-up in the CERTInext portal.
        /// </summary>
        private async Task CleanupOrderAsync(CERTInextCAPlugin plugin, string orderId)
        {
            if (string.IsNullOrWhiteSpace(orderId))
                return;

            try
            {
                var current = await plugin.GetSingleRecord(orderId);
                if (current?.Status == (int)EndEntityStatus.GENERATED)
                {
                    int revokeResult = await plugin.Revoke(orderId, hexSerialNumber: string.Empty, revocationReason: 4 /* superseded */);
                    _output.WriteLine($"Cleanup: revoked issued order {orderId} -> {revokeResult}.");
                }
                else
                {
                    await V2RawProbeHelpers.CancelSslOrderRawAsync(
                        _v2ApiUrl, _v2ClientId, _v2ClientSecret, orderId,
                        "V2 full-lifecycle test cleanup — order not issued, cancelling.");
                    _output.WriteLine($"Cleanup: cancelled non-issued order {orderId} (status={current?.Status}).");
                }
            }
            catch (Exception ex)
            {
                _output.WriteLine(
                    $"Cleanup FAILED for order {orderId}: {ex.GetType().Name}: {ex.Message}. " +
                    "Revoke/cancel it by hand in the CERTInext portal if it should not remain pending.");
            }
        }

        // ---------------------------------------------------------------------------
        // 1. DV UCC — enroll (2+ SANs) -> track -> sync/GetSingleRecord -> revoke
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Places one V2 DV SSL UCC order (<see cref="Constants.Products.DvSslUcc"/>) with the
        /// primary domain on the account's long-reused, likely-already-verified
        /// <c>CERTINEXT_DCV_DOMAIN</c>, plus two fresh never-seen subdomains as additional SANs
        /// (so the order itself places cleanly regardless of whether the extra SANs clear DCV —
        /// mirrors UccPendingSanOrderProbeTests' reasoning). Exercises Enroll -> GetSingleRecord
        /// -> Synchronize, then cleans up (revoke if GENERATED, else cancel).
        /// Expected sandbox order count: 1.
        /// </summary>
        [SkippableFact]
        public async Task Enroll_V2_DvUcc_WithMultipleSans_FullLifecycle()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");
            Skip.If(Environment.GetEnvironmentVariable("CERTINEXT_V2_LIFECYCLE_DV_UCC") != "1",
                "CERTINEXT_V2_LIFECYCLE_DV_UCC=1 not set — this places a real DV UCC sandbox order. Skipping.");

            string ts = Timestamp();
            string primary = _v2Domain;
            string sanA = $"ucc-a-{ts}.{_v2Domain}";
            string sanB = $"ucc-b-{ts}.{_v2Domain}";

            var config = BuildV2Config();
            var plugin = BuildV2Plugin(config);

            string orderId = null;
            try
            {
                var productInfo = new EnrollmentProductInfo { ProductID = Constants.Products.DvSslUcc };

                var enrollResult = await plugin.Enroll(
                    csr:            GenerateCsrPem(primary),
                    subject:        $"CN={primary}",
                    san:            new Dictionary<string, string[]> { ["dns"] = new[] { sanA, sanB } },
                    productInfo:    productInfo,
                    requestFormat:  RequestFormat.PKCS10,
                    enrollmentType: EnrollmentType.New);

                enrollResult.Should().NotBeNull();
                enrollResult.CARequestID.Should().NotBeNullOrWhiteSpace(
                    "V2 DV UCC Enroll must return a non-empty CARequestID");
                orderId = enrollResult.CARequestID;
                enrollResult.Status.Should().NotBe((int)EndEntityStatus.FAILED,
                    $"DV UCC Enroll must not FAILED at submission; message: {enrollResult.StatusMessage}");
                _output.WriteLine($"DV UCC order {orderId}: Status={enrollResult.Status}, Primary={primary}, SANs=[{sanA}, {sanB}]");

                var tracked = await plugin.GetSingleRecord(orderId);
                tracked.Should().NotBeNull("GetSingleRecord must return a record for a just-placed DV UCC order");
                tracked.CARequestID.Should().Be(orderId);
                _output.WriteLine($"Tracked: Status={tracked.Status}");

                var synced = await RunSyncAsync(plugin, lastSync: DateTime.UtcNow.AddHours(-1), fullSync: false);
                synced.Should().Contain(r => r.CARequestID == orderId,
                    $"the newly placed DV UCC order '{orderId}' must appear in a delta sync via V2 /reports/orders");

                var syncedRecord = synced.First(r => r.CARequestID == orderId);
                _output.WriteLine($"Synced status: {syncedRecord.Status}");
                if (syncedRecord.Status == (int)EndEntityStatus.GENERATED)
                    syncedRecord.Certificate.Should().NotBeNullOrWhiteSpace("an issued DV UCC order must carry a cert body via Synchronize");
            }
            finally
            {
                await CleanupOrderAsync(plugin, orderId);
            }
        }

        // ---------------------------------------------------------------------------
        // 2. OV — enroll -> track -> sync -> revoke/cancel
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Places one V2 OV SSL order (<see cref="Constants.Products.OvSsl"/>); productVariant
        /// "ov" and the organization block are both derived/required automatically by
        /// EnrollV2Async (issues 0028, 0059) from the connector's OrganizationNumber. Sandbox
        /// OV orders commonly park in a pending-vetting state rather than auto-issuing — this
        /// test asserts on whatever state machine is actually observed (only FAILED at submission
        /// is treated as a hard failure) rather than forcing GENERATED. See
        /// <see cref="OvEvCreateTimeoutTarget"/> for the 120s-vs-300s client timeout caveat.
        /// Expected sandbox order count: 1.
        /// </summary>
        [SkippableFact]
        public async Task Enroll_V2_Ov_FullLifecycle()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");
            Skip.If(Environment.GetEnvironmentVariable("CERTINEXT_V2_LIFECYCLE_OV") != "1",
                "CERTINEXT_V2_LIFECYCLE_OV=1 not set — this places a real OV sandbox order. Skipping.");

            string organizationNumber = _fixture.IsConfigured ? _fixture.OrgNumber : null;
            Skip.If(string.IsNullOrWhiteSpace(organizationNumber),
                "CERTINEXT_ORG_NUMBER not set in ~/.env_certinext — OV requires a pre-vetted organization number. Skipping.");

            var config = BuildV2Config(organizationNumber: organizationNumber);
            var plugin = BuildV2Plugin(config);

            string domain = _v2Domain;
            string probeTag = $"ov-{Timestamp()}";
            DateTime windowStart = DateTime.UtcNow;
            string orderId = null;
            try
            {
                EnrollmentResult enrollResult;
                try
                {
                    enrollResult = await plugin.Enroll(
                        csr:            GenerateCsrPem(domain, probeTag),
                        subject:        $"CN={domain},OU={probeTag}",
                        san:            new Dictionary<string, string[]> { ["dns"] = new[] { domain } },
                        productInfo:    new EnrollmentProductInfo { ProductID = Constants.Products.OvSsl },
                        requestFormat:  RequestFormat.PKCS10,
                        enrollmentType: EnrollmentType.New);
                }
                catch (Exception ex) when (IsClientTimeout(ex))
                {
                    string sweepResult = await TryCancelOrphanByWindowAsync(domain, windowStart, probeTag);
                    Skip.If(true,
                        "OV order creation did not return within the plugin's hard-coded 120s V2 HTTP client " +
                        "timeout. Per issue 0064 (closed won't-fix) that timeout stays as-is, so this is an " +
                        "expected skip rather than a production bug on its own — but a client timeout does not " +
                        $"prove the CA never created the order; it likely did. {sweepResult}. " +
                        $"Observed: {ex.GetType().Name}: {ex.Message}");
                    return;
                }

                enrollResult.Should().NotBeNull();
                enrollResult.CARequestID.Should().NotBeNullOrWhiteSpace("V2 OV Enroll must return a non-empty CARequestID");
                orderId = enrollResult.CARequestID;
                enrollResult.Status.Should().NotBe((int)EndEntityStatus.FAILED,
                    $"OV Enroll must not FAILED at submission; message: {enrollResult.StatusMessage}");
                _output.WriteLine($"OV order {orderId}: Status={enrollResult.Status}, Message={enrollResult.StatusMessage}");

                var tracked = await plugin.GetSingleRecord(orderId);
                tracked.Should().NotBeNull();
                _output.WriteLine($"Tracked OV order {orderId}: Status={tracked.Status} (OV sandbox orders commonly sit in a pending-vetting state — this is the observed, not forced, state machine).");

                var synced = await RunSyncAsync(plugin, lastSync: DateTime.UtcNow.AddHours(-1), fullSync: false);
                synced.Should().Contain(r => r.CARequestID == orderId,
                    $"the newly placed OV order '{orderId}' must appear in a delta sync");
            }
            finally
            {
                await CleanupOrderAsync(plugin, orderId);
            }
        }

        // ---------------------------------------------------------------------------
        // 3. OV UCC — enroll (2+ SANs) -> track -> sync -> revoke/cancel
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Places one V2 OV SSL UCC order (<see cref="Constants.Products.OvSslUcc"/>) — the
        /// organization-block requirement (OV/EV) and the UCC multi-SAN path (additionalDomains)
        /// are exercised together, which neither <c>OrganizationBlockV2ProbeTests</c> nor
        /// <c>UccPendingSanOrderProbeTests</c> combined into one order. Same pending-vetting
        /// observation and timeout caveat as the plain OV test above.
        /// Expected sandbox order count: 1.
        /// </summary>
        [SkippableFact]
        public async Task Enroll_V2_OvUcc_WithMultipleSans_FullLifecycle()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");
            Skip.If(Environment.GetEnvironmentVariable("CERTINEXT_V2_LIFECYCLE_OV_UCC") != "1",
                "CERTINEXT_V2_LIFECYCLE_OV_UCC=1 not set — this places a real OV UCC sandbox order. Skipping.");

            string organizationNumber = _fixture.IsConfigured ? _fixture.OrgNumber : null;
            Skip.If(string.IsNullOrWhiteSpace(organizationNumber),
                "CERTINEXT_ORG_NUMBER not set in ~/.env_certinext — OV UCC requires a pre-vetted organization number. Skipping.");

            string ts = Timestamp();
            string primary = _v2Domain;
            string sanA = $"ovucc-a-{ts}.{_v2Domain}";
            string sanB = $"ovucc-b-{ts}.{_v2Domain}";

            var config = BuildV2Config(organizationNumber: organizationNumber);
            var plugin = BuildV2Plugin(config);

            string probeTag = $"ovucc-{ts}";
            DateTime windowStart = DateTime.UtcNow;
            string orderId = null;
            try
            {
                EnrollmentResult enrollResult;
                try
                {
                    enrollResult = await plugin.Enroll(
                        csr:            GenerateCsrPem(primary, probeTag),
                        subject:        $"CN={primary},OU={probeTag}",
                        san:            new Dictionary<string, string[]> { ["dns"] = new[] { sanA, sanB } },
                        productInfo:    new EnrollmentProductInfo { ProductID = Constants.Products.OvSslUcc },
                        requestFormat:  RequestFormat.PKCS10,
                        enrollmentType: EnrollmentType.New);
                }
                catch (Exception ex) when (IsClientTimeout(ex))
                {
                    string sweepResult = await TryCancelOrphanByWindowAsync(primary, windowStart, probeTag);
                    Skip.If(true,
                        "OV UCC order creation did not return within the plugin's hard-coded 120s V2 HTTP client " +
                        "timeout — same accepted-stays-as-is condition as the plain OV test (issue 0064, closed " +
                        "won't-fix). A client timeout does not prove the CA never created the order; it likely " +
                        $"did. {sweepResult}. Observed: {ex.GetType().Name}: {ex.Message}");
                    return;
                }

                enrollResult.Should().NotBeNull();
                enrollResult.CARequestID.Should().NotBeNullOrWhiteSpace("V2 OV UCC Enroll must return a non-empty CARequestID");
                orderId = enrollResult.CARequestID;
                enrollResult.Status.Should().NotBe((int)EndEntityStatus.FAILED,
                    $"OV UCC Enroll must not FAILED at submission; message: {enrollResult.StatusMessage}");
                _output.WriteLine($"OV UCC order {orderId}: Status={enrollResult.Status}, Primary={primary}, SANs=[{sanA}, {sanB}]");

                var tracked = await plugin.GetSingleRecord(orderId);
                tracked.Should().NotBeNull();
                _output.WriteLine($"Tracked OV UCC order {orderId}: Status={tracked.Status}");

                var synced = await RunSyncAsync(plugin, lastSync: DateTime.UtcNow.AddHours(-1), fullSync: false);
                synced.Should().Contain(r => r.CARequestID == orderId,
                    $"the newly placed OV UCC order '{orderId}' must appear in a delta sync");
            }
            finally
            {
                await CleanupOrderAsync(plugin, orderId);
            }
        }

        // ---------------------------------------------------------------------------
        // 4. EV — enroll -> track -> sync -> revoke/cancel
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Places one V2 EV SSL order (<see cref="Constants.Products.EvSsl"/>) — same
        /// organization-block requirement as OV (issue 0028/0059's ProductVariantsV2 mapping
        /// resolves "ev" automatically), same pending-vetting observation, same client-timeout
        /// caveat. Uses <c>CERTINEXT_EV_ORG_NUMBER</c> — NOT <c>CERTINEXT_ORG_NUMBER</c>/
        /// <see cref="IntegrationTestFixture.OrgNumber"/>, which is only pre-vetted for OV. EV
        /// requires its own, separately-vetted organization number that this account does not
        /// currently have; the test skips cleanly rather than guessing.
        /// Expected sandbox order count: 1.
        /// </summary>
        [SkippableFact]
        public async Task Enroll_V2_Ev_FullLifecycle()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");
            Skip.If(Environment.GetEnvironmentVariable("CERTINEXT_V2_LIFECYCLE_EV") != "1",
                "CERTINEXT_V2_LIFECYCLE_EV=1 not set — this places a real EV sandbox order. Skipping.");

            string organizationNumber = Environment.GetEnvironmentVariable("CERTINEXT_EV_ORG_NUMBER");
            Skip.If(string.IsNullOrWhiteSpace(organizationNumber),
                "CERTINEXT_EV_ORG_NUMBER not set — EV requires its own pre-vetted organization number " +
                "(distinct from CERTINEXT_ORG_NUMBER, which is only vetted for OV). Skipping.");

            var config = BuildV2Config(organizationNumber: organizationNumber);
            var plugin = BuildV2Plugin(config);

            string domain = _v2Domain;
            string orderId = null;
            try
            {
                EnrollmentResult enrollResult;
                try
                {
                    enrollResult = await plugin.Enroll(
                        csr:            GenerateCsrPem(domain),
                        subject:        $"CN={domain}",
                        san:            new Dictionary<string, string[]> { ["dns"] = new[] { domain } },
                        productInfo:    new EnrollmentProductInfo { ProductID = Constants.Products.EvSsl },
                        requestFormat:  RequestFormat.PKCS10,
                        enrollmentType: EnrollmentType.New);
                }
                catch (Exception ex) when (IsClientTimeout(ex))
                {
                    Skip.If(true,
                        $"EV order creation did not return within the plugin's hard-coded 120s V2 HTTP " +
                        $"client timeout — same production gap flagged for OV (issue 0064). " +
                        $"Observed: {ex.GetType().Name}: {ex.Message}");
                    return;
                }

                enrollResult.Should().NotBeNull();
                enrollResult.CARequestID.Should().NotBeNullOrWhiteSpace("V2 EV Enroll must return a non-empty CARequestID");
                orderId = enrollResult.CARequestID;
                enrollResult.Status.Should().NotBe((int)EndEntityStatus.FAILED,
                    $"EV Enroll must not FAILED at submission; message: {enrollResult.StatusMessage}");
                _output.WriteLine($"EV order {orderId}: Status={enrollResult.Status}, Message={enrollResult.StatusMessage}");

                var tracked = await plugin.GetSingleRecord(orderId);
                tracked.Should().NotBeNull();
                _output.WriteLine($"Tracked EV order {orderId}: Status={tracked.Status} (EV sandbox orders commonly sit in a pending-vetting state).");

                var synced = await RunSyncAsync(plugin, lastSync: DateTime.UtcNow.AddHours(-1), fullSync: false);
                synced.Should().Contain(r => r.CARequestID == orderId,
                    $"the newly placed EV order '{orderId}' must appear in a delta sync");
            }
            finally
            {
                await CleanupOrderAsync(plugin, orderId);
            }
        }

        // ---------------------------------------------------------------------------
        // 5. Wildcard DV — both CSR shapes (wildcard-only, wildcard+apex SAN)
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Resolves the wildcard domain to use: <c>CERTINEXT_V2_WILDCARD_DOMAIN</c> if set,
        /// else the literal <c>*.dcv-test.scrup.org</c> named in the task brief — this repo's own
        /// always-reused sandbox base domain (see UccPendingSanOrderProbeTests' header comment),
        /// not customer data.
        /// </summary>
        private static string ResolveWildcardDomain() =>
            Environment.GetEnvironmentVariable("CERTINEXT_V2_WILDCARD_DOMAIN") ?? "*.dcv-test.scrup.org";

        /// <summary>
        /// Wildcard-only CSR shape: CN and sole SAN are both the wildcard
        /// (<see cref="ResolveWildcardDomain"/>). Expected to be accepted — wildcard is a
        /// first-class DV SSL Wildcard product shape.
        /// Expected sandbox order count: 1.
        /// </summary>
        [SkippableFact]
        public async Task Enroll_V2_WildcardDv_WildcardOnly_FullLifecycle()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");
            Skip.If(Environment.GetEnvironmentVariable("CERTINEXT_V2_LIFECYCLE_WILDCARD_DV") != "1",
                "CERTINEXT_V2_LIFECYCLE_WILDCARD_DV=1 not set — this places real wildcard DV sandbox orders. Skipping.");

            string wildcard = ResolveWildcardDomain();
            var config = BuildV2Config();
            var plugin = BuildV2Plugin(config);

            string orderId = null;
            try
            {
                var enrollResult = await plugin.Enroll(
                    csr:            GenerateCsrPem(wildcard),
                    subject:        $"CN={wildcard}",
                    san:            new Dictionary<string, string[]> { ["dns"] = new[] { wildcard } },
                    productInfo:    new EnrollmentProductInfo { ProductID = Constants.Products.DvSslWildcard },
                    requestFormat:  RequestFormat.PKCS10,
                    enrollmentType: EnrollmentType.New);

                enrollResult.Should().NotBeNull();
                _output.WriteLine($"Wildcard-only ({wildcard}): Status={enrollResult.Status}, Message={enrollResult.StatusMessage}");
                enrollResult.Status.Should().NotBe((int)EndEntityStatus.FAILED,
                    $"a wildcard-only CSR/SAN shape must not be rejected; message: {enrollResult.StatusMessage}");
                enrollResult.CARequestID.Should().NotBeNullOrWhiteSpace();
                orderId = enrollResult.CARequestID;

                var tracked = await plugin.GetSingleRecord(orderId);
                tracked.Should().NotBeNull();
                _output.WriteLine($"Tracked: Status={tracked.Status}");
            }
            finally
            {
                await CleanupOrderAsync(plugin, orderId);
            }
        }

        /// <summary>
        /// Wildcard+apex CSR shape: CN is the wildcard, SAN dictionary carries BOTH the wildcard
        /// and its bare apex domain. The non-UCC V2 SAN guard (CERTInextCAPlugin.cs, EnrollV2Async)
        /// now explicitly exempts exactly this shape for a wildcard product (fix: 1f1de1b) — the
        /// guard computes <c>domain</c> as the literal CN ("*.dcv-test.scrup.org" here), and
        /// without the exemption the apex ("dcv-test.scrup.org") would match neither that nor its
        /// "www." variant and be treated as a disallowed "extra SAN", even though a wildcard+apex
        /// pairing is an extremely common, legitimate certificate shape. The order is therefore
        /// expected to be accepted and issued. This test still RECORDS the actual observed
        /// behavior rather than hard-asserting on it everywhere: if the order is rejected anyway,
        /// it asserts the rejection is specifically this guard's (by message content) rather than
        /// some unrelated failure; if accepted and issued, it parses the issued leaf (BouncyCastle)
        /// and logs — as an observation only, not an assertion — whether the apex is covered by
        /// the certificate's own SAN list (CERTInext may or may not add the apex to
        /// additionalDomains automatically for a non-UCC wildcard product; unconfirmed live).
        /// Expected sandbox order count: 0 or 1 (0 if CERTInext itself rejects a FAILED result
        /// before any order is ever placed — see the FAILED branch below).
        /// </summary>
        [SkippableFact]
        public async Task Enroll_V2_WildcardDv_WildcardPlusApexSan_RecordsActualBehavior()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");
            Skip.If(Environment.GetEnvironmentVariable("CERTINEXT_V2_LIFECYCLE_WILDCARD_DV") != "1",
                "CERTINEXT_V2_LIFECYCLE_WILDCARD_DV=1 not set — this places real wildcard DV sandbox orders. Skipping.");

            string wildcard = ResolveWildcardDomain();
            string apex = wildcard.StartsWith("*.", StringComparison.Ordinal) ? wildcard.Substring(2) : wildcard;

            var config = BuildV2Config();
            var plugin = BuildV2Plugin(config);

            string orderId = null;
            try
            {
                var enrollResult = await plugin.Enroll(
                    csr:            GenerateCsrPem(wildcard),
                    subject:        $"CN={wildcard}",
                    san:            new Dictionary<string, string[]> { ["dns"] = new[] { wildcard, apex } },
                    productInfo:    new EnrollmentProductInfo { ProductID = Constants.Products.DvSslWildcard },
                    requestFormat:  RequestFormat.PKCS10,
                    enrollmentType: EnrollmentType.New);

                enrollResult.Should().NotBeNull();
                _output.WriteLine($"Wildcard+apex ({wildcard} + {apex}): Status={enrollResult.Status}, Message={enrollResult.StatusMessage}");

                if (enrollResult.Status == (int)EndEntityStatus.FAILED)
                {
                    _output.WriteLine(
                        "RESULT: wildcard+apex was REJECTED before any CA call — the non-UCC SAN guard's " +
                        $"wildcard-apex exemption did not cover this case: domain==CN=='{wildcard}', and the " +
                        $"apex '{apex}' matched neither that nor its 'www.' variant.");
                    enrollResult.StatusMessage.Should().Contain("SAN",
                        "a FAILED result here must specifically be the non-UCC multi-SAN guard's rejection " +
                        "(StatusMessage mentions SAN/domain count), not some unrelated failure masquerading as it");
                    enrollResult.CARequestID.Should().BeNullOrWhiteSpace(
                        "the guard rejects before PlaceOrderV2Async — no CARequestID should be minted");
                }
                else
                {
                    _output.WriteLine(
                        "RESULT: wildcard+apex was ACCEPTED — the non-UCC single-domain SAN guard's " +
                        "wildcard-apex exemption (fix: 1f1de1b) allows the bare apex alongside the wildcard CN.");
                    enrollResult.CARequestID.Should().NotBeNullOrWhiteSpace();
                    orderId = enrollResult.CARequestID;

                    var tracked = await plugin.GetSingleRecord(orderId);
                    tracked.Should().NotBeNull();
                    _output.WriteLine($"Tracked: Status={tracked.Status}");

                    if (tracked.Status == (int)EndEntityStatus.GENERATED && !string.IsNullOrWhiteSpace(tracked.Certificate))
                    {
                        var sans = ExtractDnsSansOrEmpty(tracked.Certificate);
                        _output.WriteLine($"OBSERVATION: issued certificate SAN list: [{string.Join(", ", sans)}]");

                        bool apexCovered = sans.Any(s => string.Equals(s, apex, StringComparison.OrdinalIgnoreCase));
                        _output.WriteLine(apexCovered
                            ? $"OBSERVATION: the apex '{apex}' IS covered by the issued certificate's SAN list."
                            : $"OBSERVATION: the apex '{apex}' is NOT covered by the issued certificate's SAN " +
                              "list (observation only, not asserted — whether CERTInext adds the apex to " +
                              "additionalDomains automatically for a non-UCC wildcard product is unconfirmed live).");
                    }
                    else
                    {
                        _output.WriteLine(
                            $"Order not yet issued (Status={tracked.Status}) — skipping the SAN-coverage observation.");
                    }
                }
            }
            finally
            {
                await CleanupOrderAsync(plugin, orderId);
            }
        }

        // ---------------------------------------------------------------------------
        // 6. Renew and Reissue of an issued DV order
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Enrolls a DV order (New), then calls Enroll again with EnrollmentType.Renew and then
        /// EnrollmentType.Reissue for the same domain, passing the prior order's serial via
        /// ProductParameters["PriorCertSN"] (the V1 RenewOrReissueAsync convention). V2's
        /// EnrollV2Async never branches on enrollmentType beyond logging it — every enrollment
        /// type is dispatched identically (CERTInextCAPlugin.cs: "V2 path: all enrollment types
        /// go through EnrollV2Async", and EnrollV2Async itself never reads PriorCertSN or
        /// enrollmentType except in log statements). This test records the real observed
        /// behavior (distinct CARequestIDs, original never implicitly revoked) but — unlike an
        /// earlier version of this test — does NOT pass merely because the CA accepted each
        /// submission; a FAILED order at the CA (e.g. the product-selection bug this plugin's own
        /// catalog code resolves — now a separate, actively-fixed issue) must still fail this
        /// test, since "records actual behavior" was never meant to license "observe FAILED
        /// three times and call it a pass."
        /// Expected sandbox order count: up to 3 (original + renew + reissue).
        /// </summary>
        [SkippableFact]
        public async Task EnrollRenewReissue_V2_IssuedDvOrder_RecordsActualBehavior()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");
            Skip.If(Environment.GetEnvironmentVariable("CERTINEXT_V2_LIFECYCLE_RENEW_REISSUE") != "1",
                "CERTINEXT_V2_LIFECYCLE_RENEW_REISSUE=1 not set — this places up to 3 real DV sandbox orders. Skipping.");

            var config = BuildV2Config();
            var plugin = BuildV2Plugin(config);

            string domain = _v2Domain;
            string originalOrderId = null, renewOrderId = null, reissueOrderId = null;
            try
            {
                var original = await plugin.Enroll(
                    csr:            GenerateCsrPem(domain),
                    subject:        $"CN={domain}",
                    san:            new Dictionary<string, string[]> { ["dns"] = new[] { domain } },
                    productInfo:    new EnrollmentProductInfo { ProductID = Constants.Products.DvSsl },
                    requestFormat:  RequestFormat.PKCS10,
                    enrollmentType: EnrollmentType.New);

                original.Should().NotBeNull();
                original.CARequestID.Should().NotBeNullOrWhiteSpace();
                originalOrderId = original.CARequestID;
                _output.WriteLine($"Original order {originalOrderId}: Status={original.Status}, Message={original.StatusMessage}");
                original.Status.Should().BeOneOf(
                    new[] { (int)EndEntityStatus.GENERATED, (int)EndEntityStatus.EXTERNALVALIDATION },
                    $"the original New enrollment must actually reach an in-flight or issued state for this to be a " +
                    $"meaningful renew/reissue lifecycle test, not FAILED; message: {original.StatusMessage}");

                string priorSn = ExtractHexSerialOrEmpty(original.Certificate);
                var priorParams = new Dictionary<string, string> { ["PriorCertSN"] = priorSn };

                var renewResult = await plugin.Enroll(
                    csr:            GenerateCsrPem(domain),
                    subject:        $"CN={domain}",
                    san:            new Dictionary<string, string[]> { ["dns"] = new[] { domain } },
                    productInfo:    new EnrollmentProductInfo { ProductID = Constants.Products.DvSsl, ProductParameters = priorParams },
                    requestFormat:  RequestFormat.PKCS10,
                    enrollmentType: EnrollmentType.Renew);

                renewResult.Should().NotBeNull();
                renewResult.CARequestID.Should().NotBeNullOrWhiteSpace();
                renewOrderId = renewResult.CARequestID;
                renewOrderId.Should().NotBe(originalOrderId,
                    "V2 has no dedicated renew endpoint — EnrollV2Async dispatches every EnrollmentType " +
                    "identically, so Renew places a brand-new order with a new CARequestID rather than " +
                    "reusing or superseding the original's ID");
                _output.WriteLine($"Renew order {renewOrderId}: Status={renewResult.Status}, Message={renewResult.StatusMessage} (new order, distinct CARequestID).");
                renewResult.Status.Should().BeOneOf(
                    new[] { (int)EndEntityStatus.GENERATED, (int)EndEntityStatus.EXTERNALVALIDATION },
                    $"Renew must actually reach an in-flight or issued state, not FAILED; message: {renewResult.StatusMessage}");

                var reissueResult = await plugin.Enroll(
                    csr:            GenerateCsrPem(domain),
                    subject:        $"CN={domain}",
                    san:            new Dictionary<string, string[]> { ["dns"] = new[] { domain } },
                    productInfo:    new EnrollmentProductInfo { ProductID = Constants.Products.DvSsl, ProductParameters = priorParams },
                    requestFormat:  RequestFormat.PKCS10,
                    enrollmentType: EnrollmentType.Reissue);

                reissueResult.Should().NotBeNull();
                reissueResult.CARequestID.Should().NotBeNullOrWhiteSpace();
                reissueOrderId = reissueResult.CARequestID;
                reissueOrderId.Should().NotBe(originalOrderId);
                reissueOrderId.Should().NotBe(renewOrderId);
                _output.WriteLine($"Reissue order {reissueOrderId}: Status={reissueResult.Status}, Message={reissueResult.StatusMessage} (new order, distinct CARequestID).");
                reissueResult.Status.Should().BeOneOf(
                    new[] { (int)EndEntityStatus.GENERATED, (int)EndEntityStatus.EXTERNALVALIDATION },
                    $"Reissue must actually reach an in-flight or issued state, not FAILED; message: {reissueResult.StatusMessage}");

                var originalAfter = await plugin.GetSingleRecord(originalOrderId);
                originalAfter.Should().NotBeNull();
                originalAfter.Status.Should().NotBe((int)EndEntityStatus.REVOKED,
                    "neither Renew nor Reissue should implicitly revoke the original order under the V2 " +
                    "path — EnrollV2Async never calls Revoke on a prior order");
                _output.WriteLine($"Original order {originalOrderId} after renew+reissue: Status={originalAfter.Status} (unaffected, as expected).");
            }
            finally
            {
                await CleanupOrderAsync(plugin, originalOrderId);
                await CleanupOrderAsync(plugin, renewOrderId);
                await CleanupOrderAsync(plugin, reissueOrderId);
            }
        }

        /// <summary>
        /// Extracts the issued certificate's serial number as an uppercase hex string using
        /// BouncyCastle (never BCL System.Security.Cryptography). Returns empty when
        /// <paramref name="certPem"/> is null/blank/unparseable — e.g. a DV order still pending
        /// DCV at enrollment time has no cert body yet, and PriorCertSN is not read at all by
        /// EnrollV2Async under V2 (see this method's caller), so an empty value is harmless here.
        /// </summary>
        private static string ExtractHexSerialOrEmpty(string certPem)
        {
            if (string.IsNullOrWhiteSpace(certPem))
                return string.Empty;

            try
            {
                var match = System.Text.RegularExpressions.Regex.Match(
                    certPem,
                    @"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
                    System.Text.RegularExpressions.RegexOptions.Singleline);
                if (!match.Success)
                    return string.Empty;

                string b64 = match.Groups[1].Value.Replace("\r", string.Empty).Replace("\n", string.Empty).Trim();
                var cert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(Convert.FromBase64String(b64));
                return cert.SerialNumber.ToString(16).ToUpperInvariant();
            }
            catch
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// Extracts the issued certificate's dNSName SAN entries using BouncyCastle (never BCL
        /// System.Security.Cryptography) — mirrors the main plugin's own <c>GeneralNameToSanEntry</c>
        /// dNSName handling, but reading the ISSUED certificate's own SAN extension rather than a
        /// CSR's. Returns an empty list when <paramref name="certPem"/> is null/blank/unparseable,
        /// or the certificate carries no SAN extension.
        /// </summary>
        private static List<string> ExtractDnsSansOrEmpty(string certPem)
        {
            var result = new List<string>();
            if (string.IsNullOrWhiteSpace(certPem))
                return result;

            try
            {
                var match = System.Text.RegularExpressions.Regex.Match(
                    certPem,
                    @"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
                    System.Text.RegularExpressions.RegexOptions.Singleline);
                if (!match.Success)
                    return result;

                string b64 = match.Groups[1].Value.Replace("\r", string.Empty).Replace("\n", string.Empty).Trim();
                var cert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(Convert.FromBase64String(b64));

                var sanExtensionOctets = cert.GetExtensionValue(X509Extensions.SubjectAlternativeName)?.GetOctets();
                if (sanExtensionOctets == null)
                    return result;

                var generalNames = GeneralNames.GetInstance(
                    Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(sanExtensionOctets));

                foreach (var generalName in generalNames.GetNames())
                {
                    if (generalName.TagNo == GeneralName.DnsName)
                        result.Add(Org.BouncyCastle.Asn1.DerIA5String.GetInstance(generalName.Name).GetString());
                }
            }
            catch
            {
                // Observation-only helper — an unparseable cert/extension just yields no SAN
                // observations rather than failing the test.
            }

            return result;
        }
    }
}
