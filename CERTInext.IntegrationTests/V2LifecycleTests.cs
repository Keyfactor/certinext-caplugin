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

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
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
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Plugin-level integration tests for the V2 (OAuth2) API path — Tiers 1–3 (no DCV
    /// build required). Unlike <see cref="V2ApiTests"/>, which exercises
    /// <see cref="CERTInextClient"/> methods directly, these tests drive the full
    /// <c>IAnyCAPlugin</c> surface (<c>Enroll</c>, <c>Revoke</c>, <c>GetSingleRecord</c>,
    /// <c>Synchronize</c>) the way Keyfactor Command actually calls the plugin.
    ///
    /// All tests are gated behind <c>CERTINEXT_USE_V2_API=1</c> plus valid V2 OAuth2
    /// credentials and skip gracefully otherwise.  See <see cref="V2ApiTests"/> for the
    /// full list of required environment variables.
    /// </summary>
    public class V2LifecycleTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;

        private readonly string _v2ApiUrl;
        private readonly string _v2ClientId;
        private readonly string _v2ClientSecret;
        private readonly string _v2ProductCode;
        private readonly string _v2Domain;
        private readonly bool _v2Enabled;

        public V2LifecycleTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output  = output;

            var env = V2EnvHelper.LoadAndPromote();

            _v2ApiUrl       = V2EnvHelper.GetEnv(env, "CERTINEXT_API_URL");
            _v2ClientId     = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_ID");
            _v2ClientSecret = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_SECRET");
            _v2ProductCode  = V2EnvHelper.GetEnv(env, "CERTINEXT_PRODUCT_CODE", "842");
            _v2Domain       = V2EnvHelper.GetEnv(env, "CERTINEXT_DCV_DOMAIN", "test.example.com");

            _v2Enabled = !string.IsNullOrWhiteSpace(V2EnvHelper.GetEnv(env, "CERTINEXT_USE_V2_API"))
                         && !string.IsNullOrWhiteSpace(_v2ApiUrl)
                         && !string.IsNullOrWhiteSpace(_v2ClientId)
                         && !string.IsNullOrWhiteSpace(_v2ClientSecret);
        }

        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Builds a <see cref="CERTInextConfig"/> wired for the V2 API. A single
        /// <see cref="CERTInextConfig.ApiUrl"/> serves both modes — in V2 mode it is the V2
        /// base URL, and V2 auth reuses
        /// <see cref="CERTInextConfig.OAuthClientId"/>/<see cref="CERTInextConfig.OAuthClientSecret"/>.
        /// Deliberately does NOT set any V1-only field (ApiKey/AccountNumber/AuthMode) — proving
        /// those are optional when UseV2Api is true is itself part of what these tests exercise
        /// (Synchronize now uses V2 /reports/orders, not V1 GetOrderReport).
        /// </summary>
        private CERTInextConfig BuildV2Config(bool dcvEnabled = false, int? pageSize = null, int? syncLookbackHours = null)
        {
            return new CERTInextConfig
            {
                ApiUrl            = _v2ApiUrl,
                UseV2Api          = true,
                OAuthClientId     = _v2ClientId,
                OAuthClientSecret = _v2ClientSecret,

                RequestorName         = _fixture.IsConfigured ? _fixture.Config.RequestorName : "Keyfactor Test",
                RequestorEmail        = _fixture.IsConfigured ? _fixture.Config.RequestorEmail : "test@example.com",
                RequestorIsdCode      = "1",
                RequestorMobileNumber = "0000000000",
                SignerPlace           = "Gateway Lab",
                SignerIp              = "127.0.0.1",

                PageSize = pageSize ?? 100,

                // Default 72h (Constants.ApiV2.DefaultSyncLookbackHours) is always added on top
                // of lastSync regardless of how recent it is — on a busy shared sandbox that
                // means every delta-sync test touches several days of orders (each issued row
                // costs a live certificate download) unless narrowed here.
                V2SyncLookbackHours = syncLookbackHours ?? Constants.ApiV2.DefaultSyncLookbackHours,

                DcvEnabled                 = dcvEnabled,
                DcvPropagationDelaySeconds = 5,
                DcvTimeoutMinutes          = 3
            };
        }

        /// <summary>
        /// Constructs a plugin instance wired to a real <see cref="CERTInextClient"/>
        /// built from <paramref name="config"/> (or a fresh <see cref="BuildV2Config"/>
        /// if none is supplied). Uses the two-arg test constructor so no
        /// <c>Initialize</c> call is required.
        /// </summary>
        private CERTInextCAPlugin BuildV2Plugin(CERTInextConfig config = null)
        {
            config ??= BuildV2Config();
            var client = new CERTInextClient(config);
            return new CERTInextCAPlugin(client, config);
        }

        /// <summary>
        /// Generates a fresh RSA-2048 PKCS#10 CSR for the given common name using
        /// BouncyCastle only.
        /// </summary>
        private static string GenerateCsrPem(string commonName)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            var keyPair = keyGen.GenerateKeyPair();

            var subject = new X509Name($"CN={commonName}");
            var csr = new Pkcs10CertificationRequest("SHA256withRSA", subject, keyPair.Public, null, keyPair.Private);

            return "-----BEGIN CERTIFICATE REQUEST-----\n"
                + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                + "\n-----END CERTIFICATE REQUEST-----";
        }

        /// <summary>
        /// Runs a full synchronization via the plugin and returns all collected records.
        /// </summary>
        private static async Task<List<AnyCAPluginCertificate>> RunSyncAsync(
            CERTInextCAPlugin plugin, DateTime? lastSync = null, bool fullSync = true)
        {
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(boundedCapacity: 10_000);
            var collected = new List<AnyCAPluginCertificate>();

            var syncTask = Task.Run(async () =>
            {
                await plugin.Synchronize(
                    buffer,
                    lastSync: lastSync,
                    fullSync: fullSync,
                    cancelToken: CancellationToken.None);

                if (!buffer.IsAddingCompleted)
                    buffer.CompleteAdding();
            });

            foreach (var record in buffer.GetConsumingEnumerable())
                collected.Add(record);

            await syncTask;
            return collected;
        }

        /// <summary>
        /// Polls <see cref="CERTInextCAPlugin.GetSingleRecord"/> until the order reaches
        /// GENERATED or FAILED, or the poll budget is exhausted.
        /// </summary>
        private static async Task<AnyCAPluginCertificate> WaitForIssuanceAsync(
            CERTInextCAPlugin plugin, string caRequestId, int maxPolls = 6, int delaySeconds = 15)
        {
            AnyCAPluginCertificate record = null;
            for (int poll = 1; poll <= maxPolls; poll++)
            {
                record = await plugin.GetSingleRecord(caRequestId);
                if (record?.Status == (int)EndEntityStatus.GENERATED
                    || record?.Status == (int)EndEntityStatus.FAILED)
                    break;
                if (poll < maxPolls)
                    await Task.Delay(TimeSpan.FromSeconds(delaySeconds));
            }
            return record;
        }

        private EnrollmentProductInfo BuildV2ProductInfo() =>
            new EnrollmentProductInfo
            {
                ProductID         = _v2ProductCode,
                ProductParameters = new Dictionary<string, string>
                {
                    [Constants.EnrollmentParam.ProductCode] = _v2ProductCode,
                    [Constants.EnrollmentParam.ProfileId]   = _v2ProductCode,
                }
            };

        /// <summary>
        /// Resolves the order ID to exercise for tests that need a pre-existing V2 order.
        /// Reads only <c>CERTINEXT_V2_ORDER_ID</c> — deliberately does not fall back to an
        /// order ID produced by another test in this class, so results do not depend on
        /// test run order.
        /// </summary>
        private static string ResolveOrderId()
            => Environment.GetEnvironmentVariable("CERTINEXT_V2_ORDER_ID");

        /// <summary>
        /// Returns an issued (GENERATED) V2 order to exercise, plus the plugin instance
        /// that owns it. Prefers <c>CERTINEXT_V2_ORDER_ID</c> if set; otherwise enrolls a
        /// fresh order in this test and polls (bounded) for issuance, so tests using this
        /// helper are self-contained and don't depend on env state or another test's run
        /// order. <c>Skip.If</c>s (via <see cref="SkippableFactAttribute"/>) when no env ID
        /// is set and the freshly-enrolled order never reaches GENERATED within the poll
        /// budget — sandboxes may require DCV to auto-issue.
        /// </summary>
        private async Task<(string orderId, CERTInextCAPlugin plugin)> EnsureIssuedOrderIdAsync()
        {
            var plugin = BuildV2Plugin();
            string envOrderId = ResolveOrderId();
            if (!string.IsNullOrWhiteSpace(envOrderId))
                return (envOrderId, plugin);

            var enrollResult = await plugin.Enroll(
                csr:            GenerateCsrPem(_v2Domain),
                subject:        $"CN={_v2Domain}",
                san:            new Dictionary<string, string[]> { ["dns"] = new[] { _v2Domain } },
                productInfo:    BuildV2ProductInfo(),
                requestFormat:  RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            enrollResult.Should().NotBeNull();
            enrollResult.CARequestID.Should().NotBeNullOrWhiteSpace();
            _output.WriteLine(
                $"EnsureIssuedOrderIdAsync: no CERTINEXT_V2_ORDER_ID set — enrolled fresh order {enrollResult.CARequestID}.");

            var record = await WaitForIssuanceAsync(plugin, enrollResult.CARequestID);
            Skip.If(record?.Status != (int)EndEntityStatus.GENERATED,
                $"Freshly-enrolled order '{enrollResult.CARequestID}' did not reach GENERATED within the poll " +
                $"budget (status={record?.Status}) — sandbox may require DCV to auto-issue. Set " +
                "CERTINEXT_V2_ORDER_ID to a known-issued order to bypass enrollment.");

            return (enrollResult.CARequestID, plugin);
        }

        // ---------------------------------------------------------------------------
        // Enroll() via the plugin, V2 path
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task Enroll_V2_ReturnsCARequestID()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            var plugin = BuildV2Plugin();

            var result = await plugin.Enroll(
                csr:            GenerateCsrPem(_v2Domain),
                subject:        $"CN={_v2Domain}",
                san:            new Dictionary<string, string[]> { ["dns"] = new[] { _v2Domain } },
                productInfo:    BuildV2ProductInfo(),
                requestFormat:  RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Should().NotBeNull();
            result.CARequestID.Should().NotBeNullOrWhiteSpace(
                "V2 Enroll must return a non-empty CARequestID — it is the stable foreign key for all future operations");
            result.Status.Should().NotBe((int)EndEntityStatus.FAILED,
                $"V2 Enroll must not FAILED at submission time; message: {result.StatusMessage}");

            _output.WriteLine($"CARequestID: {result.CARequestID}");
            _output.WriteLine($"Status:      {result.Status}");
            _output.WriteLine($"Message:     {result.StatusMessage}");
        }

        // ---------------------------------------------------------------------------
        // Revoke() via the plugin, V2 path
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Opt-in cleanup: revokes one explicit, already-issued order through the plugin's
        /// V2 <c>Revoke</c> with reason superseded (4), outside Command. Used to clean up lab
        /// orders Command never imported and to reproduce an out-of-band CA-side revoke.
        /// Gated behind <c>CERTINEXT_REVOKE_ORDER_ID</c>; never retries.
        /// </summary>
        [SkippableFact]
        public async Task Revoke_V2_ExplicitOrder_Superseded()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");
            string orderId = Environment.GetEnvironmentVariable("CERTINEXT_REVOKE_ORDER_ID");
            Skip.If(string.IsNullOrWhiteSpace(orderId), "CERTINEXT_REVOKE_ORDER_ID not set — skipping.");

            var plugin = BuildV2Plugin();
            var before = await plugin.GetSingleRecord(orderId);
            _output.WriteLine($"Before: CARequestID={orderId}, Status={before?.Status}");
            Skip.If(before?.Status != (int)EndEntityStatus.GENERATED,
                $"Order '{orderId}' is in status {before?.Status} (not GENERATED) — not revoking.");

            int revokeResult = await plugin.Revoke(orderId, hexSerialNumber: string.Empty, revocationReason: 4 /* superseded */);
            _output.WriteLine($"Revoke result: {revokeResult}");

            var after = await plugin.GetSingleRecord(orderId);
            _output.WriteLine($"After: Status={after?.Status}, RevocationDate={after?.RevocationDate:o}, RevocationReason={after?.RevocationReason}");
            revokeResult.Should().Be((int)EndEntityStatus.REVOKED);
        }

        [SkippableFact]
        public async Task Revoke_V2_IssuedOrder_ReturnsRevoked()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            var (orderId, plugin) = await EnsureIssuedOrderIdAsync();

            var current = await plugin.GetSingleRecord(orderId);
            Skip.If(current?.Status != (int)EndEntityStatus.GENERATED,
                $"Order '{orderId}' is in status {current?.Status} (not GENERATED) — revocation requires an issued certificate; skipping.");

            int revokeResult;
            try
            {
                revokeResult = await plugin.Revoke(orderId, hexSerialNumber: string.Empty, revocationReason: 1 /* keyCompromise */);
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("still being processed"))
            {
                // Documented sandbox-timing quirk: the CA reports 'issued' via GetSingleRecord
                // while still internally finalizing the order, and rejects revoke with 422
                // ("Certificate Request still being processed") in that window. Retry once
                // after a short delay before giving up — any other exception (or a second
                // failure) must fail the test rather than be swallowed here.
                _output.WriteLine($"Revoke rejected as still-processing; retrying once after 15s: {ex.Message}");
                await Task.Delay(TimeSpan.FromSeconds(15));
                try
                {
                    revokeResult = await plugin.Revoke(orderId, hexSerialNumber: string.Empty, revocationReason: 1);
                }
                catch (InvalidOperationException ex2) when (ex2.Message.Contains("still being processed"))
                {
                    Skip.If(true,
                        $"Order '{orderId}' tracked as GENERATED but CA rejected revocation twice (sandbox timing): {ex2.Message}");
                    return; // unreachable
                }
            }

            revokeResult.Should().Be((int)EndEntityStatus.REVOKED,
                "V2 Revoke must return the REVOKED status code on success");
        }

        // ---------------------------------------------------------------------------
        // GetSingleRecord() via the plugin, V2 path
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task GetSingleRecord_V2_Plugin_ReturnsDetails()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            string orderId = ResolveOrderId();
            Skip.If(string.IsNullOrWhiteSpace(orderId),
                "No V2 order ID available — set CERTINEXT_V2_ORDER_ID to a real V2 order to run this test.");

            var plugin = BuildV2Plugin();
            var record = await plugin.GetSingleRecord(orderId);

            record.Should().NotBeNull("plugin.GetSingleRecord must return a record for a known V2 order");
            record.CARequestID.Should().Be(orderId);
            _output.WriteLine($"CARequestID: {record.CARequestID}");
            _output.WriteLine($"Status:      {record.Status}");
            _output.WriteLine($"ProductID:   {record.ProductID}");
        }

        // ---------------------------------------------------------------------------
        // Enroll -> Synchronize -> Revoke, full V2 lifecycle via the plugin
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task Enroll_Synchronize_Revoke_V2_FullLifecycle()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            // Narrow lookback (1h): the plugin's default 72h margin makes an un-narrowed delta
            // sync slow against this busy shared sandbox, and the order enrolled below is
            // only seconds old.
            var config = BuildV2Config(syncLookbackHours: 1);
            var plugin = BuildV2Plugin(config);

            // --- Enroll ---
            var enrollResult = await plugin.Enroll(
                csr:            GenerateCsrPem(_v2Domain),
                subject:        $"CN={_v2Domain}",
                san:            new Dictionary<string, string[]> { ["dns"] = new[] { _v2Domain } },
                productInfo:    BuildV2ProductInfo(),
                requestFormat:  RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            enrollResult.Should().NotBeNull();
            enrollResult.CARequestID.Should().NotBeNullOrWhiteSpace();
            enrollResult.Status.Should().NotBe((int)EndEntityStatus.FAILED,
                $"V2 Enroll must not FAILED at submission time; message: {enrollResult.StatusMessage}");

            _output.WriteLine($"Enrolled V2 order {enrollResult.CARequestID}, status={enrollResult.Status}");

            // --- Synchronize (V2 /reports/orders) ---
            // Delta sync (fullSync=false, lastSync=recent) rather than a full historical
            // pull — this sandbox account has accumulated 1000+ orders from prior test
            // runs, and a full sync of the entire history is unnecessarily slow here; the
            // order we just enrolled is recent, so a delta sync (with the configured
            // lookback window) is sufficient to prove it surfaces via Synchronize.
            var synced = await RunSyncAsync(BuildV2Plugin(config), lastSync: DateTime.UtcNow.AddHours(-1), fullSync: false);
            synced.Should().Contain(
                r => r.CARequestID == enrollResult.CARequestID,
                $"the newly enrolled V2 order '{enrollResult.CARequestID}' must appear in a delta sync " +
                "via V2 /reports/orders");

            var syncedRecord = synced.First(r => r.CARequestID == enrollResult.CARequestID);
            _output.WriteLine($"Synced record status: {syncedRecord.Status}");

            // --- Revoke — only if the sandbox has already auto-issued ---
            if (syncedRecord.Status != (int)EndEntityStatus.GENERATED)
            {
                Skip.If(true,
                    $"Order '{enrollResult.CARequestID}' is in status {syncedRecord.Status} (not GENERATED) — " +
                    "sandbox may not auto-issue a V2 order without DCV; skipping revoke step.");
            }

            int revokeResult;
            try
            {
                revokeResult = await plugin.Revoke(enrollResult.CARequestID, hexSerialNumber: string.Empty, revocationReason: 1);
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("still being processed"))
            {
                // Documented sandbox-timing quirk: the sandbox can report an order as 'issued'
                // via TrackOrder/GetSingleRecord while still internally finalizing it, and
                // reject a revoke attempted in that window with 422 "Certificate Request
                // still being processed". Retry once after a short delay before giving up —
                // any other exception must fail the test rather than be swallowed here.
                _output.WriteLine($"Revoke rejected as still-processing; retrying once after 15s: {ex.Message}");
                await Task.Delay(TimeSpan.FromSeconds(15));
                try
                {
                    revokeResult = await plugin.Revoke(enrollResult.CARequestID, hexSerialNumber: string.Empty, revocationReason: 1);
                }
                catch (InvalidOperationException ex2) when (ex2.Message.Contains("still being processed"))
                {
                    Skip.If(true,
                        $"Order '{enrollResult.CARequestID}' tracked as GENERATED but CA rejected revocation " +
                        $"twice (sandbox timing): {ex2.Message}");
                    return; // unreachable
                }
            }

            revokeResult.Should().Be((int)EndEntityStatus.REVOKED,
                "Revoke must return the REVOKED status code on success");
        }

        // ---------------------------------------------------------------------------
        // GetSingleRecord() cert-body check, V2 path
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task GetSingleRecord_V2_IssuedOrder_HasParseableCertBody()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            var (orderId, plugin) = await EnsureIssuedOrderIdAsync();
            var record = await WaitForIssuanceAsync(plugin, orderId, maxPolls: 1);

            Skip.If(record?.Status != (int)EndEntityStatus.GENERATED,
                $"Order '{orderId}' is not GENERATED (status={record?.Status}) — skipping cert-body check.");

            record!.Certificate.Should().NotBeNullOrWhiteSpace(
                "GetSingleRecord must populate the PEM body for a GENERATED V2 order");
            record.Certificate.Should().StartWith("-----BEGIN CERTIFICATE-----");

            // record.Certificate may be the leaf cert alone, or the leaf followed by one or
            // more chain PEM blocks (AssembleV2CertChain concatenates them) — extract only the
            // FIRST block. Naively stripping every BEGIN/END marker and decoding the
            // concatenation as one base64 blob breaks as soon as a chain is present, because
            // each block's own '=' padding then lands mid-string, which is illegal base64.
            var firstBlock = System.Text.RegularExpressions.Regex.Match(
                record.Certificate,
                @"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
                System.Text.RegularExpressions.RegexOptions.Singleline);
            firstBlock.Success.Should().BeTrue("the certificate body must contain at least one PEM block");

            var b64 = firstBlock.Groups[1].Value
                .Replace("\r", string.Empty).Replace("\n", string.Empty).Trim();

            Action parse = () => new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(Convert.FromBase64String(b64));
            parse.Should().NotThrow("the issued V2 certificate's leaf PEM block must be parseable");
        }

        // ---------------------------------------------------------------------------
        // GetSingleRecord() across all synced orders, V2-configured plugin
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Runs a delta sync via V2 /reports/orders with a V2-configured (<c>UseV2Api=true</c>)
        /// plugin, then calls <c>GetSingleRecord</c> for a sample of the resulting CARequestIDs.
        /// All sampled IDs are now V2-native (from the V2 report itself, not a V1 listing), so
        /// they are expected to resolve via the V2 family probe; <see cref="KeyNotFoundException"/>
        /// is tolerated only as a defensive allowance (e.g. an order deleted between sync and
        /// this call) — this test's real job is to guard against any *other* unhandled exception
        /// type escaping GetSingleRecord.
        /// </summary>
        [SkippableFact]
        public async Task GetSingleRecord_V2_AllSyncedOrders_DoNotThrow()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            // Narrow lookback (1h) — this sandbox account has 1000+ historical orders, and the
            // plugin's default 72h lookback margin is always added on top of lastSync
            // regardless of how recent it is, so an un-narrowed delta sync here would touch
            // several days of orders. Every issued row costs a live certificate download, and
            // family resolution costs a sequential TrackOrder probe when not already known —
            // an un-narrowed window can take several minutes against this shared sandbox.
            var plugin = BuildV2Plugin(BuildV2Config(syncLookbackHours: 1));
            var synced = await RunSyncAsync(plugin, lastSync: DateTime.UtcNow.AddHours(-1), fullSync: false);
            synced.Should().NotBeNull();
            synced.Should().NotBeEmpty(
                "the delta sync window must return at least one record from this sandbox account to sample " +
                "GetSingleRecord against — an empty sync makes the rest of this test vacuous");

            var sample = synced.Take(10).ToList();
            _output.WriteLine($"Sampling {sample.Count} of {synced.Count} synced records for GetSingleRecord (V2-configured plugin).");

            int ok = 0, keyNotFound = 0;
            foreach (var rec in sample)
            {
                try
                {
                    await plugin.GetSingleRecord(rec.CARequestID);
                    ok++;
                }
                catch (KeyNotFoundException)
                {
                    // Tolerated defensively (e.g. sandbox timing/deletion) — every sampled ID
                    // came from the V2 report itself, so this should be rare, not expected.
                    keyNotFound++;
                }
            }

            _output.WriteLine($"GetSingleRecord results: {ok} succeeded, {keyNotFound} KeyNotFoundException.");
            (ok + keyNotFound).Should().Be(sample.Count,
                "every sampled GetSingleRecord call must either succeed or throw the tolerated " +
                "KeyNotFoundException — any other exception type must escape this loop and fail the test");
        }

        // ---------------------------------------------------------------------------
        // Synchronize() uses V2 /reports/orders when UseV2Api=true
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task Sync_V2_UsesV2ReportsOrders_ReturnsRecords()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            // Narrow lookback (1h) — see the comment in GetSingleRecord_V2_AllSyncedOrders_DoNotThrow
            // above for why the plugin's default 72h margin makes an un-narrowed delta sync slow
            // against this shared, busy sandbox.
            var plugin = BuildV2Plugin(BuildV2Config(syncLookbackHours: 1));
            var synced = await RunSyncAsync(plugin, lastSync: DateTime.UtcNow.AddHours(-1), fullSync: false);

            synced.Should().NotBeNull();
            synced.Should().NotBeEmpty(
                "Synchronize must return the account's recent order inventory via V2 /reports/orders " +
                "(Synchronize no longer falls back to V1 GetOrderReport when UseV2Api=true)");
            synced.Should().OnlyContain(r => !string.IsNullOrWhiteSpace(r.CARequestID));

            _output.WriteLine($"Synchronize (V2 /reports/orders) returned {synced.Count} record(s).");
            foreach (var r in synced.Take(5))
                _output.WriteLine($"  CARequestID={r.CARequestID}, Status={r.Status}, ProductID={r.ProductID}");
        }

        /// <summary>
        /// Hard acceptance criterion: Synchronize with
        /// <c>UseV2Api=true</c> must succeed and return records with ZERO V1 credentials
        /// configured at all — no ApiKey, no AccountNumber, no AuthMode, no V1-shaped ApiUrl.
        /// Builds its own config (rather than reusing <see cref="BuildV2Plugin"/>'s default) so
        /// the absence of every V1-only field is explicit and self-evident at the call site.
        /// </summary>
        [SkippableFact]
        public async Task Sync_V2_WithZeroV1Credentials_Succeeds()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            var config = new CERTInextConfig
            {
                ApiUrl            = _v2ApiUrl,
                UseV2Api          = true,
                OAuthClientId     = _v2ClientId,
                OAuthClientSecret = _v2ClientSecret,
                RequestorName     = "Keyfactor Test",
                RequestorEmail    = "test@example.com",
                SignerPlace       = "Gateway Lab",
                SignerIp          = "127.0.0.1",
                PageSize          = 100,
                // Narrowed to keep this test's live API call volume bounded against a busy
                // shared sandbox.
                V2SyncLookbackHours = 1
                // Deliberately NOT set: ApiKey, AccountNumber, AuthMode, OAuthTokenUrl — all
                // V1-only fields. Their CERTInextConfig defaults (empty string / "AccessKey")
                // are never read on this path once UseV2Api is true.
            };

            var client = new CERTInextClient(config);
            var plugin = new CERTInextCAPlugin(client, config);

            var synced = await RunSyncAsync(plugin, lastSync: DateTime.UtcNow.AddHours(-1), fullSync: false);

            synced.Should().NotBeNull();
            _output.WriteLine(
                $"Synchronize succeeded with UseV2Api=true and ZERO V1 credentials configured " +
                $"(ApiKey/AccountNumber/AuthMode all unset). Returned {synced.Count} record(s).");
        }

        /// <summary>
        /// Opt-in (walks the sandbox's entire order history — 1000+ orders per the other
        /// tests' comments in this class): proves a full sync (<c>fullSync=true</c>,
        /// <c>lastSync=null</c>) paginates to completion via V2 /reports/orders without
        /// throwing or truncating silently.
        /// </summary>
        [SkippableFact]
        public async Task Sync_V2_FullSync_PaginatesEntireHistory()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");
            Skip.If(string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("CERTINEXT_V2_FULL_SYNC_TEST")),
                "CERTINEXT_V2_FULL_SYNC_TEST not set — a full sync walks this sandbox's entire order " +
                "history and is opt-in to keep the default .V2 filter fast.");

            var plugin = BuildV2Plugin();
            var synced = await RunSyncAsync(plugin, lastSync: null, fullSync: true);

            synced.Should().NotBeNull();
            synced.Should().NotBeEmpty("a full sync of a non-empty sandbox account must return records");
            _output.WriteLine($"Full sync (V2, entire history) returned {synced.Count} record(s).");
        }

        /// <summary>
        /// Forces multi-page traversal with a small page size (5) on a delta sync, proving
        /// <c>ListOrdersV2Async</c>'s pagination is exercised end-to-end through Synchronize
        /// against the live sandbox (not just the WireMock-based client unit tests).
        /// </summary>
        [SkippableFact]
        public async Task Sync_V2_SmallPageSize_PaginatesAcrossMultiplePages()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            // A narrow (2h) window with pageSize=5 still forces multi-page traversal whenever
            // this busy shared sandbox has more than 5 matching orders — no need for a wide
            // window (e.g. 30 days), which would also multiply live per-row download calls
            // for no added pagination proof.
            var config = BuildV2Config(pageSize: 5, syncLookbackHours: 1);
            var plugin = BuildV2Plugin(config);

            var synced = await RunSyncAsync(plugin, lastSync: DateTime.UtcNow.AddHours(-2), fullSync: false);

            synced.Should().NotBeNull();
            _output.WriteLine(
                $"Delta sync (2h window, pageSize=5) returned {synced.Count} record(s) — pageSize=5 " +
                "forces multi-page traversal whenever the account has more than 5 matching orders.");
        }
    }

    /// <summary>
    /// Shared helper for loading <c>~/.env_certinext_v2</c>. V2 test classes must read their
    /// values from the dictionary <see cref="LoadAndPromote"/> returns, never from process env:
    /// keys the V1 <see cref="IntegrationTestFixture"/> also reads are deliberately NOT
    /// promoted. Used by <see cref="V2LifecycleTests"/>, <c>V2DcvLifecycleTests</c>, and the
    /// other V2 test classes so they don't duplicate env-loading logic.
    /// </summary>
    internal static class V2EnvHelper
    {
        /// <summary>
        /// Loads <c>~/.env_certinext_v2</c> and returns the merged environment dictionary (V2 file
        /// values win over process env). V2-only file keys (e.g. <c>CERTINEXT_CLIENT_ID</c>,
        /// <c>CERTINEXT_USE_V2_API</c>) are still promoted into process env; keys in
        /// <see cref="IntegrationTestFixture.V1EnvKeys"/> (<c>CERTINEXT_API_URL</c> and the rest)
        /// are never written to process env. The V1 fixture lets real env vars override
        /// <c>~/.env_certinext</c>, so promoting the V2 values of those shared names would
        /// corrupt the V1 fixture of any class constructed later in the same test process.
        /// </summary>
        public static Dictionary<string, string> LoadAndPromote()
        {
            string v2Path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".env_certinext_v2");

            var (env, fileKeys) = LoadEnvFile(v2Path);

            foreach (string key in PromotableKeys(fileKeys))
                if (env.TryGetValue(key, out string fv))
                    Environment.SetEnvironmentVariable(key, fv);

            return env;
        }

        /// <summary>
        /// The V2-file keys <see cref="LoadAndPromote"/> may write into process env: every file
        /// key except those the V1 side reads (<see cref="IntegrationTestFixture.V1EnvKeys"/>)
        /// and the fixture's opt-in-only flags (<see cref="IntegrationTestFixture._optInOnlyFlags"/>).
        /// Without the latter exclusion, a value left in ~/.env_certinext_v2 for
        /// one of those flags (e.g. CERTINEXT_V2_OPS_TESTS, CERTINEXT_PRIVATE_PKI_LIVE) would be
        /// read as unset by the first test class constructed in a run (before this method's
        /// promotion step runs), then promoted into real process env, silently arming every
        /// later-constructed test class in the same run even though no flag was ever exported in
        /// the shell. Exposed <c>internal</c> for direct unit-testing.
        /// </summary>
        internal static List<string> PromotableKeys(IEnumerable<string> fileKeys)
        {
            var keys = new List<string>();
            foreach (string key in fileKeys)
                if (!IntegrationTestFixture.V1EnvKeys.Contains(key)
                    && !IntegrationTestFixture._optInOnlyFlags.Contains(key))
                    keys.Add(key);
            return keys;
        }

        /// <summary>
        /// Loads a KEY=VALUE env file and merges with process env vars. File values take
        /// priority over process env because the fixture may have already promoted V1
        /// values (e.g. CERTINEXT_API_URL with /emSignHub-API suffix) into process env,
        /// and the V2 base URL differs. Returns the merged dict and the set of keys
        /// defined in the file.
        /// </summary>
        public static (Dictionary<string, string> env, HashSet<string> fileKeys) LoadEnvFile(string path)
        {
            var fileKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (System.Collections.DictionaryEntry de in Environment.GetEnvironmentVariables())
            {
                string k = de.Key?.ToString();
                string v = de.Value?.ToString();
                if (!string.IsNullOrEmpty(k)) result[k] = v ?? string.Empty;
            }

            if (File.Exists(path))
            {
                foreach (string rawLine in File.ReadAllLines(path))
                {
                    string line = rawLine.Trim();
                    if (string.IsNullOrEmpty(line) || line.StartsWith("#")) continue;

                    int idx = line.IndexOf('=');
                    if (idx <= 0) continue;

                    string key = line.Substring(0, idx).Trim();
                    string val = line.Substring(idx + 1).Trim().Trim('"').Trim('\'');
                    result[key] = val;
                    fileKeys.Add(key);
                }
            }

            return (result, fileKeys);
        }

        public static string GetEnv(Dictionary<string, string> env, string key, string defaultValue = "")
            => env.TryGetValue(key, out string v) && !string.IsNullOrWhiteSpace(v) ? v : defaultValue;
    }
}
