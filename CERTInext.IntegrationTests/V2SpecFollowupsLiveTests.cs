// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Live checks for the V2 spec follow-ups (issues 0094/0095). Each test has its own opt-in flag on
    /// top of <c>CERTINEXT_USE_V2_API</c>, so one can be run alone. They report what the sandbox does
    /// in the test output even where the sandbox lacks a feature (for example no SSL.com backend), so
    /// the result shows what a customer on the same account shape would hit.
    /// </summary>
    public class V2SpecFollowupsLiveTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;
        private readonly System.Collections.Generic.Dictionary<string, string> _env;
        private readonly string _v2ApiUrl;
        private readonly string _v2ClientId;
        private readonly string _v2ClientSecret;
        private readonly string _v2Domain;
        private readonly bool _v2Enabled;

        public V2SpecFollowupsLiveTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output  = output;
            _env = V2EnvHelper.LoadAndPromote();
            _v2ApiUrl       = V2EnvHelper.GetEnv(_env, "CERTINEXT_API_URL");
            _v2ClientId     = V2EnvHelper.GetEnv(_env, "CERTINEXT_CLIENT_ID");
            _v2ClientSecret = V2EnvHelper.GetEnv(_env, "CERTINEXT_CLIENT_SECRET");
            _v2Domain       = V2EnvHelper.GetEnv(_env, "CERTINEXT_DCV_DOMAIN", "test.example.com");
            _v2Enabled = !string.IsNullOrWhiteSpace(V2EnvHelper.GetEnv(_env, "CERTINEXT_USE_V2_API"))
                         && !string.IsNullOrWhiteSpace(_v2ApiUrl)
                         && !string.IsNullOrWhiteSpace(_v2ClientId)
                         && !string.IsNullOrWhiteSpace(_v2ClientSecret);
        }

        private bool Flag(string name) => V2EnvHelper.GetEnv(_env, name) == "1";

        private CERTInextClient BuildV2Client() =>
            new CERTInextClient(new CERTInextConfig
            {
                ApiUrl            = _v2ApiUrl,
                UseV2Api          = true,
                OAuthClientId     = _v2ClientId,
                OAuthClientSecret = _v2ClientSecret,
                RequestorName  = _fixture.IsConfigured ? _fixture.Config.RequestorName : "Test",
                RequestorEmail = _fixture.IsConfigured ? _fixture.Config.RequestorEmail : "test@example.com",
                SignerIp       = "127.0.0.1",
                SignerPlace    = "Gateway Lab",
                PageSize       = 100
            });

        private CERTInextConfig BuildV2Config() =>
            new CERTInextConfig
            {
                ApiUrl            = _v2ApiUrl,
                UseV2Api          = true,
                V2InlineCsr       = V2EnvHelper.InlineCsrFromEnv,
                OAuthClientId     = _v2ClientId,
                OAuthClientSecret = _v2ClientSecret,
                RequestorName         = _fixture.IsConfigured ? _fixture.Config.RequestorName : "Keyfactor Test",
                RequestorEmail        = _fixture.IsConfigured ? _fixture.Config.RequestorEmail : "test@example.com",
                RequestorIsdCode      = "1",
                RequestorMobileNumber = "0000000000",
                SignerPlace           = "Gateway Lab",
                SignerIp              = "127.0.0.1",
                PageSize              = 100,
                DcvEnabled            = false,
                PickupRetries         = 0
            };

        private CERTInextCAPlugin BuildV2Plugin(CERTInextConfig config = null)
        {
            config ??= BuildV2Config();
            return new CERTInextCAPlugin(new CERTInextClient(config), config);
        }

        /// <summary>RSA-2048 PKCS#10 CSR for <paramref name="commonName"/> (BouncyCastle only).</summary>
        private static string GenerateCsrPem(string commonName)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            var keyPair = keyGen.GenerateKeyPair();
            var csr = new Pkcs10CertificationRequest(
                "SHA256withRSA", new X509Name($"CN={commonName}"), keyPair.Public, null, keyPair.Private);
            return "-----BEGIN CERTIFICATE REQUEST-----\n"
                + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                + "\n-----END CERTIFICATE REQUEST-----";
        }

        /// <summary>
        /// Enrolls a pinned DV order for <c>CERTINEXT_DCV_DOMAIN</c> through the plugin and polls Track
        /// Order (up to <paramref name="waitSeconds"/>) for <c>issued</c>. Returns the order id and its
        /// last status; the caller must clean the order up.
        /// </summary>
        private async Task<(string orderId, string status)> PlaceOwnDvOrderAsync(CERTInextClient client, int waitSeconds = 90)
        {
            var result = await BuildV2Plugin().Enroll(
                csr:            GenerateCsrPem(_v2Domain),
                subject:        $"CN={_v2Domain}",
                san:            new Dictionary<string, string[]> { ["dns"] = new[] { _v2Domain } },
                productInfo:    V2ProductPinning.Info(Constants.Products.DvSsl, V2PinMode.Pinned),
                requestFormat:  RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);
            _output.WriteLine($"Placed own order: CARequestID={result.CARequestID}, Status={result.Status}, " +
                              $"Message={result.StatusMessage}");
            result.CARequestID.Should().NotBeNullOrWhiteSpace("the test needs its own order");

            string status = null;
            var deadline = DateTime.UtcNow.AddSeconds(waitSeconds);
            while (true)
            {
                var tracked = await client.ResolveAndTrackOrderV2Async(result.CARequestID);
                status = tracked.Status;
                if (status == Constants.ApiV2.StatusIssued || DateTime.UtcNow >= deadline) break;
                await Task.Delay(TimeSpan.FromSeconds(10));
            }
            _output.WriteLine($"Own order {result.CARequestID}: status={status}");
            return (result.CARequestID, status);
        }

        /// <summary>Top-level key names of the first <c>content[]</c> row, for shape discovery (no values).</summary>
        private static string FirstRowKeys(string json)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("content", out var c) && c.ValueKind == JsonValueKind.Array
                    && c.GetArrayLength() > 0 && c[0].ValueKind == JsonValueKind.Object)
                    return string.Join(", ", c[0].EnumerateObject().Select(p => p.Name));
                return "(no rows)";
            }
            catch (JsonException)
            {
                return "(not JSON)";
            }
        }

        private static int RowCount(string json)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                return doc.RootElement.TryGetProperty("content", out var c) && c.ValueKind == JsonValueKind.Array
                    ? c.GetArrayLength() : -1;
            }
            catch (JsonException)
            {
                return -1;
            }
        }

        // ---------------------------------------------------------------------------
        // 0094 item 1: SSL.com domain-level DCV (read-only)
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Read-only. Runs the plugin's domain lookup on <c>CERTINEXT_DCV_DOMAIN</c> exactly as the DCV
        /// flow does, lists any domains the account has with <c>validatedBy=SSLCOM</c>, and, when one
        /// exists, reads its <c>GET /domains/{id}/dcv</c> to see SSL.com's record shape (method names and
        /// caStatus only; record values are not printed). Publishes and verifies nothing.
        /// Opt-in: <c>CERTINEXT_V2_SSLCOM_DCV_PROBE=1</c>.
        /// </summary>
        [SkippableFact]
        public async Task SslComDomainDcv_LookupAndShape_Probe()
        {
            Skip.If(!_v2Enabled || !Flag("CERTINEXT_V2_SSLCOM_DCV_PROBE"),
                "Requires CERTINEXT_USE_V2_API + V2 credentials and CERTINEXT_V2_SSLCOM_DCV_PROBE=1.");

            using var client = BuildV2Client();

            // 1. The lookup the DCV flow makes for every pending domain.
            var raw = await client.ProbeV2GetAsync(
                $"/api/certinext/v2/domains?search={Uri.EscapeDataString(_v2Domain)}&exactMatch=true");
            _output.WriteLine($"GET /domains?search={_v2Domain}&exactMatch=true -> HTTP {raw.StatusCode}, " +
                              $"rows={RowCount(raw.Content)}, rowKeys=[{FirstRowKeys(raw.Content)}]");
            raw.StatusCode.Should().Be(200, "the DCV flow's domain lookup must work for SSL.com detection");

            var row = await client.FindDomainV2Async(_v2Domain);
            _output.WriteLine(row == null
                ? "FindDomainV2Async: no row for the test domain (emSign path; nothing to detect)."
                : $"FindDomainV2Async: id={(string.IsNullOrEmpty(row.DomainId) ? "(MISSING)" : "present")}, " +
                  $"dcvStatus={row.DcvStatus}, validatedBy={row.ValidatedBy ?? "(absent = emSign)"}");
            if (row != null)
                row.DomainId.Should().NotBeNullOrEmpty("the SSL.com path needs the row id for /domains/{id}/dcv");

            // 2. Does the account have any SSL.com-validated domains at all?
            var sslCom = await client.ProbeV2GetAsync("/api/certinext/v2/domains?validatedBy=SSLCOM&limit=5");
            int sslComRows = RowCount(sslCom.Content);
            _output.WriteLine($"GET /domains?validatedBy=SSLCOM -> HTTP {sslCom.StatusCode}, rows={sslComRows}, " +
                              $"rowKeys=[{FirstRowKeys(sslCom.Content)}]");

            if (sslCom.StatusCode != 200 || sslComRows <= 0)
            {
                _output.WriteLine("RESULT: no SSL.com-validated domains on this account; the SSL.com DCV path " +
                                  "is not verifiable live here. Customers on emSign accounts keep the order-level flow.");
                return;
            }

            // 3. SSL.com's DCV record shape for the first such domain.
            using var doc = JsonDocument.Parse(sslCom.Content);
            var first = doc.RootElement.GetProperty("content")[0];
            string name = first.TryGetProperty("domainName", out var n) ? n.GetString() : null;
            var sslRow = await client.FindDomainV2Async(name);
            _output.WriteLine($"SSL.com domain {name}: validatedBy={sslRow?.ValidatedBy}, dcvStatus={sslRow?.DcvStatus}");
            try
            {
                var details = await client.GetDomainDcvV2Async(sslRow!.DomainId);
                var option = details.SelectDnsTxtOption();
                _output.WriteLine($"GET /domains/{{id}}/dcv: method={details.Method}, caStatus={details.CaStatus}, " +
                                  $"offered=[{details.DescribeOfferedMethods()}], dnsTxtOptionUsable={option != null}, " +
                                  $"recordName={option?.RecordName ?? "(none)"}");
            }
            catch (Exception ex)
            {
                _output.WriteLine($"GET /domains/{{id}}/dcv failed: {ex.Message}");
                _output.WriteLine("RESULT: a customer on this account would see DCV left pending with this warning.");
            }
        }
        // ---------------------------------------------------------------------------
        // 0094 item 2: revoke reason privilege-withdrawn
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Places its own pinned DV order and, once Track Order shows it <c>issued</c>, revokes it
        /// directly with <c>privilege-withdrawn</c> (dropped from the 2.0.0 spec's SSL/TLS enum) to see
        /// whether CERTInext still accepts it. If CERTInext rejects it, the order is revoked through the
        /// plugin with CRL reason 9 instead, which exercises the <c>cessation-of-operation</c> fallback.
        /// Touches only the order it creates. Opt-in: <c>CERTINEXT_V2_REVOKE_PRIVILEGE_WITHDRAWN=1</c>.
        /// </summary>
        [SkippableFact]
        public async Task Revoke_PrivilegeWithdrawn_OwnOrder_ReportsCaAcceptance()
        {
            Skip.If(!_v2Enabled || !Flag("CERTINEXT_V2_REVOKE_PRIVILEGE_WITHDRAWN"),
                "Requires CERTINEXT_USE_V2_API + V2 credentials and CERTINEXT_V2_REVOKE_PRIVILEGE_WITHDRAWN=1.");

            using var client = BuildV2Client();
            var restoreLogging = TestOutputLogging.RouteTo(_output);
            string orderId = null;
            try
            {
                string status;
                (orderId, status) = await PlaceOwnDvOrderAsync(client);
                Skip.If(status != Constants.ApiV2.StatusIssued,
                    $"Own order {orderId} did not reach issued (status={status}); nothing to revoke. Cleaned up below.");

                try
                {
                    await client.RevokeOrderV2Async(Constants.ApiV2.FamilySsl, orderId, new V2RevokeRequest
                    {
                        Reason = Constants.RevocationReasonV2.PrivilegeWithdrawn,
                        Note   = "V2 integration test, privilege-withdrawn acceptance check"
                    });
                    var after = await client.ResolveAndTrackOrderV2Async(orderId);
                    _output.WriteLine($"RESULT: CERTInext ACCEPTED privilege-withdrawn. Re-tracked status={after.Status}, " +
                                      $"revocation reason={after.Revocation?.Reason ?? "(none)"}");
                }
                catch (InvalidOperationException ex) when (CERTInextCAPlugin.IsRevokeReasonRejection(ex.Message))
                {
                    _output.WriteLine($"RESULT: CERTInext REJECTED privilege-withdrawn: {ex.Message}");
                    int viaPlugin = await BuildV2Plugin().Revoke(orderId, string.Empty, 9);
                    _output.WriteLine($"Plugin Revoke(reason 9) with fallback -> {viaPlugin}");
                    viaPlugin.Should().Be((int)EndEntityStatus.REVOKED, "the fallback must revoke the order");
                }
            }
            finally
            {
                restoreLogging();
                await V2OrderCleanup.RevokeOrCancelAsync(client, orderId, "V2 integration test cleanup", _output.WriteLine);
            }
        }
        /// <summary>
        /// Sends each V2 revoke reason to one of the caller's own test orders and reports how CERTInext
        /// answers. CERTInext checks the reason before the order state, so on an order whose certificate
        /// isn't generated yet (the 2026-11 sandbox) an accepted reason answers "still being processed"
        /// and nothing changes, while a rejected one answers with its reason-rejection wording. If the
        /// certificate has been generated, the first accepted reason revokes the order, so only point
        /// this at an order the test run created and wants revoked.
        /// Opt-in: <c>CERTINEXT_V2_REVOKE_REASON_PROBE_ORDER_ID=&lt;own order id&gt;</c>.
        /// </summary>
        [SkippableFact]
        public async Task Revoke_ReasonAcceptance_OwnOrder_Probe()
        {
            string orderId = V2EnvHelper.GetEnv(_env, "CERTINEXT_V2_REVOKE_REASON_PROBE_ORDER_ID");
            Skip.If(!_v2Enabled || string.IsNullOrWhiteSpace(orderId),
                "Requires CERTINEXT_USE_V2_API + V2 credentials and CERTINEXT_V2_REVOKE_REASON_PROBE_ORDER_ID.");

            using var client = BuildV2Client();
            // Rejected-before-live reasons first, accepted ones last, so the order is revoked (if at all)
            // only after every rejected reason has been observed.
            var reasons = new[]
            {
                Constants.RevocationReasonV2.Unspecified, Constants.RevocationReasonV2.CACompromise,
                Constants.RevocationReasonV2.CertificateHold, Constants.RevocationReasonV2.AACompromise,
                Constants.RevocationReasonV2.PrivilegeWithdrawn, "remove-from-crl",
                Constants.RevocationReasonV2.AffiliationChanged, Constants.RevocationReasonV2.CessationOfOperation,
                Constants.RevocationReasonV2.KeyCompromise, Constants.RevocationReasonV2.Superseded
            };
            foreach (var reason in reasons)
            {
                var status = await client.ResolveAndTrackOrderV2Async(orderId);
                if (status.Status == Constants.ApiV2.StatusRevoked)
                {
                    _output.WriteLine($"{reason}: not sent, order is already revoked.");
                    continue;
                }
                try
                {
                    await client.RevokeOrderV2Async(Constants.ApiV2.FamilySsl, orderId,
                        new V2RevokeRequest { Reason = reason, Note = "V2 integration test, reason acceptance probe" });
                    _output.WriteLine($"{reason}: ACCEPTED and revoked.");
                }
                catch (Exception ex)
                {
                    string verdict = CERTInextCAPlugin.IsRevokeReasonRejection(ex.Message) ? "REJECTED (reason)"
                        : ex.Message.Contains("still being processed") ? "accepted (order still being processed)"
                        : "other error";
                    _output.WriteLine($"{reason}: {verdict}: {ex.Message}");
                }
            }
        }
        // ---------------------------------------------------------------------------
        // 0094 item 5: reissue via POST /ssl-certificates/{orderId}/reissue
        // ---------------------------------------------------------------------------

        // Orders the user keeps for manual tests (issue 0094 plan) and the plan's example order.
        private static readonly string[] ProtectedOrders =
        {
            "7494553568", "9179852756", "7856523635", "8389474417", "3974245235", "6753965312", "8916985882",
            "3793212921", "5461336494", "2431278382", "1663545354", "5948124826", "2669121252", "2519635936"
        };

        /// <summary>
        /// Reissues one sandbox-generated SSL/TLS order through the plugin (<c>EnrollmentType.Reissue</c>,
        /// <c>V2ReissueRevokePrevious=false</c>, so the source order is left valid) and reports the HTTP
        /// outcome, the derived order id shape, its status and certificate state, and whether Track Order and
        /// <c>/reports/orders</c> see it. The derived order is cleaned up (revoked or cancelled) afterwards.
        /// Run once, only with the maintainer's approval: it creates a derived order.
        /// Opt-in: <c>CERTINEXT_V2_LIFECYCLE_REISSUE_ENDPOINT=1</c> and
        /// <c>CERTINEXT_V2_REISSUE_SOURCE_ORDER_ID=&lt;issued, downloadable order&gt;</c>.
        /// </summary>
        [SkippableFact]
        public async Task Reissue_V2_ReissueEndpoint_DerivedOrder_Report()
        {
            string sourceId = V2EnvHelper.GetEnv(_env, "CERTINEXT_V2_REISSUE_SOURCE_ORDER_ID");
            Skip.If(!_v2Enabled || !Flag("CERTINEXT_V2_LIFECYCLE_REISSUE_ENDPOINT") || string.IsNullOrWhiteSpace(sourceId),
                "Requires CERTINEXT_USE_V2_API + V2 credentials, CERTINEXT_V2_LIFECYCLE_REISSUE_ENDPOINT=1 and " +
                "CERTINEXT_V2_REISSUE_SOURCE_ORDER_ID.");
            ProtectedOrders.Should().NotContain(sourceId, "that order is reserved for manual tests");

            using var client = BuildV2Client();
            var source = await client.TrackOrderV2Async(Constants.ApiV2.FamilySsl, sourceId);
            _output.WriteLine($"Source {sourceId}: status={source.Status}, certificateState={source.CertificateState}, " +
                              $"domain={source.Domain}, expiresAt={source.ExpiresAt}");
            Skip.If(source.Status != Constants.ApiV2.StatusIssued, $"Source order is '{source.Status}', not issued.");
            var cert = await client.DownloadCertificateV2Async(Constants.ApiV2.FamilySsl, sourceId);
            _output.WriteLine($"Source certificate serial={cert.SerialNumber}");

            // Route logs before the plugin and its client exist: their loggers are created at construction.
            var restoreLogging = TestOutputLogging.RouteTo(_output);
            var config = BuildV2Config();
            config.V2ReissueRevokePrevious = false;
            var reader = new SingleCertificateDataReader(cert.SerialNumber, sourceId,
                DateTime.TryParse(source.ExpiresAt, out var exp) ? exp.ToUniversalTime() : DateTime.UtcNow.AddDays(60));
            var plugin = new CERTInextCAPlugin(new CERTInextClient(config), reader, config);
            var info = V2ProductPinning.Info(Constants.Products.DvSsl, V2PinMode.Pinned,
                new Dictionary<string, string> { ["PriorCertSN"] = cert.SerialNumber });

            EnrollmentResult result = null;
            try
            {
                result = await plugin.Enroll(
                    csr:            GenerateCsrPem(source.Domain),
                    subject:        $"CN={source.Domain}",
                    san:            new Dictionary<string, string[]> { ["dns"] = new[] { source.Domain } },
                    productInfo:    info,
                    requestFormat:  RequestFormat.PKCS10,
                    enrollmentType: EnrollmentType.Reissue);
            }
            catch (Exception ex)
            {
                _output.WriteLine($"RESULT: Enroll(Reissue) threw: {ex.GetType().Name}: {ex.Message}");
                throw;
            }
            finally
            {
                restoreLogging();
            }

            _output.WriteLine($"RESULT: CARequestID={result.CARequestID}, Status={result.Status}, Message={result.StatusMessage}");
            string newId = result.CARequestID ?? string.Empty;
            bool derived = newId.StartsWith(sourceId, StringComparison.Ordinal) && newId.Length > sourceId.Length;
            _output.WriteLine(derived
                ? $"Derived id shape: source id + '{newId.Substring(sourceId.Length)}' suffix"
                : "Derived id shape: NOT derived from the source (fallback new order?)");

            try
            {
                var tracked = await client.ResolveAndTrackOrderV2WithFamilyAsync(result.CARequestID);
                _output.WriteLine($"Track {result.CARequestID}: family={tracked.family}, status={tracked.status.Status}, " +
                                  $"certificateState={tracked.status.CertificateState}");

                string today = DateTime.UtcNow.ToString("yyyy-MM-dd");
                bool listed = false;
                await foreach (var row in client.ListOrdersV2Async(today, today))
                {
                    if (row.OrderNumber == result.CARequestID)
                    {
                        listed = true;
                        _output.WriteLine($"/reports/orders lists it: orderStatus={row.OrderStatus}, " +
                                          $"certificateStatus={row.CertificateStatus}, productCode={row.ProductCode}");
                    }
                }
                if (!listed) _output.WriteLine("/reports/orders (today) does not list the derived order.");

                var sourceAfter = await client.TrackOrderV2Async(Constants.ApiV2.FamilySsl, sourceId);
                _output.WriteLine($"Source after reissue: status={sourceAfter.Status} (expected unchanged: issued)");
            }
            finally
            {
                if (!string.IsNullOrWhiteSpace(result.CARequestID) && result.CARequestID != sourceId)
                    await V2OrderCleanup.RevokeOrCancelAsync(client, result.CARequestID, "V2 integration test cleanup", _output.WriteLine);
            }

            result.Status.Should().NotBe((int)EndEntityStatus.FAILED, result.StatusMessage);
        }
        // ---------------------------------------------------------------------------
        // Sync: which orders make a wide V2 sync report UnresolvedStatusFallbacks (read-only)
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Read-only. Pages the whole <c>/reports/orders</c> listing (no date filter, as a full sync
        /// does), runs each row through the plugin's display-string mapping, and for every row the
        /// mapping can't place (the sync's <c>UnresolvedStatusFallbacks</c>) prints the raw
        /// <c>orderStatus</c>/<c>certificateStatus</c> and what Track Order says. Prints order numbers,
        /// statuses, product codes and dates only. Opt-in: <c>CERTINEXT_V2_UNRESOLVED_STATUS_PROBE=1</c>.
        /// </summary>
        [SkippableFact]
        public async Task Sync_UnresolvedReportStatuses_Probe()
        {
            Skip.If(!_v2Enabled || !Flag("CERTINEXT_V2_UNRESOLVED_STATUS_PROBE"),
                "Requires CERTINEXT_USE_V2_API + V2 credentials and CERTINEXT_V2_UNRESOLVED_STATUS_PROBE=1.");

            using var client = BuildV2Client();
            int total = 0;
            var combos = new Dictionary<string, int>();
            var unresolved = new List<OrderReportEntryV2>();
            // Rows the mapping places, but only from one of the two fields, or where the fields disagree.
            var mismatched = new List<OrderReportEntryV2>();
            await foreach (var row in client.ListOrdersV2Async())
            {
                total++;
                string key = $"{row.OrderStatus} | {row.CertificateStatus}";
                combos[key] = combos.TryGetValue(key, out int c) ? c + 1 : 1;
                if (CERTInextCAPlugin.MapV2ReportStatusToDisposition(row.OrderStatus, row.CertificateStatus) == null)
                    unresolved.Add(row);
                else if (CERTInextCAPlugin.MapV2ReportStatusToDisposition(null, row.CertificateStatus) == null
                         || CERTInextCAPlugin.MapV2ReportStatusToDisposition(null, row.CertificateStatus)
                            != CERTInextCAPlugin.MapV2ReportStatusToDisposition(row.OrderStatus, null))
                    mismatched.Add(row);
            }
            _output.WriteLine($"Report rows: {total}. Status combinations:");
            foreach (var kv in combos.OrderByDescending(k => k.Value))
                _output.WriteLine($"  {kv.Value,5}  {kv.Key}");

            // Track a sample of each mismatched combination (not every row: a combination can have hundreds).
            var sample = mismatched.GroupBy(r => $"{r.OrderStatus} | {r.CertificateStatus}")
                .SelectMany(g => g.Take(3)).ToList();
            _output.WriteLine($"Mapped from one field only, or fields disagree: {mismatched.Count} rows; tracking up to 3 per combination:");
            foreach (var row in sample)
            {
                int? mapped = CERTInextCAPlugin.MapV2ReportStatusToDisposition(row.OrderStatus, row.CertificateStatus);
                string track;
                try
                {
                    var (family, st) = await client.ResolveAndTrackOrderV2WithFamilyAsync(row.OrderNumber);
                    track = $"status={st.Status}, orderState={st.OrderState}, certificateState={st.CertificateState}";
                }
                catch (Exception ex)
                {
                    track = $"{ex.GetType().Name}: {ex.Message}";
                }
                _output.WriteLine($"  {row.OrderNumber}  '{row.OrderStatus} | {row.CertificateStatus}' mapped={mapped} " +
                                  $"product={row.ProductCode} -> Track: {track}");
            }

            _output.WriteLine($"Unresolved (would fall back to Track Order): {unresolved.Count}");
            foreach (var row in unresolved)
            {
                string track;
                try
                {
                    var (family, st) = await client.ResolveAndTrackOrderV2WithFamilyAsync(row.OrderNumber);
                    track = $"family={family}, status={st.Status}, orderState={st.OrderState}, certificateState={st.CertificateState}";
                }
                catch (Exception ex)
                {
                    track = $"{ex.GetType().Name}: {ex.Message}";
                }
                _output.WriteLine($"  {row.OrderNumber}  orderStatus='{row.OrderStatus}' certificateStatus='{row.CertificateStatus}' " +
                                  $"product={row.ProductCode} orderDate={row.OrderDate} -> Track: {track}");
            }
        }
        /// <summary>
        /// Read-only. Runs the plugin's real full V2 Synchronize (DCV off), scoped to
        /// <c>CERTINEXT_GROUP_NUMBER</c> like the lab gateway, and reports what it emitted. The plugin's
        /// own "synchronization complete" line (UnresolvedStatusFallbacks, UntrackableListedOrders,
        /// Errors) goes to the test output; run with <c>CERTINEXT_TEST_LOG_LEVEL=Information</c> to keep
        /// the output short. Downloads the certificate of every issued order it lists.
        /// Opt-in: <c>CERTINEXT_V2_FULL_SYNC_PROBE=1</c>.
        /// </summary>
        [SkippableFact]
        public async Task Sync_V2_FullSync_Summary_Probe()
        {
            Skip.If(!_v2Enabled || !Flag("CERTINEXT_V2_FULL_SYNC_PROBE"),
                "Requires CERTINEXT_USE_V2_API + V2 credentials and CERTINEXT_V2_FULL_SYNC_PROBE=1.");

            var restoreLogging = TestOutputLogging.RouteTo(_output);
            try
            {
                var config = BuildV2Config();
                config.GroupNumber = V2EnvHelper.GetEnv(_env, "CERTINEXT_GROUP_NUMBER", string.Empty);
                var plugin = BuildV2Plugin(config);
                var buffer = new BlockingCollection<AnyCAPluginCertificate>(boundedCapacity: 20_000);
                await plugin.Synchronize(buffer, lastSync: null, fullSync: true, cancelToken: System.Threading.CancellationToken.None);
                buffer.CompleteAdding();
                var byStatus = buffer.GroupBy(r => r.Status).OrderBy(g => g.Key)
                    .Select(g => $"{g.Key}={g.Count()}");
                _output.WriteLine($"RESULT: emitted {buffer.Count} records by status: {string.Join(", ", byStatus)} " +
                                  $"(GroupNumber={(string.IsNullOrEmpty(config.GroupNumber) ? "(none)" : config.GroupNumber)})");
            }
            finally
            {
                restoreLogging();
            }
        }
    }

    /// <summary>
    /// Gateway database stand-in for the live reissue test: maps one serial to one order id, as the
    /// gateway does for <c>PriorCertSN</c>.
    /// </summary>
    internal sealed class SingleCertificateDataReader : ICertificateDataReader
    {
        private readonly string _serial;
        private readonly string _orderId;
        private readonly DateTime? _expiry;

        public SingleCertificateDataReader(string serial, string orderId, DateTime? expiry)
        {
            _serial = serial;
            _orderId = orderId;
            _expiry = expiry;
        }

        public Task<string> GetRequestIDBySerialNumber(string serialNumber) =>
            Task.FromResult(string.Equals(serialNumber, _serial, StringComparison.OrdinalIgnoreCase) ? _orderId : null);

        public DateTime? GetExpirationDateByRequestId(string requestId) =>
            string.Equals(requestId, _orderId, StringComparison.Ordinal) ? _expiry : null;

        public Task<int> GetStatusByRequestID(string requestId) => Task.FromResult(0);

        public Task<bool> DoesCertExistForRequestID(string requestId) =>
            Task.FromResult(string.Equals(requestId, _orderId, StringComparison.Ordinal));
    }
}
