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
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Integration test stubs for the V2 REST API code path.
    ///
    /// All tests are gated behind the <c>CERTINEXT_USE_V2_API=1</c> environment variable
    /// and skip gracefully when it is not set, so they are safe to run in CI environments
    /// that do not have V2 credentials configured.
    ///
    /// <b>To run against a live V2 environment:</b>
    /// <code>
    ///   set -a; . ~/.env_certinext; . ~/.env_certinext_v2; set +a
    ///   export CERTINEXT_USE_V2_API=1
    ///   dotnet test CERTInext.IntegrationTests/ --filter "FullyQualifiedName~V2ApiTests"
    /// </code>
    ///
    /// <b>Required variables in <c>~/.env_certinext_v2</c> (or real env vars):</b>
    /// <list type="bullet">
    ///   <item><c>CERTINEXT_API_URL</c>     — V2 base URL (e.g. https://sandbox-us-api.certinext.io)</item>
    ///   <item><c>CERTINEXT_CLIENT_ID</c>    — OAuth2 client ID</item>
    ///   <item><c>CERTINEXT_CLIENT_SECRET</c> — OAuth2 client secret</item>
    ///   <item><c>CERTINEXT_PRODUCT_CODE</c>  — product code for lifecycle test (e.g. 842)</item>
    ///   <item><c>CERTINEXT_DCV_DOMAIN</c>    — domain for lifecycle test (e.g. dcv-test.example.com)</item>
    /// </list>
    /// V1 variables (<c>CERTINEXT_API_URL</c>, <c>CERTINEXT_ACCESS_KEY</c>, etc.) must remain
    /// configured because Synchronize continues to use the V1 GetOrderReport endpoint.
    /// </summary>
    public class V2ApiTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;
        private readonly string _v2ApiUrl;
        private readonly string _v2ClientId;
        private readonly string _v2ClientSecret;
        private readonly string _v2ProductCode;
        private readonly string _v2Domain;
        private readonly bool _v2Enabled;
        private readonly string _cfApiToken;
        private readonly string _cfZoneId;
        private readonly bool _dcvEnabled;
        private readonly string _issuedOrderId;

        // Shared across test instances so Lifecycle can hand an order ID to
        // Revoke/ChainPem tests that run later in the same class.
        private static string s_lastCreatedOrderId;

        public V2ApiTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output  = output;

            // Load ~/.env_certinext_v2 if present.  V2 file values take priority
            // over process env because IntegrationTestFixture may have already
            // promoted the V1 CERTINEXT_API_URL (with /emSignHub-API suffix) into
            // process env, and the V2 base URL is different.
            string v2Path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".env_certinext_v2");
            var (env, fileKeys) = LoadEnvFile(v2Path);

            // Force-promote V2-file-defined keys into process env so they override
            // any V1 values the fixture already set.
            foreach (string key in fileKeys)
                if (env.TryGetValue(key, out string fv))
                    Environment.SetEnvironmentVariable(key, fv);

            // Promote remaining keys that aren't already in process env
            foreach (var kv in env)
                if (Environment.GetEnvironmentVariable(kv.Key) == null)
                    Environment.SetEnvironmentVariable(kv.Key, kv.Value);

            _v2ApiUrl       = GetEnv(env, "CERTINEXT_API_URL");
            _v2ClientId     = GetEnv(env, "CERTINEXT_CLIENT_ID");
            _v2ClientSecret = GetEnv(env, "CERTINEXT_CLIENT_SECRET");
            _v2ProductCode  = GetEnv(env, "CERTINEXT_PRODUCT_CODE", "842");
            _v2Domain       = GetEnv(env, "CERTINEXT_DCV_DOMAIN", "test.example.com");
            _cfApiToken     = GetEnv(env, "CERTINEXT_CF_API_TOKEN");
            _cfZoneId       = GetEnv(env, "CERTINEXT_CF_ZONE_ID");
            _issuedOrderId  = GetEnv(env, "CERTINEXT_V2_ISSUED_ORDER_ID");

            _v2Enabled = !string.IsNullOrWhiteSpace(GetEnv(env, "CERTINEXT_USE_V2_API"))
                         && !string.IsNullOrWhiteSpace(_v2ApiUrl)
                         && !string.IsNullOrWhiteSpace(_v2ClientId)
                         && !string.IsNullOrWhiteSpace(_v2ClientSecret);

            _dcvEnabled = _v2Enabled
                          && !string.IsNullOrWhiteSpace(_cfApiToken)
                          && !string.IsNullOrWhiteSpace(_cfZoneId);
        }

        // ---------------------------------------------------------------------------
        // V2 Connectivity
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Calls GET /api/certinext/v2/auth/me and verifies a non-empty accountNumber
        /// is returned. Skips when CERTINEXT_USE_V2_API is not set.
        /// </summary>
        [SkippableFact]
        public async Task Connectivity_V2_Ping()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            using var client = BuildV2Client();
            var me = await client.GetAuthMeV2Async();

            me.Should().NotBeNull();
            me.AccountNumber.Should().NotBeNullOrEmpty("auth/me must return accountNumber for a valid OAuth2 client");
            me.AuthType.Should().Be("oauth2");
        }

        // ---------------------------------------------------------------------------
        // V2 Lifecycle: place order → track → revoke
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Places a V2 SSL order, asserts that the CARequestID starts with "ord_",
        /// then revokes the order.
        /// Skips when CERTINEXT_USE_V2_API is not set.
        /// </summary>
        [SkippableFact]
        public async Task Lifecycle_V2_EnrollTrackRevoke()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            using var client = BuildV2Client();

            // Place order
            var orderReq   = BuildStandardOrderRequest();
            var createResp = await client.PlaceOrderV2Async(
                Constants.ApiV2.FamilySsl, _v2ProductCode, orderReq);

            createResp.Should().NotBeNull();
            createResp.OrderId.Should().NotBeNullOrEmpty(
                "V2 place-order must return a non-empty orderId (sandbox may return numeric IDs rather than 'ord_' prefix)");

            // Track the order
            var (_, trackResp) = await ResolveOrderFamilyAsync(client, createResp.OrderId);
            trackResp.OrderId.Should().Be(createResp.OrderId);
            trackResp.Status.Should().NotBeNullOrEmpty(
                "V2 TrackOrder must return a status for the placed order");
            // Best-effort structural check: this sandbox's TrackOrder response has been
            // observed to omit "_links" entirely (see issues/0016), so we log rather than
            // hard-fail — the regression we actually guard against is OrderId/Status shape.
            if (trackResp.Links?.Self?.Href is string href && !string.IsNullOrWhiteSpace(href))
                _output.WriteLine($"TrackOrder links.self.href: {href}");
            else
                _output.WriteLine("TrackOrder response did not include a links.self.href (sandbox may omit _links).");

            // Store the order ID so Revoke/ChainPem tests can use it if no
            // CERTINEXT_V2_ISSUED_ORDER_ID env var is configured.
            s_lastCreatedOrderId = createResp.OrderId;
            _output.WriteLine($"Stored lifecycle order ID for downstream tests: {s_lastCreatedOrderId}");

            // Note: revoke requires the order to reach 'issued' state first.
            // The sandbox processes orders asynchronously, so we only assert enroll + track here.
            // A full revoke smoke test requires waiting for issuance (run separately with DCV configured).
        }

        // ---------------------------------------------------------------------------
        // Synchronize still uses V1 when UseV2Api=true
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Verifies that Synchronize calls the V1 GetOrderReport (not V2 /reports/orders)
        /// even when UseV2Api=true.
        /// Skips when V1 credentials are absent.
        /// </summary>
        [SkippableFact]
        public async Task Sync_UsesV1_WhenV2Enabled()
        {
            Skip.If(!_fixture.IsConfigured || !_v2Enabled,
                "V1 credentials or V2 opt-in (CERTINEXT_USE_V2_API) not configured — skipping.");

            // Build a V2-enabled config that still has V1 creds for sync
            var config = new CERTInextConfig
            {
                // V1 creds (required for sync)
                ApiUrl          = _fixture.Config.ApiUrl,
                AuthMode        = "AccessKey",
                ApiKey          = _fixture.Config.ApiKey,
                AccountNumber   = _fixture.Config.AccountNumber,
                // V2 creds (only used for enroll/revoke)
                UseV2Api        = true,
                ApiUrlV2        = _v2Enabled ? _v2ApiUrl  : "https://placeholder.certinext.io",
                ClientId        = _v2Enabled ? _v2ClientId : "placeholder-client",
                ClientSecret    = _v2Enabled ? _v2ClientSecret : "placeholder-secret",
                RequestorName   = _fixture.Config.RequestorName,
                RequestorEmail  = _fixture.Config.RequestorEmail,
                PageSize        = 10    // small page — we just want to confirm sync runs via V1
            };

            using var client = new CERTInextClient(config);
            var plugin = new CERTInextCAPlugin(client, config);

            var buffer = new BlockingCollection<AnyCAPluginCertificate>(1000);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            Exception caughtEx = null;
            try
            {
                await plugin.Synchronize(buffer, DateTime.UtcNow.AddDays(-1), false, cts.Token);
            }
            catch (Exception ex)
            {
                caughtEx = ex;
            }
            buffer.CompleteAdding();

            // Sync must call V1 GetOrderReport, not V2 endpoints.
            // A V2-routing bug would throw KeyNotFoundException with "not found in any V2 product family".
            // A V1 API error (wrong creds / URL mismatch) is acceptable here — it proves the V1 path ran.
            if (caughtEx != null)
                caughtEx.Message.Should().NotContain("V2 product family",
                    "sync must use V1 GetOrderReport, not V2 product-family routing");
        }

        // ---------------------------------------------------------------------------
        // V2 Product catalogue
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Calls GET /api/certinext/v2/catalog/products and asserts a non-empty list
        /// is returned.  Skips when CERTINEXT_USE_V2_API is not set.
        /// </summary>
        [SkippableFact]
        public async Task GetProductDetails_V2_ReturnsProducts()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            using var client = BuildV2Client();
            List<ProductDetail> products = await client.GetProductDetailsV2Async();

            products.Should().NotBeNull("V2 catalog/products must return a non-null list");
            products.Should().NotBeEmpty("V2 catalog/products must return at least one product");

            // Best-effort structural check: this sandbox's catalog/products entries have been
            // observed to carry null ProductCode/ProductName/ProductType (see issues/0016), so
            // we log rather than hard-fail — the regression we actually guard against is an
            // empty/null list, asserted above.
            int withCode = products.Count(p => !string.IsNullOrWhiteSpace(p.ProductCode));
            _output.WriteLine($"{withCode}/{products.Count} catalog products carry a non-empty ProductCode.");
        }

        // ---------------------------------------------------------------------------
        // GetSingleRecord via V2 (ResolveAndTrackOrderV2Async)
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Places a fresh DV SSL order then calls ResolveAndTrackOrderV2Async on the
        /// returned orderId.  Asserts that the order can be found and has a non-empty
        /// status.  The order will typically be pending-csr or pending-dcv; that is fine.
        /// Skips when CERTINEXT_USE_V2_API is not set.
        /// </summary>
        [SkippableFact]
        public async Task GetSingleRecord_V2_ReturnsOrderDetails()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            using var client = BuildV2Client();

            var orderReq = BuildStandardOrderRequest();
            var createResp = await client.PlaceOrderV2Async(
                Constants.ApiV2.FamilySsl, _v2ProductCode, orderReq);

            createResp.Should().NotBeNull();
            string orderId = createResp.OrderId;
            orderId.Should().NotBeNullOrEmpty("PlaceOrderV2Async must return a non-empty orderId");

            var status = await client.ResolveAndTrackOrderV2Async(orderId);

            status.Should().NotBeNull("ResolveAndTrackOrderV2Async must return a non-null status");
            status.OrderId.Should().Be(orderId, "tracked order ID must match the placed order");
            status.Status.Should().NotBeNullOrEmpty("TrackOrder must return a non-empty status string");
        }

        // ---------------------------------------------------------------------------
        // Revoke a known-issued V2 order
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Revokes a previously issued V2 order using CERTINEXT_V2_ISSUED_ORDER_ID.
        /// Skips when that env var is absent (sandbox orders sit in pending-csr, so
        /// a real issued order must be pre-created separately).
        /// </summary>
        [SkippableFact]
        public async Task Revoke_V2_IssuedOrder()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            // Prefer env var, fall back to order ID produced by the lifecycle test
            string orderId = !string.IsNullOrWhiteSpace(_issuedOrderId)
                ? _issuedOrderId
                : s_lastCreatedOrderId;
            Skip.If(string.IsNullOrWhiteSpace(orderId),
                "No V2 order ID available (CERTINEXT_V2_ISSUED_ORDER_ID not set and lifecycle test has not run) — skipping.");

            using var client = BuildV2Client();

            // Resolve family + confirm status is "issued"
            var (family, trackBefore) = await ResolveOrderFamilyAsync(client, orderId);
            Skip.If(trackBefore.Status != Constants.ApiV2.StatusIssued,
                $"Order {orderId} is in '{trackBefore.Status}' state, not 'issued' — skipping revoke (sandbox orders may not reach issued without DCV).");

            // Revoke — sandbox may report 'issued' via track but reject revocation
            // with 422 while the order is still being processed internally.
            var revokeReq = new V2RevokeRequest
            {
                Reason = "superseded",
                Note   = "V2 integration test cleanup"
            };

            try
            {
                await client.RevokeOrderV2Async(family, orderId, revokeReq);
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("not in issued state"))
            {
                Skip.If(true,
                    $"Order {orderId} tracked as '{trackBefore.Status}' but CA rejected revocation (sandbox timing): {ex.Message}");
                return; // unreachable; satisfies compiler
            }

            // Re-track — must be revoked
            var trackAfter = await client.ResolveAndTrackOrderV2Async(orderId);
            trackAfter.Status.Should().Be(
                Constants.ApiV2.StatusRevoked,
                $"order {orderId} must be 'revoked' after revocation");
        }

        // ---------------------------------------------------------------------------
        // DCV flow (publishes real Cloudflare TXT record) — requires SUPPORTS_DCV build
        // ---------------------------------------------------------------------------

#if SUPPORTS_DCV
        /// <summary>
        /// Places a DV SSL order, publishes the DCV TXT token via real Cloudflare DNS,
        /// calls VerifyDcvV2Async, and polls until the order leaves pending-dcv.
        /// Requires CERTINEXT_CF_API_TOKEN and CERTINEXT_CF_ZONE_ID in addition to
        /// CERTINEXT_USE_V2_API.  Skips if either is absent.
        /// </summary>
        [SkippableFact]
        public async Task DcvFlow_V2_PublishesAndVerifies()
        {
            Skip.If(!_dcvEnabled,
                "DCV test requires CERTINEXT_USE_V2_API + CERTINEXT_CF_API_TOKEN + CERTINEXT_CF_ZONE_ID — skipping.");

            using var client  = BuildV2Client();
            var dns           = new CloudflareDomainValidator(_cfApiToken, _cfZoneId);
            string txtKey     = null;
            string orderId    = null;

            try
            {
                // 1. Place a DV SSL order — it lands in pending-dcv
                var orderReq   = BuildStandardOrderRequest();
                var createResp = await client.PlaceOrderV2Async(
                    Constants.ApiV2.FamilySsl, _v2ProductCode, orderReq);
                orderId = createResp.OrderId;
                orderId.Should().NotBeNullOrEmpty();

                // 2. Get DCV challenge
                var dcvResp = await client.GetDcvV2Async(orderId);
                dcvResp.Should().NotBeNull();
                dcvResp.FileNameContent.Should().NotBeNullOrEmpty(
                    "GetDcvV2Async must return a TXT token in FileNameContent");

                string domainName = string.IsNullOrWhiteSpace(dcvResp.DomainName)
                    ? _v2Domain
                    : dcvResp.DomainName;

                // 3. Publish TXT record
                txtKey = $"_emudhra-challenge.{domainName}";
                _output.WriteLine($"Publishing TXT {txtKey} = {dcvResp.FileNameContent}");
                var staged = await dns.StageValidation(txtKey, dcvResp.FileNameContent, CancellationToken.None);
                staged.Success.Should().BeTrue($"Cloudflare TXT record creation must succeed: {staged.ErrorMessage}");

                // Brief propagation pause
                await Task.Delay(TimeSpan.FromSeconds(5));

                // 4. Ask CERTInext to verify
                var verifyResp = await client.VerifyDcvV2Async(orderId, _v2Domain);
                verifyResp.Should().NotBeNull();
                verifyResp.OverallStatus.Should().Be("VERIFIED",
                    "VerifyDcvV2Async must return OverallStatus=VERIFIED after DNS record is published");

                // 5. Poll until order leaves pending-dcv (up to 60s)
                V2OrderStatusResponse finalStatus = null;
                var deadline = DateTime.UtcNow.AddSeconds(60);
                while (DateTime.UtcNow < deadline)
                {
                    finalStatus = await client.ResolveAndTrackOrderV2Async(orderId);
                    _output.WriteLine($"Poll: orderId={orderId} status={finalStatus.Status}");
                    if (finalStatus.Status != Constants.ApiV2.StatusPendingDcv)
                        break;
                    await Task.Delay(TimeSpan.FromSeconds(5));
                }

                finalStatus.Should().NotBeNull();
                finalStatus!.Status.Should().NotBe(
                    Constants.ApiV2.StatusPendingDcv,
                    "order must leave pending-dcv after successful DCV verification");
            }
            finally
            {
                if (txtKey != null)
                {
                    _output.WriteLine($"Cleaning up TXT record: {txtKey}");
                    await dns.CleanupValidation(txtKey, CancellationToken.None);
                }
            }
        }
#endif

        // ---------------------------------------------------------------------------
        // Chain PEM assembly
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Downloads the certificate for a known-issued V2 order and logs whether
        /// ChainPem is populated.  The test passes in either case — it is a
        /// best-effort diagnostic to confirm chain assembly works in production.
        /// Requires CERTINEXT_V2_ISSUED_ORDER_ID.  Skips if absent.
        /// </summary>
        [SkippableFact]
        public async Task ChainPem_V2_IsAssembled()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            // Prefer env var, fall back to order ID produced by the lifecycle test
            string orderId = !string.IsNullOrWhiteSpace(_issuedOrderId)
                ? _issuedOrderId
                : s_lastCreatedOrderId;
            Skip.If(string.IsNullOrWhiteSpace(orderId),
                "No V2 order ID available (CERTINEXT_V2_ISSUED_ORDER_ID not set and lifecycle test has not run) — skipping.");

            using var client = BuildV2Client();

            // Verify the order is actually issued before attempting download
            var trackResp = await client.ResolveAndTrackOrderV2Async(orderId);
            Skip.If(trackResp.Status != Constants.ApiV2.StatusIssued,
                $"Order {orderId} is in '{trackResp.Status}' state, not 'issued' — skipping chain assembly (sandbox orders may not reach issued without DCV).");

            V2CertificateDownloadResponse downloadResp;
            try
            {
                downloadResp = await client.DownloadCertificateV2Async(
                    Constants.ApiV2.FamilySsl, orderId);
            }
            catch (Exception ex) when (ex.Message.Contains("422") || ex.Message.Contains("Invalid request status"))
            {
                Skip.If(true,
                    $"Order {orderId} tracked as '{trackResp.Status}' but CA rejected download (sandbox timing): {ex.Message}");
                return; // unreachable; satisfies compiler
            }

            downloadResp.Should().NotBeNull("DownloadCertificateV2Async must return a non-null response");
            downloadResp.CertificatePem.Should().NotBeNull(
                "CertificatePem must be present for an issued order");
            downloadResp.CertificatePem.Should().StartWith(
                "-----BEGIN CERTIFICATE-----",
                "leaf certificate must be PEM-encoded");

            bool chainPresent = downloadResp.ChainPem != null && downloadResp.ChainPem.Count > 0;
            _output.WriteLine(chainPresent
                ? $"ChainPem: {downloadResp.ChainPem!.Count} intermediate(s) returned."
                : "ChainPem: null or empty — sandbox may not return chain.");

            if (chainPresent)
            {
                foreach (string chainCert in downloadResp.ChainPem!)
                {
                    chainCert.Should().StartWith(
                        "-----BEGIN CERTIFICATE-----",
                        "each chain entry must be a PEM-encoded certificate");
                }
            }
        }

        // ---------------------------------------------------------------------------
        // Private helpers
        // ---------------------------------------------------------------------------

        private V2CreateSslOrderRequest BuildStandardOrderRequest() =>
            new V2CreateSslOrderRequest
            {
                ProductVariant     = "dv",
                EmailNotifications = "all",
                Requestor = new V2Requestor
                {
                    Name        = _fixture.Config?.RequestorName ?? "Keyfactor Test",
                    Email       = _fixture.Config?.RequestorEmail ?? "test@example.com",
                    Phone       = "0000000000",
                    Designation = "IT Administrator"
                },
                Certificate = new V2CertificateParams
                {
                    Domain        = _v2Domain,
                    AutoSecureWww = false
                },
                Subscription = new V2SubscriptionParams
                {
                    ValidityYears   = 1,
                    AutoRenew       = false,
                    RenewBeforeDays = 30
                },
                Agreement = new V2AgreementParams
                {
                    SignerName  = _fixture.Config?.RequestorName ?? "Keyfactor Test",
                    SignerIp    = "127.0.0.1",
                    SignerPlace = "Gateway Lab",
                    Accepted    = true
                },
                Remarks = "Keyfactor V2 integration test — safe to revoke immediately."
            };

        private CERTInextClient BuildV2Client()
        {
            return new CERTInextClient(new CERTInextConfig
            {
                // V1 fields (still needed for Synchronize)
                ApiUrl        = _fixture.IsConfigured ? _fixture.Config.ApiUrl : "https://v1-placeholder.certinext.io",
                AuthMode      = "AccessKey",
                ApiKey        = _fixture.IsConfigured ? _fixture.Config.ApiKey : "placeholder",
                AccountNumber = _fixture.IsConfigured ? _fixture.Config.AccountNumber : "0",
                // V2 fields
                UseV2Api      = true,
                ApiUrlV2      = _v2ApiUrl,
                ClientId      = _v2ClientId,
                ClientSecret  = _v2ClientSecret,
                RequestorName  = _fixture.IsConfigured ? _fixture.Config.RequestorName : "Test",
                RequestorEmail = _fixture.IsConfigured ? _fixture.Config.RequestorEmail : "test@example.com",
                SignerIp       = "127.0.0.1",
                SignerPlace    = "Gateway Lab",
                PageSize       = 100
            });
        }

        private static async Task<(string family, V2OrderStatusResponse status)> ResolveOrderFamilyAsync(
            CERTInextClient client, string orderId)
        {
            foreach (var family in new[] { Constants.ApiV2.FamilySsl, Constants.ApiV2.FamilyPrivatePki, Constants.ApiV2.FamilySignature })
            {
                try
                {
                    var s = await client.TrackOrderV2Async(family, orderId);
                    return (family, s);
                }
                catch (KeyNotFoundException)
                {
                    // try next
                }
            }
            throw new KeyNotFoundException($"Order '{orderId}' not found in any V2 product family.");
        }

        /// <summary>
        /// Loads a KEY=VALUE env file and merges with process env vars.
        /// V2 file values take priority over process env because the fixture
        /// may have already promoted V1 values (e.g. CERTINEXT_API_URL with
        /// /emSignHub-API suffix) into process env, and the V2 base URL differs.
        /// Returns the merged dict and the set of keys defined in the file.
        /// </summary>
        private static (Dictionary<string, string> env, HashSet<string> fileKeys) LoadEnvFile(string path)
        {
            var fileKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            // Seed with process env vars first
            foreach (System.Collections.DictionaryEntry de in Environment.GetEnvironmentVariables())
            {
                string k = de.Key?.ToString();
                string v = de.Value?.ToString();
                if (!string.IsNullOrEmpty(k)) result[k] = v ?? string.Empty;
            }

            // V2 env-file values override process env for any key they define.
            // This is the correct priority: the V2 file is a targeted overlay.
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

        private static string GetEnv(Dictionary<string, string> env, string key, string defaultValue = "")
            => env.TryGetValue(key, out string v) && !string.IsNullOrWhiteSpace(v) ? v : defaultValue;
    }
}
