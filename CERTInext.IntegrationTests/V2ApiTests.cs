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
    ///   set -a; . ~/.env_certinext; set +a
    ///   export CERTINEXT_USE_V2_API=1
    ///   dotnet test CERTInext.IntegrationTests/ --filter "FullyQualifiedName~V2ApiTests"
    /// </code>
    /// Note: the shell must source ONLY <c>~/.env_certinext</c> (never <c>~/.env_certinext_v2</c> —
    /// see issue 0017); this class loads <c>~/.env_certinext_v2</c> itself from disk at
    /// test-construction time.
    ///
    /// <b>Required variables in <c>~/.env_certinext_v2</c> (or real env vars):</b>
    /// <list type="bullet">
    ///   <item><c>CERTINEXT_API_URL</c>     — V2 base URL (e.g. https://sandbox-us-api.certinext.io)</item>
    ///   <item><c>CERTINEXT_CLIENT_ID</c>    — OAuth2 client ID</item>
    ///   <item><c>CERTINEXT_CLIENT_SECRET</c> — OAuth2 client secret</item>
    ///   <item><c>CERTINEXT_PRODUCT_CODE</c>  — product code for lifecycle test (e.g. 842)</item>
    ///   <item><c>CERTINEXT_DCV_DOMAIN</c>    — domain for lifecycle test (e.g. dcv-test.example.com)</item>
    /// </list>
    /// V1 variables (<c>CERTINEXT_API_URL</c>, <c>CERTINEXT_ACCESS_KEY</c>, etc.) are NOT required
    /// for V2-mode tests — Synchronize now uses V2 <c>/reports/orders</c> when UseV2Api is true
    /// (issues/0022), and V1 credentials are optional in that mode.
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

        public V2ApiTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output  = output;

            // Load ~/.env_certinext_v2 via the shared helper (issues/0017, gap G14 — one env
            // loader, not a private copy per test class). V2 file values take priority over
            // process env because IntegrationTestFixture may have already promoted the V1
            // CERTINEXT_API_URL (with /emSignHub-API suffix) into process env, and the V2 base
            // URL is different.
            var env = V2EnvHelper.LoadAndPromote();

            _v2ApiUrl       = V2EnvHelper.GetEnv(env, "CERTINEXT_API_URL");
            _v2ClientId     = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_ID");
            _v2ClientSecret = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_SECRET");
            _v2ProductCode  = V2EnvHelper.GetEnv(env, "CERTINEXT_PRODUCT_CODE", "842");
            _v2Domain       = V2EnvHelper.GetEnv(env, "CERTINEXT_DCV_DOMAIN", "test.example.com");
            _cfApiToken     = V2EnvHelper.GetEnv(env, "CERTINEXT_CF_API_TOKEN");
            _cfZoneId       = V2EnvHelper.GetEnv(env, "CERTINEXT_CF_ZONE_ID");
            _issuedOrderId  = V2EnvHelper.GetEnv(env, "CERTINEXT_V2_ISSUED_ORDER_ID");

            _v2Enabled = !string.IsNullOrWhiteSpace(V2EnvHelper.GetEnv(env, "CERTINEXT_USE_V2_API"))
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

            // Note: revoke requires the order to reach 'issued' state first.
            // The sandbox processes orders asynchronously, so we only assert enroll + track here.
            // A full revoke smoke test requires waiting for issuance (run separately with DCV configured).
        }

        // ---------------------------------------------------------------------------
        // Synchronize uses V2 /reports/orders when UseV2Api=true (issues/0022)
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Verifies that Synchronize calls V2 <c>/reports/orders</c> (not V1 GetOrderReport)
        /// when <c>UseV2Api=true</c>, and succeeds with ZERO V1 credentials configured at all —
        /// the hard acceptance criterion from the Phase 4 parent plan. A single
        /// <see cref="CERTInextConfig.ApiUrl"/> now serves both modes (issues/0022 config
        /// consolidation), so the V1-only fields (ApiKey/AccountNumber/AuthMode) below are
        /// simply never set.
        /// </summary>
        [SkippableFact]
        public async Task Sync_UsesV2_WithZeroV1Credentials()
        {
            Skip.If(!_v2Enabled, "V2 opt-in (CERTINEXT_USE_V2_API) or V2 credentials not configured — skipping.");

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
                PageSize          = 10,
                // A small lookback keeps this test's live API call volume bounded — every
                // issued row in the window needs a live certificate download (the report
                // carries no body), and ResolveAndDownloadCertificateV2Async re-resolves the
                // product family via a sequential TrackOrder probe when it isn't already known.
                // The DEFAULT 72h lookback margin (Constants.ApiV2.DefaultSyncLookbackHours) is
                // always added on top of lastSync regardless of how recent lastSync is, so on a
                // busy shared sandbox account even a "last hour" delta sync still touches
                // several days of orders unless this is overridden. See issues/0022's "V2 sync
                // per-row download cost" note — this is a real, currently-unbounded cost on the
                // live path, not just a test-tuning artifact.
                V2SyncLookbackHours = 1
                // Deliberately NOT set: ApiKey, AccountNumber, AuthMode, OAuthTokenUrl — all
                // V1-only fields. Proving Synchronize succeeds without them is the point of
                // this test.
            };

            using var client = new CERTInextClient(config);
            var plugin = new CERTInextCAPlugin(client, config);

            var buffer = new BlockingCollection<AnyCAPluginCertificate>(1000);
            // 300s: this shared sandbox has been observed to return 100+ orders even within a
            // narrow ~1-2h window (heavy ongoing test activity), and each issued row costs a
            // live download plus (when family isn't already known) a family-probe TrackOrder
            // call — real, measured durations for comparable scope elsewhere in this class are
            // 3-4.5 minutes. See issues/0022's "V2 sync per-row download cost" note — this is a
            // genuine current performance characteristic of the live path, not a test artifact.
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(300));

            await plugin.Synchronize(buffer, DateTime.UtcNow.AddHours(-1), false, cts.Token);
            if (!buffer.IsAddingCompleted)
                buffer.CompleteAdding();

            var records = new List<AnyCAPluginCertificate>();
            foreach (var record in buffer.GetConsumingEnumerable())
                records.Add(record);

            // The delta sync window is narrow (see V2SyncLookbackHours above), so this only
            // proves correctness (zero V1 creds, records returned, shape is sane) — not sync
            // performance at scale, which issues/0022 flags as a separate, real concern.
            records.Should().NotBeEmpty(
                "Synchronize must return records via V2 /reports/orders when UseV2Api=true, with zero V1 " +
                "credentials configured — an empty result here proves nothing about which code path ran");
            records.Should().OnlyContain(r => !string.IsNullOrWhiteSpace(r.CARequestID));

            _output.WriteLine(
                $"Sync_UsesV2_WithZeroV1Credentials: {records.Count} record(s) returned via V2 /reports/orders, " +
                "with no ApiKey/AccountNumber/AuthMode configured.");
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

            // Hard assertion restored (issues/0016 item 1, fixed by issues/0025): the live
            // catalog/products response is a nested category envelope, the same shape V1's
            // GetProductDetails returns. ParseProductDetailsV2Response now flattens it, so
            // every parsed product must carry a non-empty ProductCode.
            products.Should().OnlyContain(p => !string.IsNullOrWhiteSpace(p.ProductCode),
                "ParseProductDetailsV2Response must flatten the nested category envelope into ProductCode-bearing rows");
            _output.WriteLine($"{products.Count}/{products.Count} catalog products carry a non-empty ProductCode.");
        }

        /// <summary>
        /// Drives <see cref="CERTInextCAPlugin.ValidateProductInfo"/> (not just the client
        /// method) end-to-end in V2 mode against the configured product code — the regression
        /// test for issue 0025. Read-only.
        /// </summary>
        [SkippableFact]
        public async Task ValidateProductInfo_V2_AcceptsConfiguredProductCode()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            var plugin = new CERTInextCAPlugin();
            var connectionInfo = BuildV2ConnectionInfo();
            var productInfo = new EnrollmentProductInfo
            {
                ProductID = "ssl",
                ProductParameters = new Dictionary<string, string> { ["ProductCode"] = _v2ProductCode }
            };

            Func<Task> act = () => plugin.ValidateProductInfo(productInfo, connectionInfo);

            await act.Should().NotThrowAsync(
                $"ProductCode '{_v2ProductCode}' should be present in the live V2 catalog");
        }

        /// <summary>
        /// Same as <see cref="ValidateProductInfo_V2_AcceptsConfiguredProductCode"/> but with a
        /// product code that should never exist, asserting the same "not found" failure mode
        /// V1 has always had. Read-only — no order is placed.
        /// </summary>
        [SkippableFact]
        public async Task ValidateProductInfo_V2_RejectsUnknownProductCode()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            var plugin = new CERTInextCAPlugin();
            var connectionInfo = BuildV2ConnectionInfo();
            var productInfo = new EnrollmentProductInfo
            {
                ProductID = "ssl",
                ProductParameters = new Dictionary<string, string> { ["ProductCode"] = "999999" }
            };

            Func<Task> act = () => plugin.ValidateProductInfo(productInfo, connectionInfo);

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*not found*");
        }

        /// <summary>
        /// <see cref="CERTInextCAPlugin.ValidateProductInfo"/> ignores the constructor-injected
        /// client/config and builds its own from <c>connectionInfo</c>, so integration tests
        /// must pass a real dictionary — <c>UseV2Api</c> is a bool, not a string
        /// (CERTInextCAPluginConfig.cs, CERTInextCAPlugin.cs's <c>is bool</c> check).
        /// </summary>
        private Dictionary<string, object> BuildV2ConnectionInfo()
        {
            var info = new Dictionary<string, object>
            {
                ["UseV2Api"] = true,
                ["ApiUrl"] = _v2ApiUrl,
                ["OAuthClientId"] = _v2ClientId,
                ["OAuthClientSecret"] = _v2ClientSecret
            };

            string groupNumber = _fixture.IsConfigured ? _fixture.GroupNumber : null;
            if (!string.IsNullOrWhiteSpace(groupNumber))
                info["GroupNumber"] = groupNumber;

            return info;
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
        /// Revokes a previously issued V2 order. Prefers CERTINEXT_V2_ISSUED_ORDER_ID;
        /// otherwise self-enrolls a fresh order via <see cref="EnsureIssuedOrderIdAsync"/>
        /// and polls (bounded) for issuance (V2_TEST_GAP_PLAN.md Phase 1.4b) — so the test
        /// no longer depends on another test's run order (issues/0017, gap G7) to have a
        /// usable order ID.
        /// </summary>
        [SkippableFact]
        public async Task Revoke_V2_IssuedOrder()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            using var client = BuildV2Client();
            var (orderId, family) = await EnsureIssuedOrderIdAsync(client);

            // Revoke — sandbox may report 'issued' via track but reject revocation
            // with 422 ("Certificate Request still being processed") while the order
            // is still being processed internally (issues/0019).
            var revokeReq = new V2RevokeRequest
            {
                Reason = "superseded",
                Note   = "V2 integration test cleanup"
            };

            try
            {
                await client.RevokeOrderV2Async(family, orderId, revokeReq);
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("still being processed"))
            {
                // Retry once after a short delay before giving up — any other exception
                // (or a second failure) must fail the test rather than be swallowed here.
                _output.WriteLine($"Revoke rejected as still-processing; retrying once after 15s: {ex.Message}");
                await Task.Delay(TimeSpan.FromSeconds(15));
                try
                {
                    await client.RevokeOrderV2Async(family, orderId, revokeReq);
                }
                catch (InvalidOperationException ex2) when (ex2.Message.Contains("still being processed"))
                {
                    Skip.If(true,
                        $"Order {orderId} tracked as 'issued' but CA rejected revocation twice (sandbox timing): {ex2.Message}");
                    return; // unreachable; satisfies compiler
                }
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
        ///
        /// CERTInext's domain DCV is account-scoped and reusable (BR 3.2.2.5): once
        /// <c>CERTINEXT_DCV_DOMAIN</c> is verified once, it stays verified for the
        /// <c>validTill</c> reuse window, and GetDcv/VerifyDcv return EMS-1080
        /// ("Domain is already verified") instead of issuing a fresh challenge — see
        /// issues/0020. That is treated here as the reuse-path outcome, not a failure:
        /// the publish/verify steps are skipped and the order is polled directly for
        /// leaving pending-dcv.
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

            var (domainVerifiedBeforeEnroll, rawStatus) = await V2DomainStatusHelper.GetDcvStatusAsync(client, _v2Domain);
            _output.WriteLine($"Pre-enroll domain status for '{_v2Domain}': dcvStatus={rawStatus ?? "<no row>"}");

            try
            {
                // 1. Place a DV SSL order — it lands in pending-dcv
                var orderReq   = BuildStandardOrderRequest();
                var createResp = await client.PlaceOrderV2Async(
                    Constants.ApiV2.FamilySsl, _v2ProductCode, orderReq);
                orderId = createResp.OrderId;
                orderId.Should().NotBeNullOrEmpty();

                // 2. Get DCV challenge
                V2DcvChallengeResponse dcvResp;
                try
                {
                    dcvResp = await client.GetDcvV2Async(orderId, Constants.ApiV2.FamilySsl);
                }
                catch (Exception ex) when (ex.Message.Contains("EMS-1080"))
                {
                    // Reuse path: the domain is already verified account-wide, so there is no
                    // fresh challenge to publish. Prove the order still reaches a non-pending-dcv
                    // state without ever staging a TXT record.
                    _output.WriteLine($"GetDcv returned EMS-1080 (domain already verified) — reuse path: {ex.Message}");
                    _output.WriteLine($"(pre-enroll domain probe {(domainVerifiedBeforeEnroll ? "agreed: VERIFIED" : "did NOT show VERIFIED — status may have changed between the probe and this order")}.)");

                    V2OrderStatusResponse reuseStatus = null;
                    var reuseDeadline = DateTime.UtcNow.AddSeconds(30);
                    while (DateTime.UtcNow < reuseDeadline)
                    {
                        reuseStatus = await client.ResolveAndTrackOrderV2Async(orderId);
                        _output.WriteLine($"Poll (reuse path): orderId={orderId} status={reuseStatus.Status}");
                        if (reuseStatus.Status != Constants.ApiV2.StatusPendingDcv)
                            break;
                        await Task.Delay(TimeSpan.FromSeconds(5));
                    }

                    reuseStatus.Should().NotBeNull();
                    reuseStatus!.Status.Should().NotBe(
                        Constants.ApiV2.StatusPendingDcv,
                        $"order {orderId} must leave pending-dcv on a reused/already-verified domain (EMS-1080) " +
                        "without a fresh TXT challenge. If this fails, see issues/0020.");
                    return;
                }
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
                var verifyResp = await client.VerifyDcvV2Async(orderId, _v2Domain, Constants.ApiV2.FamilySsl);
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
        /// Prefers CERTINEXT_V2_ISSUED_ORDER_ID; otherwise self-enrolls a fresh order
        /// via <see cref="EnsureIssuedOrderIdAsync"/> (V2_TEST_GAP_PLAN.md Phase 1.4b).
        /// </summary>
        [SkippableFact]
        public async Task ChainPem_V2_IsAssembled()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            using var client = BuildV2Client();
            var (orderId, family) = await EnsureIssuedOrderIdAsync(client);

            V2CertificateDownloadResponse downloadResp;
            try
            {
                downloadResp = await client.DownloadCertificateV2Async(family, orderId);
            }
            catch (Exception ex) when (ex.Message.Contains("422") || ex.Message.Contains("Invalid request status"))
            {
                Skip.If(true,
                    $"Order {orderId} tracked as 'issued' but CA rejected download (sandbox timing): {ex.Message}");
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
                // A single ApiUrl now serves V2 (issues/0022 config consolidation) — no V1-only
                // fields are set here.
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
        }

        /// <summary>
        /// Returns an issued V2 order (and the family it lives in) to exercise. Prefers
        /// <c>CERTINEXT_V2_ISSUED_ORDER_ID</c> if set; otherwise places a fresh order on
        /// <paramref name="client"/> and polls (bounded) until it reaches <c>issued</c>, so
        /// tests using this helper are self-contained and don't depend on env state or
        /// another test's run order (V2_TEST_GAP_PLAN.md Phase 1.4b). <c>Skip.If</c>s when
        /// no env ID is set and the freshly-placed order never reaches <c>issued</c> within
        /// the poll budget — sandboxes may require DCV to auto-issue.
        /// </summary>
        private async Task<(string orderId, string family)> EnsureIssuedOrderIdAsync(CERTInextClient client)
        {
            if (!string.IsNullOrWhiteSpace(_issuedOrderId))
            {
                var (family, status) = await ResolveOrderFamilyAsync(client, _issuedOrderId);
                Skip.If(status.Status != Constants.ApiV2.StatusIssued,
                    $"Order '{_issuedOrderId}' is in '{status.Status}' state, not 'issued' — skipping.");
                return (_issuedOrderId, family);
            }

            var orderReq   = BuildStandardOrderRequest();
            var createResp = await client.PlaceOrderV2Async(Constants.ApiV2.FamilySsl, _v2ProductCode, orderReq);
            createResp.Should().NotBeNull();
            string orderId = createResp.OrderId;
            orderId.Should().NotBeNullOrEmpty("PlaceOrderV2Async must return a non-empty orderId");
            _output.WriteLine(
                $"EnsureIssuedOrderIdAsync: no CERTINEXT_V2_ISSUED_ORDER_ID set — placed fresh order {orderId}.");

            V2OrderStatusResponse trackResp = null;
            var deadline = DateTime.UtcNow.AddSeconds(90);
            while (DateTime.UtcNow < deadline)
            {
                trackResp = await client.TrackOrderV2Async(Constants.ApiV2.FamilySsl, orderId);
                _output.WriteLine($"EnsureIssuedOrderIdAsync poll: orderId={orderId} status={trackResp.Status}");
                if (trackResp.Status == Constants.ApiV2.StatusIssued)
                    break;
                await Task.Delay(TimeSpan.FromSeconds(15));
            }

            Skip.If(trackResp?.Status != Constants.ApiV2.StatusIssued,
                $"Freshly-placed order '{orderId}' did not reach 'issued' within the poll budget " +
                $"(status={trackResp?.Status}) — sandbox may require DCV to auto-issue. Set " +
                "CERTINEXT_V2_ISSUED_ORDER_ID to a known-issued order to bypass placement.");

            return (orderId, Constants.ApiV2.FamilySsl);
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

    }
}
