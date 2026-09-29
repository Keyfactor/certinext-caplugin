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
// Live-order support for issue 0042 (V2 DCV machinery only drives the primary domain on a UCC
// order — issues/0042-v2-ucc-dcv-only-drives-primary-domain.md). UccDcvShapeV2ProbeTests is
// strictly GET-only and targets an *existing* order; this file is the one mutating step the
// 0042 investigation needs — placing exactly one V2 DV SSL UCC order whose additionalDomains
// land on a never-before-verified base domain (*.example.com, RFC 2606 reserved), so the SANs
// stay genuinely PENDING for UccDcvShapeV2ProbeTests to inspect, instead of validating
// instantly via base-domain reuse the way order 9295677273's scrup.org SANs did.
//
// Two independent opt-in tests, each gated on its own env var so neither runs by accident:
//
//   1. PlaceUccOrder_V2_PendingSanDcv_ForIssue0042Probe (CERTINEXT_LIVE_UCC_ENROLL=1) — places
//      the order. Built with DcvEnabled=false (default) so no inline DCV publish is attempted
//      against example.com. Never retries: on any exception (including a client-side timeout,
//      which does not prove the order was never created — see v2-api-support-questions.md
//      Finding 1/2), it makes exactly one read-only /reports/orders lookup for the same primary
//      domain and logs whatever it finds, then rethrows without placing a second order.
//
//   2. CancelOrder_V2_Issue0042Probe (CERTINEXT_CANCEL_ORDER_ID=<id>) — cleanup. Same shape as
//      V2LifecycleTests.Revoke_V2_ExplicitOrder_Superseded: one plugin.GetSingleRecord check
//      before (skips if already terminal), one raw Cancel Order call (no client method exists
//      for this yet — same raw-HTTP idiom as EmailNotificationsV2ProbeTests/
//      IdempotencyKeyV2ProbeTests/OrganizationBlockV2ProbeTests' CancelSslOrderRawAsync, but
//      non-throwing so a failed cancel is reported rather than escalated), then one fresh
//      plugin.GetSingleRecord check after. No retries either direction.
//
// Run (place):
//   set -a; . ~/.env_certinext; set +a
//   export CERTINEXT_LIVE_UCC_ENROLL=1
//   dotnet test CERTInext.IntegrationTests -c Release \
//     --filter "FullyQualifiedName~PlaceUccOrder_V2_PendingSanDcv_ForIssue0042Probe" \
//     --logger "console;verbosity=detailed" > /tmp/lab0042/place.log 2>&1
//
// Run (cancel, after capturing the wire shape via UccDcvShapeV2ProbeTests):
//   export CERTINEXT_CANCEL_ORDER_ID=<order id from place.log>
//   dotnet test CERTInext.IntegrationTests -c Release \
//     --filter "FullyQualifiedName~CancelOrder_V2_Issue0042Probe" \
//     --logger "console;verbosity=detailed" > /tmp/lab0042/cancel.log 2>&1
namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    using System;
    using System.Collections.Generic;
    using System.Text.Json;
    using System.Threading;
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
    using RestSharp;
    using Xunit;
    using Xunit.Abstractions;

    public class UccPendingSanOrderProbeTests : IClassFixture<IntegrationTestFixture>
    {
        private const string LiveEnrollFlag = "CERTINEXT_LIVE_UCC_ENROLL";
        private const string CancelOrderIdFlag = "CERTINEXT_CANCEL_ORDER_ID";

        /// <summary>
        /// V2 catalog product code for "DV SSL Multi-Domain (UCC)" on this sandbox account, as
        /// live-confirmed by the 0042 wire-shape probe (order 9295677273, see the issue file's
        /// "Live wire shape" section) — NOT the V1-era Constants.Products.DefaultProductCodes
        /// value (issue 0036: V1 numbering does not match the live V2 catalog). Overridable via
        /// CERTINEXT_UCC_PRODUCT_CODE for re-use against a different account.
        /// </summary>
        private const string DefaultUccProductCode = "844";

        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;

        private readonly string _v2ApiUrl;
        private readonly string _v2ClientId;
        private readonly string _v2ClientSecret;
        private readonly string _uccProductCode;
        private readonly bool _v2Enabled;

        public UccPendingSanOrderProbeTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;

            var env = V2EnvHelper.LoadAndPromote();

            _v2ApiUrl       = V2EnvHelper.GetEnv(env, "CERTINEXT_API_URL");
            _v2ClientId     = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_ID");
            _v2ClientSecret = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_SECRET");
            _uccProductCode = V2EnvHelper.GetEnv(env, "CERTINEXT_UCC_PRODUCT_CODE", DefaultUccProductCode);

            _v2Enabled = !string.IsNullOrWhiteSpace(V2EnvHelper.GetEnv(env, "CERTINEXT_USE_V2_API"))
                         && !string.IsNullOrWhiteSpace(_v2ApiUrl)
                         && !string.IsNullOrWhiteSpace(_v2ClientId)
                         && !string.IsNullOrWhiteSpace(_v2ClientSecret);
        }

        // ---------------------------------------------------------------------------
        // Shared helpers (deliberately duplicated per this repo's existing convention
        // of small per-test-file helpers — see V2UccEnrollmentTests.cs's own comment
        // to the same effect — rather than sharing test infrastructure across files).
        // ---------------------------------------------------------------------------

        /// <summary>
        /// DcvEnabled is fixed false — this probe must not attempt to publish a DNS-01 TXT
        /// record for any *.example.com SAN (there is no real DNS provider for it, and the
        /// whole point is to observe the CA's PENDING challenge shape, not drive it to
        /// issuance). Matches this repo's documented default build (DcvSupport=false on this
        /// branch) — see CLAUDE.md.
        /// </summary>
        private CERTInextConfig BuildV2Config()
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

                PageSize = 100,

                DcvEnabled = false
            };
        }

        private CERTInextCAPlugin BuildV2Plugin(CERTInextConfig config = null)
        {
            config ??= BuildV2Config();
            var client = new CERTInextClient(config);
            return new CERTInextCAPlugin(client, config);
        }

        /// <summary>Generates a fresh RSA-2048 PKCS#10 CSR for the given CN using BouncyCastle only.</summary>
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

        // ---------------------------------------------------------------------------
        // 1. Place the order
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Places exactly one V2 DV SSL UCC order: primary domain on the always-verified
        /// dcv-test.scrup.org base domain (so the order itself places cleanly), additionalDomains
        /// on two fresh *.example.com subdomains that have never been validated on this account
        /// and cannot be (no real DNS provider is wired for RFC 2606 reserved space) — so they
        /// stay PENDING for UccDcvShapeV2ProbeTests to inspect. Never retries: a caught exception
        /// (including a client-side timeout — see v2-api-support-questions.md Finding 2's
        /// "Secondary observation") triggers exactly one read-only orders-report lookup for the
        /// same primary domain, logs whatever it finds, and rethrows.
        /// </summary>
        [SkippableFact]
        public async Task PlaceUccOrder_V2_PendingSanDcv_ForIssue0042Probe()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");
            Skip.If(Environment.GetEnvironmentVariable(LiveEnrollFlag) != "1",
                $"Set {LiveEnrollFlag}=1 to run this probe — it places one real UCC order (issue 0042). " +
                "See this file's header comment for the full run recipe.");

            string stamp = DateTime.UtcNow.ToString("yyyyMMddHHmm");
            string primary = $"ucc0042-{stamp}.dcv-test.scrup.org";
            string sanA = $"a.pending0042-{stamp}.example.com";
            string sanB = $"b.pending0042-{stamp}.example.com";

            var config = BuildV2Config();
            var plugin = BuildV2Plugin(config);

            var productInfo = new EnrollmentProductInfo
            {
                ProductID = Constants.Products.DvSslUcc,
                ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    [Constants.EnrollmentParam.ProductCode] = _uccProductCode
                }
            };

            _output.WriteLine("=== Issue 0042 live probe: placing one V2 UCC order ===");
            _output.WriteLine($"Primary domain:      {primary}");
            _output.WriteLine($"Additional domain A: {sanA}");
            _output.WriteLine($"Additional domain B: {sanB}");
            _output.WriteLine($"ProductCode:         {_uccProductCode}");

            EnrollmentResult result;
            try
            {
                result = await plugin.Enroll(
                    csr:            GenerateCsrPem(primary),
                    subject:        $"CN={primary}",
                    san:            new Dictionary<string, string[]> { ["dns"] = new[] { sanA, sanB } },
                    productInfo:    productInfo,
                    requestFormat:  RequestFormat.PKCS10,
                    enrollmentType: EnrollmentType.New);
            }
            catch (Exception ex)
            {
                _output.WriteLine("");
                _output.WriteLine($"Enroll threw: {ex.GetType().Name}: {ex.Message}");
                _output.WriteLine(
                    "Per issue 0042's no-retry rule: NOT placing a second order. A client-side error " +
                    "(including a timeout) does not prove no order was created server-side — checking " +
                    "the read-only orders report once for a same-domain match before giving up.");

                try
                {
                    string today = DateTime.UtcNow.ToString("yyyy-MM-dd");
                    var rawClient = new CERTInextClient(config);
                    var matches = new List<OrderReportEntryV2>();
                    await foreach (var entry in rawClient.ListOrdersV2Async(from: today, to: today, ct: CancellationToken.None))
                    {
                        if (string.Equals(entry.DomainName, primary, StringComparison.OrdinalIgnoreCase))
                            matches.Add(entry);
                    }

                    if (matches.Count == 0)
                    {
                        _output.WriteLine($"No order for domain '{primary}' found in today's orders report.");
                    }
                    else
                    {
                        foreach (var m in matches)
                        {
                            _output.WriteLine(
                                $"FOUND despite the exception above: OrderNumber={m.OrderNumber}, " +
                                $"OrderStatus={m.OrderStatus}, CertificateStatus={m.CertificateStatus}, " +
                                $"Domain={m.DomainName}. This order must be accounted for (report/cancel) " +
                                "even though Enroll() itself threw.");
                        }
                    }
                }
                catch (Exception lookupEx)
                {
                    _output.WriteLine($"Read-only orders-report lookup also failed: {lookupEx.Message}");
                }

                throw;
            }

            result.Should().NotBeNull();
            result.CARequestID.Should().NotBeNullOrWhiteSpace(
                "V2 Enroll must return a non-empty CARequestID even for a UCC order with pending SANs");

            _output.WriteLine("");
            _output.WriteLine("=== Order placed ===");
            _output.WriteLine($"CARequestID (OrderId): {result.CARequestID}");
            _output.WriteLine($"Status:                {result.Status}");
            _output.WriteLine($"StatusMessage:         {result.StatusMessage}");
            _output.WriteLine("");
            _output.WriteLine("Next: capture the wire shape with UccDcvShapeV2ProbeTests:");
            _output.WriteLine($"  CERTINEXT_PROBE_UCC_ORDER_ID={result.CARequestID}");
            _output.WriteLine($"  CERTINEXT_PROBE_UCC_DOMAINS={primary},{sanA},{sanB}");
            _output.WriteLine("Then clean up with CancelOrder_V2_Issue0042Probe:");
            _output.WriteLine($"  CERTINEXT_CANCEL_ORDER_ID={result.CARequestID}");
        }

        // ---------------------------------------------------------------------------
        // 2. Cancel (cleanup) — same shape as V2LifecycleTests.Revoke_V2_ExplicitOrder_Superseded
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Cleanup for the order placed above. One plugin.GetSingleRecord check before (skips if
        /// the order is already GENERATED/REVOKED — a terminal state Cancel Order does not apply
        /// to), one raw Cancel Order call (no <c>ICERTInextClient</c> method exists for this V2
        /// endpoint yet — same non-throwing raw-HTTP idiom as
        /// EmailNotificationsV2ProbeTests.CancelOrderRawAsync), and one fresh
        /// plugin.GetSingleRecord check after. Never retries the cancel call itself; a failed
        /// cancel is reported as-is and the order is left in place, per issue 0042's runbook.
        /// </summary>
        [SkippableFact]
        public async Task CancelOrder_V2_Issue0042Probe()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");
            string orderId = Environment.GetEnvironmentVariable(CancelOrderIdFlag);
            Skip.If(string.IsNullOrWhiteSpace(orderId), $"{CancelOrderIdFlag} not set — skipping.");

            var plugin = BuildV2Plugin();

            var before = await plugin.GetSingleRecord(orderId);
            _output.WriteLine($"Before cancel: CARequestID={orderId}, Status={before?.Status}");

            Skip.If(
                before?.Status == (int)EndEntityStatus.GENERATED || before?.Status == (int)EndEntityStatus.REVOKED,
                $"Order '{orderId}' is already terminal (status={before?.Status}) — Cancel Order does not apply; not cancelling.");

            var cancelResp = await CancelOrderRawAsync(
                orderId, "Issue 0042 live probe cleanup — pending-SAN DCV wire shape captured.");

            _output.WriteLine("");
            _output.WriteLine($"Cancel response: HTTP {cancelResp.StatusCode}, IsSuccessful={cancelResp.IsSuccessful}");
            _output.WriteLine($"Cancel response body: {cancelResp.Body}");

            if (!cancelResp.IsSuccessful)
            {
                _output.WriteLine(
                    "Cancel did not succeed. Per issue 0042's runbook: NOT escalating to any other " +
                    "destructive call. Leaving the order as-is; see the response above for the exact detail.");
            }

            var after = await plugin.GetSingleRecord(orderId);
            _output.WriteLine("");
            _output.WriteLine($"After cancel: Status={after?.Status}, RevocationDate={after?.RevocationDate:o}");
        }

        // ---------------------------------------------------------------------------
        // Raw HTTP helpers for the one V2 operation with no ICERTInextClient method yet
        // (Cancel Order) — same idiom as EmailNotificationsV2ProbeTests/
        // IdempotencyKeyV2ProbeTests/OrganizationBlockV2ProbeTests' CancelSslOrderRawAsync.
        // ---------------------------------------------------------------------------

        private sealed class RawApiResponse
        {
            public int StatusCode { get; set; }
            public string Body { get; set; }
            public bool IsSuccessful { get; set; }
        }

        private static RestClient NewApiClient(string baseUrl) =>
            new RestClient(new RestClientOptions(baseUrl) { Timeout = TimeSpan.FromSeconds(120) });

        private async Task<string> GetV2AccessTokenAsync()
        {
            string tokenUrl = _v2ApiUrl.TrimEnd('/') + "/oauth/token";
            using var tokenClient = NewApiClient(tokenUrl);
            var tokenReq = new RestRequest(string.Empty, Method.Post);
            tokenReq.AddHeader("Content-Type", "application/x-www-form-urlencoded");
            tokenReq.AddParameter("grant_type", "client_credentials");
            tokenReq.AddParameter("client_id", _v2ClientId);
            tokenReq.AddParameter("client_secret", _v2ClientSecret);
            var tokenResp = await tokenClient.ExecuteAsync(tokenReq);
            if (!tokenResp.IsSuccessful || string.IsNullOrWhiteSpace(tokenResp.Content))
                throw new Exception($"Token request failed: {(int)tokenResp.StatusCode}");

            using var tokenDoc = JsonDocument.Parse(tokenResp.Content);
            return tokenDoc.RootElement.GetProperty("access_token").GetString();
        }

        /// <summary>
        /// Raw HTTP POST to /api/certinext/v2/ssl-certificates/{orderId}/cancel. Returns the raw
        /// status/body instead of throwing on non-2xx, so a failed cancel can be reported without
        /// losing detail and without the caller needing to catch an exception to see it.
        /// </summary>
        private async Task<RawApiResponse> CancelOrderRawAsync(string orderId, string reason)
        {
            string accessToken = await GetV2AccessTokenAsync();

            using var apiClient = NewApiClient(_v2ApiUrl.TrimEnd('/'));
            var cancelReq = new RestRequest($"{Constants.ApiV2.SslCertificatesPath}/{orderId}/cancel", Method.Post);
            cancelReq.AddHeader("Authorization", $"Bearer {accessToken}");
            cancelReq.AddHeader("Accept", "application/json");
            cancelReq.AddJsonBody(new { reason });
            var cancelResp = await apiClient.ExecuteAsync(cancelReq);

            string body = cancelResp.Content;
            if (string.IsNullOrEmpty(body) && !cancelResp.IsSuccessful)
            {
                body = cancelResp.ErrorException != null
                    ? $"<no HTTP response — transport error: {cancelResp.ErrorException.GetType().Name}: {cancelResp.ErrorException.Message}>"
                    : $"<no HTTP response — {cancelResp.ErrorMessage ?? cancelResp.ResponseStatus.ToString()}>";
            }

            return new RawApiResponse
            {
                StatusCode = (int)cancelResp.StatusCode,
                Body = body,
                IsSuccessful = cancelResp.IsSuccessful
            };
        }
    }
}
