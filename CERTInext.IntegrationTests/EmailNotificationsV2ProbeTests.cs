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
// Live probe for issue 0027 item 1b (EmailNotifications value vocabulary — V2). The V2
// spec documents `emailNotifications` as "Optional (default `all`)" but every single
// create-request example across all three product families sends exactly `"all"` — no
// alternate value appears anywhere in the spec text. This probe places ONE real V2 OV SSL
// order with `emailNotifications` set to `"0"` (V1's connector-config "notifications off"
// value) instead of `"all"`, and captures the raw HTTP status + response body from the
// create-order call (and, if the order is accepted, the Track Order response too) to
// determine whether the live CA accepts the value as-is, silently coerces it, or rejects
// the order outright.
//
// Raw HTTP only (same idiom as IdempotencyKeyV2ProbeTests.PlaceOrderRawAsync /
// OrganizationBlockV2ProbeTests.CancelSslOrderRawAsync) — deliberately bypasses
// CERTInextClient.PlaceOrderV2Async so the exact, unmodified response body can be
// inspected (the V2CreateOrderResponse/V2OrderStatusResponse DTOs have no
// emailNotifications slot at all, so going through them would silently discard the one
// piece of evidence this probe needs if the CA does echo the field back).
//
// Does NOT submit a CSR and does NOT attempt to push the order to issuance — the question
// this probe answers is fully contained in the create-order (and optional Track Order)
// response. Best-effort cancels the order afterward via the same raw cancel helper used by
// the other V2 probes in this project.
//
// Opt-in: requires CERTINEXT_PROBE_EMAIL_NOTIFICATIONS=1 (same convention as this project's
// sibling probes' CERTINEXT_PROBE_ORG_MISSING/CERTINEXT_PROBE_ORG_FIX/
// CERTINEXT_PROBE_IDEMPOTENCY_KEY flags). Not armed by default in ~/.env_certinext or
// ~/.env_certinext_v2 — an operator must deliberately opt in, since this places one real,
// potentially cost-bearing V2 OV SSL order. Uses an OV product code confirmed orderable on
// this sandbox account (issues/V2_AUDIT_TRIAGE_HANDOFF.md's "Credentials / live access"
// section: 846/847/848/849/850/851) — default 846 (OV SSL, single-domain, non-UCC),
// overridable via CERTINEXT_OV_PRODUCT_CODE. Requires CERTINEXT_ORG_NUMBER (already present
// in most ~/.env_certinext files per this repo's other live tests) since OV orders require
// the `organization` block (issue 0028).
//
// IMPORTANT — observed during authoring (2026-09-26): on this sandbox, an OV order-create
// call can silently exceed 120s and cause a client-side TaskCanceledException with NO HTTP
// response ever received (RestSharp reports it as StatusCode=0/empty body), even though the
// CA actually created the order server-side. A client-side timeout on this endpoint is
// therefore NOT proof the order was never created — before assuming a failed create call
// means "no order," check the orders report (ListOrdersV2Async / GET
// /api/certinext/v2/reports/orders) for the domain used. This is why NewApiClient below uses
// an explicit long timeout matching CERTInextClient's own 120s, and why a caller hitting this
// timeout should not simply retry without checking for an orphaned order first — retrying
// blindly after a timeout is exactly how this authoring session ended up with two live OV
// orders (1815749817, 2743834762 — both since cancelled) instead of the single order this
// probe is meant to place.

using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using RestSharp;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    public class EmailNotificationsV2ProbeTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;
        private readonly string _v2ApiUrl;
        private readonly string _v2ClientId;
        private readonly string _v2ClientSecret;
        private readonly string _v2OvProductCode;
        private readonly bool _v2Enabled;

        public EmailNotificationsV2ProbeTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;

            var env = V2EnvHelper.LoadAndPromote();

            _v2ApiUrl = V2EnvHelper.GetEnv(env, "CERTINEXT_API_URL");
            _v2ClientId = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_ID");
            _v2ClientSecret = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_SECRET");
            _v2OvProductCode = V2EnvHelper.GetEnv(env, "CERTINEXT_OV_PRODUCT_CODE", "846");

            _v2Enabled = !string.IsNullOrWhiteSpace(V2EnvHelper.GetEnv(env, "CERTINEXT_USE_V2_API"))
                         && !string.IsNullOrWhiteSpace(_v2ApiUrl)
                         && !string.IsNullOrWhiteSpace(_v2ClientId)
                         && !string.IsNullOrWhiteSpace(_v2ClientSecret);
        }

        /// <summary>
        /// Places ONE real V2 OV order with <c>emailNotifications: "0"</c> (not the spec's
        /// only-documented value, <c>"all"</c>) and reports the raw create-order HTTP
        /// status/body, whether the field is echoed back anywhere (create response or Track
        /// Order), and whether the order was accepted, rejected, or something in between.
        /// No CSR is submitted and the order is never pushed toward issuance. Best-effort
        /// cancels the order afterward.
        ///
        /// Opt-in: requires CERTINEXT_PROBE_EMAIL_NOTIFICATIONS=1, plus a configured
        /// CERTINEXT_ORG_NUMBER for the OV order's required organization block. Neither is
        /// set by default.
        /// </summary>
        [SkippableFact]
        public async Task EmailNotifications_V2_NonAllValue_ObservesCaResponse()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            string probeFlag = Environment.GetEnvironmentVariable("CERTINEXT_PROBE_EMAIL_NOTIFICATIONS");
            Skip.If(string.IsNullOrWhiteSpace(probeFlag) || probeFlag != "1",
                "CERTINEXT_PROBE_EMAIL_NOTIFICATIONS=1 not set — this probe places a real, " +
                "potentially cost-bearing OV order and is opt-in only. Skipping.");

            string organizationNumber = _fixture.IsConfigured ? _fixture.OrgNumber : null;
            Skip.If(string.IsNullOrWhiteSpace(organizationNumber),
                "CERTINEXT_ORG_NUMBER not set in ~/.env_certinext — no pre-vetted organization " +
                "number is available to populate the OV order's required organization block. Skipping.");

            string domain = $"probe-0027-emailnotif-{DateTime.UtcNow:yyyyMMddHHmmss}.example.com";
            var orderReq = new V2CreateSslOrderRequest
            {
                ProductVariant = "ov",
                EmailNotifications = "0", // <-- the value under test; spec only documents "all"
                Requestor = new V2Requestor
                {
                    Name = _fixture.IsConfigured ? _fixture.Config.RequestorName : "Keyfactor Test",
                    Email = _fixture.IsConfigured ? _fixture.Config.RequestorEmail : "test@example.com",
                    Phone = "0000000000",
                    Designation = "IT Administrator"
                },
                Organization = new V2OrganizationParams
                {
                    OrganizationNumber = organizationNumber,
                    PreVetted = true
                },
                Certificate = new V2CertificateParams
                {
                    Domain = domain,
                    AutoSecureWww = false
                },
                Subscription = new V2SubscriptionParams
                {
                    ValidityYears = 1,
                    AutoRenew = false,
                    RenewBeforeDays = 30
                },
                Agreement = new V2AgreementParams
                {
                    SignerName = _fixture.IsConfigured ? _fixture.Config.RequestorName : "Keyfactor Test",
                    SignerIp = "127.0.0.1",
                    SignerPlace = "Gateway Lab",
                    Accepted = true
                },
                Remarks = "Issue 0027 item 1b live probe — emailNotifications=\"0\" instead of \"all\". " +
                          "No CSR submitted; not pushed to issuance."
            };

            string requestJson = JsonSerializer.Serialize(orderReq, GetJsonOptions());

            _output.WriteLine("=== Issue 0027 item 1b live probe: V2 emailNotifications=\"0\" on an OV order ===");
            _output.WriteLine($"Domain={domain} ProductCode={_v2OvProductCode} OrganizationNumber={organizationNumber}");
            _output.WriteLine($"Request body: {requestJson}");
            _output.WriteLine("");

            var createResp = await PlaceOrderRawAsync(_v2OvProductCode, requestJson);
            _output.WriteLine($"--- Create-order response ---");
            _output.WriteLine($"HTTP {createResp.StatusCode}");
            _output.WriteLine($"Body: {createResp.Body}");

            bool echoedInCreate = createResp.Body?.IndexOf("emailNotifications", StringComparison.OrdinalIgnoreCase) >= 0;
            _output.WriteLine($"emailNotifications present in create response body: {echoedInCreate}");

            if (!createResp.IsSuccessful)
            {
                _output.WriteLine("");
                _output.WriteLine("=== VERDICT: REJECTED — CERTInext returned a non-success status for " +
                                   $"emailNotifications=\"0\". HTTP {createResp.StatusCode}: {createResp.Body} ===");
                return;
            }

            string orderId = TryExtractOrderId(createResp.Body);
            _output.WriteLine($"OrderId={orderId ?? "<none parsed>"}");

            string trackBody = null;
            bool echoedInTrack = false;
            if (!string.IsNullOrWhiteSpace(orderId))
            {
                try
                {
                    var trackResp = await TrackOrderRawAsync(orderId);
                    trackBody = trackResp.Body;
                    _output.WriteLine("");
                    _output.WriteLine("--- Track Order response ---");
                    _output.WriteLine($"HTTP {trackResp.StatusCode}");
                    _output.WriteLine($"Body: {trackResp.Body}");
                    echoedInTrack = trackBody?.IndexOf("emailNotifications", StringComparison.OrdinalIgnoreCase) >= 0;
                    _output.WriteLine($"emailNotifications present in Track Order response body: {echoedInTrack}");
                }
                catch (Exception trackEx)
                {
                    _output.WriteLine($"Track Order call failed (non-fatal to this probe): {trackEx.Message}");
                }
            }

            _output.WriteLine("");
            if (echoedInCreate || echoedInTrack)
            {
                _output.WriteLine("=== VERDICT: ACCEPTED, AND emailNotifications IS ECHOED BACK — inspect the " +
                                   "captured body above to see the echoed value (accepted-as-sent vs. coerced). ===");
            }
            else
            {
                _output.WriteLine("=== VERDICT: ACCEPTED (HTTP 2xx, no rejection) but emailNotifications is NOT " +
                                   "echoed back anywhere in the create or Track Order response — matches the spec, " +
                                   "which never surfaces this field in any response schema. Whether the CA silently " +
                                   "coerces \"0\" back to \"all\" server-side cannot be confirmed or ruled out via " +
                                   "the API alone from this probe; only that a non-\"all\" value does not cause a " +
                                   "hard rejection at create time. ===");
            }

            if (!string.IsNullOrWhiteSpace(orderId))
            {
                _output.WriteLine("");
                _output.WriteLine($"Attempting best-effort cleanup: cancelling order {orderId}...");
                try
                {
                    var cancelResp = await CancelOrderRawAsync(orderId,
                        "Issue 0027 item 1b live probe — cleaning up after observing CA response.");
                    _output.WriteLine(cancelResp.IsSuccessful
                        ? $"Cleanup: order {orderId} cancel request returned HTTP {cancelResp.StatusCode} (success)."
                        : $"Cleanup FAILED for order {orderId}: HTTP {cancelResp.StatusCode}: {cancelResp.Body}. " +
                          "Cancel it by hand in the CERTInext portal if it should not remain pending.");
                }
                catch (Exception cleanupEx)
                {
                    _output.WriteLine(
                        $"Cleanup FAILED for order {orderId}: {cleanupEx.Message}. " +
                        "Cancel it by hand in the CERTInext portal if it should not remain pending.");
                }
            }
        }

        // ---------------------------------------------------------------------------
        // Private helpers — same raw-HTTP idiom as IdempotencyKeyV2ProbeTests /
        // OrganizationBlockV2ProbeTests (see those files' header comments for rationale).
        // ---------------------------------------------------------------------------

        private static JsonSerializerOptions GetJsonOptions() => new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        private sealed class RawApiResponse
        {
            public int StatusCode { get; set; }
            public string Body { get; set; }
            public bool IsSuccessful { get; set; }
        }

        /// <summary>
        /// 120s timeout — matches CERTInextClient's own V1/V2 RestClientOptions
        /// (CERTInextClient.cs:71/88). The framework's default HttpClient timeout (100s) is
        /// too short for this sandbox's OV order-create latency and was observed to trip
        /// during authoring (HTTP 0 / empty body after ~100s, i.e. a transport-level
        /// timeout, not a real CA rejection).
        /// </summary>
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
        /// Raw HTTP POST to /api/certinext/v2/ssl-certificates. Does not throw on non-2xx —
        /// the caller needs the exact raw status/body either way, which is the entire point
        /// of this probe.
        /// </summary>
        private async Task<RawApiResponse> PlaceOrderRawAsync(string productCode, string requestJson)
        {
            string accessToken = await GetV2AccessTokenAsync();

            using var apiClient = NewApiClient(_v2ApiUrl.TrimEnd('/'));
            var req = new RestRequest(Constants.ApiV2.SslCertificatesPath, Method.Post);
            req.AddHeader("Authorization", $"Bearer {accessToken}");
            req.AddHeader("Accept", "application/json");
            req.AddHeader("X-Product-Code", productCode ?? string.Empty);
            req.AddHeader("Idempotency-Key", Guid.NewGuid().ToString());
            req.AddJsonBody(requestJson);

            var resp = await apiClient.ExecuteAsync(req);
            return ToRawApiResponse(resp);
        }

        /// <summary>
        /// Raw HTTP GET to /api/certinext/v2/ssl-certificates/{orderId} (Track Order) — used
        /// here purely to check whether emailNotifications is echoed back post-creation, not
        /// to drive any lifecycle logic.
        /// </summary>
        private async Task<RawApiResponse> TrackOrderRawAsync(string orderId)
        {
            string accessToken = await GetV2AccessTokenAsync();

            using var apiClient = NewApiClient(_v2ApiUrl.TrimEnd('/'));
            var req = new RestRequest($"{Constants.ApiV2.SslCertificatesPath}/{orderId}", Method.Get);
            req.AddHeader("Authorization", $"Bearer {accessToken}");
            req.AddHeader("Accept", "application/json");

            var resp = await apiClient.ExecuteAsync(req);
            return ToRawApiResponse(resp);
        }

        /// <summary>
        /// Raw HTTP POST to /api/certinext/v2/ssl-certificates/{orderId}/cancel — same idiom
        /// as OrganizationBlockV2ProbeTests.CancelSslOrderRawAsync, but returns the raw
        /// status/body instead of throwing on non-2xx so cleanup failure can be reported
        /// without losing the underlying detail.
        /// </summary>
        private async Task<RawApiResponse> CancelOrderRawAsync(string orderId, string reason)
        {
            string accessToken = await GetV2AccessTokenAsync();

            using var apiClient = NewApiClient(_v2ApiUrl.TrimEnd('/'));
            var cancelReq = new RestRequest($"{Constants.ApiV2.SslCertificatesPath}/{orderId}/cancel", Method.Post);
            cancelReq.AddHeader("Authorization", $"Bearer {accessToken}");
            cancelReq.AddJsonBody(new { reason });
            var cancelResp = await apiClient.ExecuteAsync(cancelReq);
            return ToRawApiResponse(cancelResp);
        }

        /// <summary>
        /// Converts a RestSharp <see cref="RestResponse"/> into the probe's raw
        /// status/body/success tuple. On a transport-level failure (no HTTP status ever
        /// received — e.g. a timeout), StatusCode/Content come back empty/zero; in that case
        /// this falls back to RestSharp's own ErrorMessage/ErrorException so the failure
        /// reason is still visible in the report rather than an unexplained "HTTP 0".
        /// </summary>
        private static RawApiResponse ToRawApiResponse(RestResponse resp)
        {
            string body = resp.Content;
            if (string.IsNullOrEmpty(body) && !resp.IsSuccessful)
            {
                body = resp.ErrorException != null
                    ? $"<no HTTP response — transport error: {resp.ErrorException.GetType().Name}: {resp.ErrorException.Message}>"
                    : $"<no HTTP response — {resp.ErrorMessage ?? resp.ResponseStatus.ToString()}>";
            }

            return new RawApiResponse
            {
                StatusCode = (int)resp.StatusCode,
                Body = body,
                IsSuccessful = resp.IsSuccessful
            };
        }

        /// <summary>
        /// Best-effort orderId extraction from a raw JSON response body. Returns null rather
        /// than throwing if the body is empty, malformed, or lacks an orderId field.
        /// </summary>
        private static string TryExtractOrderId(string body)
        {
            if (string.IsNullOrWhiteSpace(body))
                return null;

            try
            {
                using var doc = JsonDocument.Parse(body);
                return doc.RootElement.TryGetProperty("orderId", out var el) ? el.GetString() : null;
            }
            catch (JsonException)
            {
                return null;
            }
        }
    }
}
