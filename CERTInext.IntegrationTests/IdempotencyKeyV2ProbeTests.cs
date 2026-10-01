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
// Live investigation probe for issue 0032 (V2 Idempotency-Key is minted fresh on every
// call, so it can never dedupe a retry). This is purely informational — no code fix is
// planned regardless of the outcome (see issues/0032-v2-idempotency-key-not-reused-on-
// retry.md's "Live investigation" section); the maintainer asked whether the live sandbox
// already enforces Idempotency-Key dedup on V2 order-create today, ahead of the spec's own
// "parsed today, enforced in a future release" wording. Places TWO real V2 DV SSL
// order-create calls with byte-identical request bodies and the SAME hardcoded
// Idempotency-Key header value, back-to-back, and reports which of three outcomes was
// observed:
//
//   1. Same orderId returned both times          -> dedup IS enforced today.
//   2. Two distinct orderIds returned             -> dedup is NOT enforced (matches the
//                                                     spec's "future release" wording).
//   3. Second call returns a non-2xx (e.g. 409)    -> an explicit-rejection enforcement
//                                                     mode (neither of the above).
//
// Raw HTTP only (mirrors OrganizationBlockV2ProbeTests.CancelSslOrderRawAsync's idiom) —
// deliberately does NOT go through CERTInextClient.PlaceOrderV2Async, since that method
// mints a fresh GUID per call (the exact behavior under investigation) and has no
// parameter for a caller-supplied idempotency key. No production code is touched by this
// probe.
//
// Opt-in: requires CERTINEXT_PROBE_IDEMPOTENCY_KEY=1 (same convention as this file's
// sibling OrganizationBlockV2ProbeTests's CERTINEXT_PROBE_ORG_MISSING/CERTINEXT_PROBE_ORG_FIX
// flags). Not armed by default in ~/.env_certinext or ~/.env_certinext_v2 — an operator
// must deliberately opt in, since this places one or two real, potentially cost-bearing V2
// DV SSL orders (product code from CERTINEXT_PRODUCT_CODE, default 842 — the standard
// cheap/throwaway DV SSL test product already reused across V2LifecycleTests.cs/
// V2ApiTests.cs). Both orders (if dedup fails and two distinct orders are created) are
// best-effort cancelled in a finally block. Neither order ever reaches 'issued' state (no
// DCV/CSR step is involved), so plugin.Revoke is never called — matching this repo's
// convention for never-issued probe orders.

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using RestSharp;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    public class IdempotencyKeyV2ProbeTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;
        private readonly string _v2ApiUrl;
        private readonly string _v2ClientId;
        private readonly string _v2ClientSecret;
        private readonly string _v2ProductCode;
        private readonly string _v2Domain;
        private readonly bool _v2Enabled;

        /// <summary>
        /// Fixed, hardcoded Idempotency-Key value reused across BOTH order-create calls in
        /// <see cref="IdempotencyKey_V2_SameKeyTwice_ObservesDedupBehavior"/> — the entire
        /// point of the probe is that this value does NOT change between calls (unlike
        /// <c>CERTInextClient.PlaceOrderV2Async</c>'s own <c>Guid.NewGuid()</c>-per-call
        /// behavior, issue 0032's core finding).
        /// </summary>
        private const string ProbeIdempotencyKey = "00320032-0032-0032-0032-003200320032";

        public IdempotencyKeyV2ProbeTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;

            var env = V2EnvHelper.LoadAndPromote();

            _v2ApiUrl = V2EnvHelper.GetEnv(env, "CERTINEXT_API_URL");
            _v2ClientId = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_ID");
            _v2ClientSecret = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_SECRET");
            _v2ProductCode = V2EnvHelper.GetEnv(env, "CERTINEXT_PRODUCT_CODE", "842");
            _v2Domain = V2EnvHelper.GetEnv(env, "CERTINEXT_DCV_DOMAIN", "test.example.com");

            _v2Enabled = !string.IsNullOrWhiteSpace(V2EnvHelper.GetEnv(env, "CERTINEXT_USE_V2_API"))
                         && !string.IsNullOrWhiteSpace(_v2ApiUrl)
                         && !string.IsNullOrWhiteSpace(_v2ClientId)
                         && !string.IsNullOrWhiteSpace(_v2ClientSecret);
        }

        /// <summary>
        /// Places two real V2 DV SSL order-create calls, back-to-back, with byte-identical
        /// request bodies and the same hardcoded <see cref="ProbeIdempotencyKey"/> header
        /// value, and reports which of the three outcomes described in this file's header
        /// comment was observed. Informational only — no assertion is made on WHICH outcome
        /// occurs (that is the unknown this probe exists to answer); the only hard assertion
        /// is that the first call itself succeeds, since a first-call failure would be an
        /// unrelated test-environment/account problem, not a dedup-behavior finding.
        ///
        /// Opt-in: requires CERTINEXT_PROBE_IDEMPOTENCY_KEY=1. Not armed by default in
        /// ~/.env_certinext or ~/.env_certinext_v2.
        /// </summary>
        [SkippableFact]
        public async Task IdempotencyKey_V2_SameKeyTwice_ObservesDedupBehavior()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            string probeFlag = Environment.GetEnvironmentVariable("CERTINEXT_PROBE_IDEMPOTENCY_KEY");
            Skip.If(string.IsNullOrWhiteSpace(probeFlag) || probeFlag != "1",
                "CERTINEXT_PROBE_IDEMPOTENCY_KEY=1 not set — this probe places one or two real, " +
                "potentially cost-bearing V2 DV SSL orders and is opt-in only. Skipping.");

            var orderReq = BuildStandardOrderRequest();
            string requestJson = JsonSerializer.Serialize(orderReq, GetJsonOptions());

            _output.WriteLine("=== Issue 0032 live probe: V2 Idempotency-Key dedup on order-create ===");
            _output.WriteLine($"ProductCode={_v2ProductCode} Domain={_v2Domain} IdempotencyKey={ProbeIdempotencyKey}");
            _output.WriteLine($"Request body (identical bytes sent on both calls): {requestJson}");

            var orderIds = new List<string>();
            try
            {
                _output.WriteLine("");
                _output.WriteLine("--- Call 1 ---");
                var firstResp = await PlaceOrderRawAsync(ProbeIdempotencyKey, requestJson);
                _output.WriteLine($"HTTP {firstResp.StatusCode}: {firstResp.Body}");

                firstResp.IsSuccessful.Should().BeTrue(
                    "the FIRST order-create call must succeed on its own merits (unrelated to " +
                    $"idempotency-key behavior) — got HTTP {firstResp.StatusCode}: {firstResp.Body}");

                string firstOrderId = TryExtractOrderId(firstResp.Body);
                firstOrderId.Should().NotBeNullOrWhiteSpace(
                    "a successful order-create response must carry a non-empty orderId");
                orderIds.Add(firstOrderId);

                _output.WriteLine("");
                _output.WriteLine("--- Call 2 (same Idempotency-Key, same request body) ---");
                var secondResp = await PlaceOrderRawAsync(ProbeIdempotencyKey, requestJson);
                _output.WriteLine($"HTTP {secondResp.StatusCode}: {secondResp.Body}");

                string verdict;
                if (secondResp.IsSuccessful)
                {
                    string secondOrderId = TryExtractOrderId(secondResp.Body);
                    if (!string.IsNullOrWhiteSpace(secondOrderId) && secondOrderId != firstOrderId)
                        orderIds.Add(secondOrderId);

                    verdict = !string.IsNullOrWhiteSpace(secondOrderId) && secondOrderId == firstOrderId
                        ? $"OUTCOME 1 — DEDUP IS ENFORCED TODAY: both calls returned the same orderId '{firstOrderId}'."
                        : "OUTCOME 2 — DEDUP IS NOT ENFORCED: two distinct orderIds returned " +
                          $"('{firstOrderId}' and '{secondOrderId ?? "<none parsed>"}'). Matches the spec's " +
                          "\"parsed today, enforced in a future release\" wording.";
                }
                else
                {
                    verdict = $"OUTCOME 3 — EXPLICIT REJECTION: first call succeeded (orderId='{firstOrderId}'), " +
                              "second call with the same Idempotency-Key was rejected: " +
                              $"HTTP {secondResp.StatusCode}: {secondResp.Body}";
                }

                _output.WriteLine("");
                _output.WriteLine($"=== VERDICT: {verdict} ===");
            }
            finally
            {
                _output.WriteLine("");
                foreach (string orderId in orderIds)
                {
                    _output.WriteLine($"Attempting best-effort cleanup: cancelling order {orderId}...");
                    try
                    {
                        await CancelSslOrderRawAsync(orderId,
                            "Issue 0032 idempotency-key probe — cleaning up after observing CA response.");
                        _output.WriteLine($"Cleanup: order {orderId} cancel request returned success.");
                    }
                    catch (Exception cleanupEx)
                    {
                        _output.WriteLine(
                            $"Cleanup FAILED for order {orderId}: {cleanupEx.Message}. " +
                            "Cancel it by hand in the CERTInext portal if it should not remain pending.");
                    }
                }
            }
        }

        // ---------------------------------------------------------------------------
        // Private helpers
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Mirrors <c>V2ApiTests.BuildStandardOrderRequest</c>'s exact shape/fields — a
        /// standard DV SSL order-create body with no CSR and no per-call-unique field, so
        /// serializing it once and reusing the resulting JSON string for both calls
        /// guarantees byte-identical request bodies.
        /// </summary>
        private V2CreateSslOrderRequest BuildStandardOrderRequest() =>
            new V2CreateSslOrderRequest
            {
                ProductVariant = "dv",
                EmailNotifications = "all",
                Requestor = new V2Requestor
                {
                    Name = _fixture.Config?.RequestorName ?? "Keyfactor Test",
                    Email = _fixture.Config?.RequestorEmail ?? "test@example.com",
                    Phone = "0000000000",
                    Designation = "IT Administrator"
                },
                Certificate = new V2CertificateParams
                {
                    Domain = _v2Domain,
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
                    SignerName = _fixture.Config?.RequestorName ?? "Keyfactor Test",
                    SignerIp = "127.0.0.1",
                    SignerPlace = "Gateway Lab",
                    Accepted = true
                },
                Remarks = "Issue 0032 idempotency-key live probe — safe to cancel immediately."
            };

        /// <summary>
        /// Same serializer options as <c>CERTInextClient.GetJsonOptions</c> (private in that
        /// class, so duplicated here) — needed so the JSON body this probe sends matches
        /// what the production client would actually send byte-for-byte.
        /// </summary>
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
        /// Raw HTTP POST to <c>/api/certinext/v2/ssl-certificates</c> with an explicit,
        /// caller-supplied <c>Idempotency-Key</c> header — deliberately bypasses
        /// <c>CERTInextClient.PlaceOrderV2Async</c>, which mints its own fresh GUID per call
        /// and has no parameter for a caller-supplied key. Mirrors
        /// <c>OrganizationBlockV2ProbeTests.CancelSslOrderRawAsync</c>'s token-fetch idiom.
        /// Does not throw on non-2xx — the caller needs the raw status/body either way.
        /// </summary>
        private async Task<RawApiResponse> PlaceOrderRawAsync(string idempotencyKey, string requestJson)
        {
            string accessToken = await GetV2AccessTokenAsync();

            using var apiClient = new RestClient(_v2ApiUrl.TrimEnd('/'));
            var req = new RestRequest(Constants.ApiV2.SslCertificatesPath, Method.Post);
            req.AddHeader("Authorization", $"Bearer {accessToken}");
            req.AddHeader("Accept", "application/json");
            req.AddHeader("X-Product-Code", _v2ProductCode);
            req.AddHeader("Idempotency-Key", idempotencyKey);
            req.AddJsonBody(requestJson);

            var resp = await apiClient.ExecuteAsync(req);
            return new RawApiResponse
            {
                StatusCode = (int)resp.StatusCode,
                Body = resp.Content,
                IsSuccessful = resp.IsSuccessful
            };
        }

        /// <summary>
        /// Standalone OAuth2 client_credentials token fetch. Delegates to
        /// <see cref="V2RawProbeHelpers.GetV2AccessTokenAsync"/> (issue 0058) — this file used
        /// to carry its own private copy, near-identical to
        /// <c>OrganizationBlockV2ProbeTests.CancelSslOrderRawAsync</c>'s inline token request;
        /// extracted so this file, <c>OrganizationBlockV2ProbeTests</c>, and
        /// <c>V2GapProbeTests</c> share one implementation. Behavior is unchanged.
        /// </summary>
        private Task<string> GetV2AccessTokenAsync() =>
            V2RawProbeHelpers.GetV2AccessTokenAsync(_v2ApiUrl, _v2ClientId, _v2ClientSecret);

        /// <summary>
        /// Standalone cancel call for triage cleanup only. Delegates to
        /// <see cref="V2RawProbeHelpers.CancelSslOrderRawAsync"/> (issue 0058) — same idiom as
        /// <see cref="GetV2AccessTokenAsync"/> above. Behavior is unchanged.
        /// </summary>
        private Task CancelSslOrderRawAsync(string orderId, string reason) =>
            V2RawProbeHelpers.CancelSslOrderRawAsync(_v2ApiUrl, _v2ClientId, _v2ClientSecret, orderId, reason);

        /// <summary>
        /// Best-effort orderId extraction from a raw JSON response body. Returns null rather
        /// than throwing if the body is empty, malformed, or lacks an <c>orderId</c> field —
        /// callers treat a null/empty result as "could not confirm an orderId", which is
        /// itself part of the outcome this probe reports.
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
