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
// Read-only investigation probe for issue 0034 (V2 revocation date/reason DTO shape
// mismatch). Static analysis (issues/0034-v2-revocation-date-reason-dto-mismatch.md)
// already confirmed the CERTInext V2 spec documents a nested
// `revocation: {status, reason, processedAt}` object on Track Order, while
// V2OrderStatusResponse (CertificateResponseV2.cs:130-136) instead models flat top-level
// `revocationReason`/`revocationDate` properties. This probe settles the exact live wire
// shape before that DTO is fixed: it searches the sandbox account's recent V2 order
// history for an order already in a revoked state (issues/0026's live revoke work left
// several behind on 2026-09-24), then calls the raw, unparsed Track Order response for
// that order and reports the revocation-related JSON verbatim.
//
// Deliberately read-only: no order is placed, no order is revoked. Only GET calls are
// made — ListOrdersV2Async's report endpoint to search, and a raw GET against each of
// the three V2 product-family Track Order paths in turn to locate the revoked order's
// family. If no already-revoked order is found within the search window, the test
// reports that and passes without asserting a shape — creating one on demand would be a
// mutating, cost-bearing action requiring separate, explicit sign-off (out of scope here).
//
// Opt-in: requires CERTINEXT_PROBE_REVOCATION_SHAPE=1. Not armed by default in
// ~/.env_certinext or ~/.env_certinext_v2 — an operator must deliberately opt in, per
// this repo's convention for live-API probes (mirrors OrganizationBlockV2ProbeTests /
// IdempotencyKeyV2ProbeTests).

using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using RestSharp;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    public class RevocationShapeV2ProbeTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;
        private readonly string _v2ApiUrl;
        private readonly string _v2ClientId;
        private readonly string _v2ClientSecret;
        private readonly bool _v2Enabled;

        /// <summary>
        /// V2 product-family URL path segments to probe, in the same order as
        /// <c>CERTInextClient.ResolveV2OrderFamilyAsync</c> (SSL, then Private PKI, then
        /// Signature) — an order id is only ever valid within exactly one family.
        /// </summary>
        private static readonly string[] Families =
        {
            Constants.ApiV2.FamilySsl,
            Constants.ApiV2.FamilyPrivatePki,
            Constants.ApiV2.FamilySignature
        };

        public RevocationShapeV2ProbeTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;

            var env = V2EnvHelper.LoadAndPromote();

            _v2ApiUrl = V2EnvHelper.GetEnv(env, "CERTINEXT_API_URL");
            _v2ClientId = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_ID");
            _v2ClientSecret = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_SECRET");

            _v2Enabled = !string.IsNullOrWhiteSpace(V2EnvHelper.GetEnv(env, "CERTINEXT_USE_V2_API"))
                         && !string.IsNullOrWhiteSpace(_v2ApiUrl)
                         && !string.IsNullOrWhiteSpace(_v2ClientId)
                         && !string.IsNullOrWhiteSpace(_v2ClientSecret);
        }

        private CERTInextClient BuildV2Client()
        {
            return new CERTInextClient(new CERTInextConfig
            {
                ApiUrl = _v2ApiUrl,
                UseV2Api = true,
                OAuthClientId = _v2ClientId,
                OAuthClientSecret = _v2ClientSecret,
                RequestorName = _fixture.IsConfigured ? _fixture.Config.RequestorName : "Test",
                RequestorEmail = _fixture.IsConfigured ? _fixture.Config.RequestorEmail : "test@example.com",
                SignerIp = "127.0.0.1",
                SignerPlace = "Gateway Lab",
                PageSize = 100
            });
        }

        /// <summary>
        /// Read-only. Searches recent V2 order-report history (last 90 days) for an order
        /// whose orderStatus/certificateStatus display string indicates it has been
        /// revoked (mirrors <c>CERTInextCAPlugin.TryMapV2ReportDisplayStatus</c>'s
        /// "revoked" / "certificate revoked" vocabulary), then calls the raw Track Order
        /// endpoint for that order and reports the unparsed JSON response body —
        /// specifically the revocation-related portion — so the exact wire shape (nested
        /// vs flat, field names, casing, timestamp format) can be confirmed before issue
        /// 0034's DTO fix is written.
        ///
        /// Bounded to a 90-day lookback and a capped number of scanned rows so this never
        /// walks full account history (this repo's convention for shared-account
        /// contention — see the "Only run 1 fullSync at a time" memory note). issues/0026's
        /// live revoke work (2026-09-24) left multiple V2 orders in a revoked state, so a
        /// 90-day window from today should already cover them without a full-history scan.
        ///
        /// If no revoked order is found within that window, the test reports so and passes
        /// without asserting a shape — placing/revoking a fresh order to force one is a
        /// mutating, cost-bearing action out of scope for this probe.
        /// </summary>
        [SkippableFact]
        public async Task RevocationShape_V2_FindsRevokedOrderAndCapturesRawTrackOrderJson()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            string probeFlag = Environment.GetEnvironmentVariable("CERTINEXT_PROBE_REVOCATION_SHAPE");
            Skip.If(string.IsNullOrWhiteSpace(probeFlag) || probeFlag != "1",
                "CERTINEXT_PROBE_REVOCATION_SHAPE=1 not set — this probe is opt-in only per this " +
                "repo's live-API-probe convention. Skipping.");

            using var client = BuildV2Client();

            string from = DateTime.UtcNow.AddDays(-90).ToString("yyyy-MM-dd");

            _output.WriteLine("=== Issue 0034 live probe: V2 revocation date/reason wire shape ===");
            _output.WriteLine($"Searching V2 order report from={from} for an already-revoked order...");

            string revokedOrderId = null;
            string matchedOn = null;
            int scanned = 0;
            const int maxScanned = 1000; // bound the scan regardless of account size

            await foreach (var row in client.ListOrdersV2Async(from, null, 100, CancellationToken.None))
            {
                scanned++;

                if (LooksRevoked(row.CertificateStatus))
                {
                    revokedOrderId = row.OrderNumber;
                    matchedOn = $"certificateStatus='{row.CertificateStatus}'";
                    break;
                }
                if (LooksRevoked(row.OrderStatus))
                {
                    revokedOrderId = row.OrderNumber;
                    matchedOn = $"orderStatus='{row.OrderStatus}'";
                    break;
                }
                if (scanned >= maxScanned)
                    break;
            }

            _output.WriteLine($"Scanned {scanned} order report row(s).");

            if (revokedOrderId == null)
            {
                _output.WriteLine(
                    "No already-revoked V2 order found within the search window. Not creating one — " +
                    "that would be a mutating, cost-bearing action requiring separate, explicit " +
                    "sign-off. Reporting NONE FOUND for issue 0034; re-run with a wider window (or " +
                    "after a live revoke exists) if this needs to be re-verified.");
                return;
            }

            _output.WriteLine($"Found revoked order candidate: orderId={revokedOrderId} ({matchedOn})");

            var raw = await TrackOrderRawAsync(revokedOrderId);

            raw.Should().NotBeNull("a revoked order located via the report endpoint must resolve to some family");

            _output.WriteLine($"Family={raw.Family} HTTP={raw.StatusCode}");
            _output.WriteLine("Raw Track Order response body:");
            _output.WriteLine(raw.Body);

            // Best-effort slice of just the revocation-related keys, for a quick eyeball of
            // nested-vs-flat shape without re-reading the whole body by hand — the full body
            // is logged above regardless.
            string revocationSlice = ExtractRevocationSlice(raw.Body);
            _output.WriteLine("");
            _output.WriteLine(revocationSlice != null
                ? $"Revocation-related JSON slice: {revocationSlice}"
                : "No top-level 'revocation' object or flat 'revocationReason'/'revocationDate' " +
                  "keys found in the raw body — see the full body above.");

            raw.Body.Should().NotBeNullOrWhiteSpace(
                "the raw Track Order response for a revoked order must have a non-empty body");
        }

        // ---------------------------------------------------------------------------
        // Private helpers
        // ---------------------------------------------------------------------------

        private static bool LooksRevoked(string displayStatus)
        {
            if (string.IsNullOrWhiteSpace(displayStatus))
                return false;
            return displayStatus.Trim().ToLowerInvariant().Contains("revok");
        }

        private sealed class RawTrackOrderResult
        {
            public string Family { get; set; }
            public int StatusCode { get; set; }
            public string Body { get; set; }
        }

        /// <summary>
        /// Raw HTTP GET against each V2 product-family Track Order path in turn, stopping
        /// at the first non-404 response — mirrors
        /// <c>CERTInextClient.ResolveV2OrderFamilyAsync</c>'s try-each-family algorithm, but
        /// deliberately bypasses <c>CERTInextClient.TrackOrderV2Async</c>'s typed
        /// deserialization so the exact unparsed response body can be captured (same raw-
        /// HTTP idiom as <c>OrganizationBlockV2ProbeTests.CancelSslOrderRawAsync</c> /
        /// <c>IdempotencyKeyV2ProbeTests.PlaceOrderRawAsync</c>). Returns null if the order
        /// is not found in any of the three families.
        /// </summary>
        private async Task<RawTrackOrderResult> TrackOrderRawAsync(string orderId)
        {
            string accessToken = await GetV2AccessTokenAsync();

            using var apiClient = new RestClient(_v2ApiUrl.TrimEnd('/'));
            foreach (string family in Families)
            {
                var req = new RestRequest($"/api/certinext/v2/{family}/{orderId}", Method.Get);
                req.AddHeader("Authorization", $"Bearer {accessToken}");
                req.AddHeader("Accept", "application/json");
                var resp = await apiClient.ExecuteAsync(req);

                if ((int)resp.StatusCode == 404)
                    continue;

                return new RawTrackOrderResult
                {
                    Family = family,
                    StatusCode = (int)resp.StatusCode,
                    Body = resp.Content
                };
            }
            return null;
        }

        /// <summary>
        /// Same OAuth2 client_credentials token-fetch idiom as
        /// <c>OrganizationBlockV2ProbeTests.CancelSslOrderRawAsync</c> /
        /// <c>IdempotencyKeyV2ProbeTests.GetV2AccessTokenAsync</c>.
        /// </summary>
        private async Task<string> GetV2AccessTokenAsync()
        {
            string tokenUrl = _v2ApiUrl.TrimEnd('/') + "/oauth/token";
            using var tokenClient = new RestClient(tokenUrl);
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
        /// Best-effort extraction of just the revocation-related portion of a raw Track
        /// Order JSON body, checking both the spec-documented nested <c>revocation</c>
        /// object and the DTO's current (likely-wrong) flat <c>revocationReason</c>/
        /// <c>revocationDate</c> keys, whichever is present. Returns null if neither is
        /// found — the full body is still logged by the caller either way.
        /// </summary>
        private static string ExtractRevocationSlice(string body)
        {
            if (string.IsNullOrWhiteSpace(body))
                return null;

            try
            {
                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;

                if (root.TryGetProperty("revocation", out var nested))
                    return nested.GetRawText();

                bool hasFlatReason = root.TryGetProperty("revocationReason", out var flatReason);
                bool hasFlatDate = root.TryGetProperty("revocationDate", out var flatDate);
                if (hasFlatReason || hasFlatDate)
                {
                    return "{" +
                        (hasFlatReason ? $"\"revocationReason\":{flatReason.GetRawText()}" : "") +
                        (hasFlatReason && hasFlatDate ? "," : "") +
                        (hasFlatDate ? $"\"revocationDate\":{flatDate.GetRawText()}" : "") +
                        "}";
                }

                return null;
            }
            catch (JsonException)
            {
                return null;
            }
        }
    }
}
