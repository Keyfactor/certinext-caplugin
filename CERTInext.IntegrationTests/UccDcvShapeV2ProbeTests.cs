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
// Read-only investigation probe for issue 0042 (V2 DCV machinery only drives the primary
// domain on a UCC order — issues/0042-v2-ucc-dcv-only-drives-primary-domain.md). Before
// generalizing PerformDcvV2IfNeededAsync to loop over a UCC order's full SAN set, this
// confirms the real wire shape of a live UCC order sitting in pending-dcv:
//
//   1. Does Track Order (GET /api/certinext/v2/{family}/{orderId}) surface per-SAN DCV
//      status anywhere (field names/shape), or only ever the single top-level "domain"
//      field that V2OrderStatusResponse currently models (CertificateResponseV2.cs:124)?
//   2. Does Get DCV Challenges (GET /api/certinext/v2/ssl-certificates/{orderId}/dcv),
//      called once per SAN via its documented optional "domain" query parameter, return a
//      distinct challenge token per domain, or does it 404 / error / silently ignore the
//      query param for a UCC order?
//
// Targets a specific already-existing live order rather than placing a new one — no
// order-create, CSR-submission, or DCV-verify call is made by this probe. Points at
// order 9295677273 (product 844, DV SSL Multi-Domain UCC; primary
// ucc-0047-09282059.dcv-test.scrup.org, additionalDomains
// ucc-0047-09282059-b.dcv-test.scrup.org / ucc-0047-09282059-c.dcv-test.scrup.org) by
// default via env vars, so this probe can be re-pointed at a different UCC order later
// without editing code.
//
// Raw HTTP only (same idiom as RevocationShapeV2ProbeTests.TrackOrderRawAsync /
// EmailNotificationsV2ProbeTests' raw-response helpers) — deliberately bypasses
// CERTInextClient.TrackOrderV2Async / GetDcvV2Async's typed deserialization (the whole
// point is to see the exact, unmodified response body, including any fields those DTOs
// do not yet model — V2DcvChallengeResponse in particular is already known to have
// diverged from earlier spec examples once before, issues/0037).
//
// Strictly GET-only: Track Order once, then Get DCV Challenges once per domain. No
// verify-DCV, publish, cancel, revoke, or order-create calls of any kind, and no
// retries/polling loops — each call is attempted exactly once and its raw result (success
// or failure) is logged as-is.
//
// Opt-in: requires CERTINEXT_PROBE_UCC_ORDER_ID to be set (skips otherwise — this repo's
// convention for live-API probes). CERTINEXT_PROBE_UCC_DOMAINS (comma-separated) is
// optional; if unset, this falls back to a best-effort scan of the raw Track Order body
// for a primary "domain" field plus a handful of plausible SAN-array field names
// (additionalDomains/domains/sans/sanList/sanDomains/domainList) — logged either way, full
// raw body always printed regardless of what the scan finds.
namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text.Json;
    using System.Threading;
    using System.Threading.Tasks;
    using FluentAssertions;
    using RestSharp;
    using Xunit;
    using Xunit.Abstractions;

    public class UccDcvShapeV2ProbeTests : IClassFixture<IntegrationTestFixture>
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
        /// Signature) — an order id is only ever valid within exactly one family. The
        /// target order for issue 0042 is a UCC SSL order, so this is expected to resolve
        /// on the first entry, but all three are tried for robustness (mirrors
        /// RevocationShapeV2ProbeTests.Families).
        /// </summary>
        private static readonly string[] Families =
        {
            Constants.ApiV2.FamilySsl,
            Constants.ApiV2.FamilyPrivatePki,
            Constants.ApiV2.FamilySignature
        };

        /// <summary>
        /// Best-effort candidate field names for a UCC order's SAN list on the raw Track
        /// Order body, tried only when CERTINEXT_PROBE_UCC_DOMAINS is unset. None of these
        /// are confirmed live — issue 0042 explicitly flags this as unconfirmed — this is
        /// purely a diagnostic aid; the full raw body is always logged regardless of what
        /// (if anything) this scan finds.
        /// </summary>
        private static readonly string[] CandidateSanArrayFields =
        {
            "additionalDomains", "domains", "sans", "sanList", "sanDomains", "domainList"
        };

        public UccDcvShapeV2ProbeTests(IntegrationTestFixture fixture, ITestOutputHelper output)
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

        /// <summary>
        /// Read-only. Fetches the raw Track Order response for the order named by
        /// CERTINEXT_PROBE_UCC_ORDER_ID, then calls the raw Get DCV Challenges endpoint
        /// once per domain (CERTINEXT_PROBE_UCC_DOMAINS, or a best-effort scan of the Track
        /// Order body if that env var is unset), logging every raw status/body verbatim.
        /// Makes no mutating call of any kind. Passes as long as the Track Order call
        /// itself succeeds — the actual DCV-shape findings are reported via the logged raw
        /// bodies, not asserted, since the whole point of this probe is that the shape is
        /// currently unknown.
        /// </summary>
        [SkippableFact]
        public async Task UccDcvShape_V2_TrackOrderAndGetDcvChallengesRawJson()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            string orderId = Environment.GetEnvironmentVariable("CERTINEXT_PROBE_UCC_ORDER_ID");
            Skip.If(string.IsNullOrWhiteSpace(orderId),
                "CERTINEXT_PROBE_UCC_ORDER_ID not set — this probe is opt-in only and targets a " +
                "specific live UCC order (issue 0042). Skipping.");

            _output.WriteLine("=== Issue 0042 live probe: V2 UCC order DCV wire shape ===");
            _output.WriteLine($"OrderId={orderId}");

            // --- 1. Track Order (raw) ---
            var track = await TrackOrderRawAsync(orderId);

            track.Should().NotBeNull(
                $"order {orderId} must resolve to one of the known V2 product families (ssl/private-pki/signature)");

            _output.WriteLine("");
            _output.WriteLine($"--- Track Order response --- Family={track.Family} HTTP={track.StatusCode}");
            _output.WriteLine("Raw body:");
            _output.WriteLine(track.Body);

            track.Body.Should().NotBeNullOrWhiteSpace(
                "the raw Track Order response for a known live order must have a non-empty body");

            // --- 2. Resolve the domain list to probe ---
            string domainsEnv = Environment.GetEnvironmentVariable("CERTINEXT_PROBE_UCC_DOMAINS");
            List<string> domains;
            if (!string.IsNullOrWhiteSpace(domainsEnv))
            {
                domains = domainsEnv
                    .Split(',')
                    .Select(d => d.Trim())
                    .Where(d => !string.IsNullOrWhiteSpace(d))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
                _output.WriteLine("");
                _output.WriteLine($"Domains from CERTINEXT_PROBE_UCC_DOMAINS: {string.Join(", ", domains)}");
            }
            else
            {
                domains = DeriveDomainsFromTrackOrderBody(track.Body, out string derivationNote);
                _output.WriteLine("");
                _output.WriteLine("CERTINEXT_PROBE_UCC_DOMAINS not set — derived from raw Track Order body instead.");
                _output.WriteLine(derivationNote);
                _output.WriteLine(domains.Count > 0
                    ? $"Derived domain(s): {string.Join(", ", domains)}"
                    : "No domain(s) could be derived — see the full Track Order body above.");
            }

            if (domains.Count == 0)
            {
                _output.WriteLine("");
                _output.WriteLine("No domains to probe against Get DCV Challenges — stopping after Track Order.");
                return;
            }

            // --- 3. Get DCV Challenges (raw), once per domain, exactly one call each ---
            foreach (string domain in domains)
            {
                var dcv = await GetDcvChallengesRawAsync(orderId, domain, track.Family);

                _output.WriteLine("");
                _output.WriteLine($"--- Get DCV Challenges response --- Domain={domain} HTTP={dcv.StatusCode}");
                _output.WriteLine("Raw body:");
                _output.WriteLine(dcv.Body);
            }

            _output.WriteLine("");
            _output.WriteLine("=== End of issue 0042 probe. See the raw bodies above for the live DCV wire shape. ===");
        }

        // ---------------------------------------------------------------------------
        // Private helpers
        // ---------------------------------------------------------------------------

        private sealed class RawV2Response
        {
            public string Family { get; set; }
            public int StatusCode { get; set; }
            public string Body { get; set; }
        }

        /// <summary>
        /// 120s timeout — matches CERTInextClient's own V1/V2 RestClientOptions and this
        /// repo's other V2 probes (e.g. EmailNotificationsV2ProbeTests.NewApiClient) — this
        /// sandbox has been observed to occasionally exceed the framework default HttpClient
        /// timeout (100s) on some V2 endpoints.
        /// </summary>
        private static RestClient NewApiClient(string baseUrl) =>
            new RestClient(new RestClientOptions(baseUrl) { Timeout = TimeSpan.FromSeconds(120) });

        /// <summary>
        /// Same OAuth2 client_credentials token-fetch idiom as this project's other V2
        /// probes (RevocationShapeV2ProbeTests / EmailNotificationsV2ProbeTests /
        /// IdempotencyKeyV2ProbeTests / OrganizationBlockV2ProbeTests). The token itself is
        /// never logged by this file — only used to set the Authorization header on the
        /// raw requests below.
        /// </summary>
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
        /// Raw HTTP GET against each V2 product-family Track Order path in turn, stopping
        /// at the first non-404 response — same algorithm as
        /// <c>CERTInextClient.ResolveV2OrderFamilyAsync</c> / this project's
        /// RevocationShapeV2ProbeTests.TrackOrderRawAsync, but deliberately bypasses
        /// <c>CERTInextClient.TrackOrderV2Async</c>'s typed deserialization so the exact
        /// unparsed response body can be captured. Returns null if the order is not found
        /// in any of the three families.
        /// </summary>
        private async Task<RawV2Response> TrackOrderRawAsync(string orderId)
        {
            string accessToken = await GetV2AccessTokenAsync();

            using var apiClient = NewApiClient(_v2ApiUrl.TrimEnd('/'));
            foreach (string family in Families)
            {
                var req = new RestRequest($"/api/certinext/v2/{family}/{orderId}", Method.Get);
                req.AddHeader("Authorization", $"Bearer {accessToken}");
                req.AddHeader("Accept", "application/json");
                var resp = await apiClient.ExecuteAsync(req);

                if ((int)resp.StatusCode == 404)
                    continue;

                return new RawV2Response
                {
                    Family = family,
                    StatusCode = (int)resp.StatusCode,
                    Body = resp.Content
                };
            }
            return null;
        }

        /// <summary>
        /// Raw HTTP GET against the V2 "Get DCV Challenges" endpoint
        /// (GET /api/certinext/v2/ssl-certificates/{orderId}/dcv?domain={domain}) for a
        /// single domain, within the already-resolved product family. Deliberately
        /// bypasses <c>CERTInextClient.GetDcvV2Async</c> (which never sends a "domain"
        /// query parameter today — issue 0042) so this probe can send it explicitly and
        /// observe the CA's raw response verbatim, whatever it turns out to be. Does not
        /// throw on a non-success status — the raw status/body is exactly what this probe
        /// needs either way.
        /// </summary>
        private async Task<RawV2Response> GetDcvChallengesRawAsync(string orderId, string domain, string family)
        {
            string accessToken = await GetV2AccessTokenAsync();

            using var apiClient = NewApiClient(_v2ApiUrl.TrimEnd('/'));
            var req = new RestRequest($"/api/certinext/v2/{family}/{orderId}/dcv", Method.Get);
            req.AddHeader("Authorization", $"Bearer {accessToken}");
            req.AddHeader("Accept", "application/json");
            req.AddQueryParameter("domain", domain);
            var resp = await apiClient.ExecuteAsync(req);

            string body = resp.Content;
            if (string.IsNullOrEmpty(body) && !resp.IsSuccessful)
            {
                body = resp.ErrorException != null
                    ? $"<no HTTP response — transport error: {resp.ErrorException.GetType().Name}: {resp.ErrorException.Message}>"
                    : $"<no HTTP response — {resp.ErrorMessage ?? resp.ResponseStatus.ToString()}>";
            }

            return new RawV2Response
            {
                Family = family,
                StatusCode = (int)resp.StatusCode,
                Body = body
            };
        }

        /// <summary>
        /// Best-effort scan of a raw Track Order JSON body for a domain list to probe
        /// against Get DCV Challenges, used only when CERTINEXT_PROBE_UCC_DOMAINS is
        /// unset. Collects the single top-level "domain" field (the only SAN-related field
        /// <see cref="V2OrderStatusResponse"/> currently models) plus, if present, any of
        /// <see cref="CandidateSanArrayFields"/> as a string array. None of the array field
        /// names are confirmed live for issue 0042 — this is purely a diagnostic
        /// convenience; the caller always logs the full raw body regardless of this
        /// method's result.
        /// </summary>
        private static List<string> DeriveDomainsFromTrackOrderBody(string body, out string derivationNote)
        {
            var domains = new List<string>();
            var notes = new List<string>();

            if (string.IsNullOrWhiteSpace(body))
            {
                derivationNote = "Track Order body was empty — nothing to derive from.";
                return domains;
            }

            try
            {
                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;

                if (root.TryGetProperty("domain", out var domainEl) && domainEl.ValueKind == JsonValueKind.String)
                {
                    string primary = domainEl.GetString();
                    if (!string.IsNullOrWhiteSpace(primary))
                    {
                        domains.Add(primary);
                        notes.Add($"Found top-level \"domain\"=\"{primary}\".");
                    }
                }
                else
                {
                    notes.Add("No top-level \"domain\" string field found.");
                }

                foreach (string field in CandidateSanArrayFields)
                {
                    if (root.TryGetProperty(field, out var arrEl) && arrEl.ValueKind == JsonValueKind.Array)
                    {
                        var found = arrEl.EnumerateArray()
                            .Where(e => e.ValueKind == JsonValueKind.String)
                            .Select(e => e.GetString())
                            .Where(s => !string.IsNullOrWhiteSpace(s))
                            .ToList();

                        if (found.Count > 0)
                        {
                            notes.Add($"Found array field \"{field}\" with {found.Count} entrie(s): {string.Join(", ", found)}.");
                            domains.AddRange(found);
                        }
                        else
                        {
                            notes.Add($"Array field \"{field}\" is present but empty.");
                        }
                    }
                }

                if (notes.Count == 1 && domains.Count <= 1)
                {
                    notes.Add(
                        "None of the candidate SAN-array field names " +
                        $"({string.Join(", ", CandidateSanArrayFields)}) were found on the Track Order body — " +
                        "matches issue 0042's finding that V2OrderStatusResponse has no confirmed field for a " +
                        "UCC order's additional domains yet.");
                }
            }
            catch (JsonException ex)
            {
                notes.Add($"Track Order body was not valid JSON: {ex.Message}");
            }

            derivationNote = string.Join(" ", notes);
            return domains.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }
    }
}
