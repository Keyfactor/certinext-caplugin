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
// Triage probe for issue 0028 (V2 OrganizationNumber not sent). Three tests:
//
//   1. Catalog_V2_ListsOrganizationVettedEntitlements — read-only, always safe to run
//      whenever V2 creds are configured. Lists the live catalog/products response and
//      flags anything that looks like an OV/EV entitlement, so we know BEFORE attempting
//      any order-placement probe whether one is even possible on this sandbox account.
//
//   2. PlaceOvOrder_WithoutOrganizationBlock_ObservesCaResponse — places one real V2 OV
//      order with no `organization` block (the pre-fix code path) and reports whether
//      CERTInext rejects it (400/422) or silently accepts it. This is opt-in behind
//      CERTINEXT_PROBE_ORG_MISSING=1 AND an explicit CERTINEXT_OV_PRODUCT_CODE — neither
//      is set by default in ~/.env_certinext or ~/.env_certinext_v2, so this test skips
//      unless an operator deliberately configures both after confirming an OV/EV product
//      is entitled and understanding a real order (and its cost) may result.
//
//   3. PlaceOvOrder_WithOrganizationBlock_ExpectsAcceptance — places one real V2 OV order
//      WITH the fix's `organization` block populated (organizationNumber + preVetted=true)
//      and asserts CERTInext accepts it (no 422), then best-effort cancels it. This is the
//      live acceptance check for the fix itself. Opt-in behind CERTINEXT_PROBE_ORG_FIX=1,
//      CERTINEXT_OV_PRODUCT_CODE, and a configured CERTINEXT_ORG_NUMBER (~/.env_certinext) —
//      none set by default. NOT executed by the agent that authored this fix; a human must
//      deliberately opt in and run it, since it places a real, potentially cost-bearing
//      order (same standard already applied to test #2 and to issues/f3-v2-multi-san-
//      limitation.md's UCC probe).

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using RestSharp;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    public class OrganizationBlockV2ProbeTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;
        private readonly string _v2ApiUrl;
        private readonly string _v2ClientId;
        private readonly string _v2ClientSecret;
        private readonly bool _v2Enabled;

        public OrganizationBlockV2ProbeTests(IntegrationTestFixture fixture, ITestOutputHelper output)
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
        /// Read-only. Lists the live V2 catalog and reports every product whose name or
        /// productType text suggests OV/EV entitlement. No order is placed. Safe to run
        /// any time V2 creds are configured.
        /// </summary>
        [SkippableFact]
        public async Task Catalog_V2_ListsOrganizationVettedEntitlements()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            using var client = BuildV2Client();
            List<ProductDetail> products = await client.GetProductDetailsV2Async();

            products.Should().NotBeNull();

            _output.WriteLine($"=== V2 catalog: {products.Count} product(s) ===");
            foreach (var p in products)
            {
                _output.WriteLine(
                    $"ProductCode={p.ProductCode,-8} ProductTypeId={p.ProductTypeId,-6} " +
                    $"ProductType={p.ProductType,-30} ProductName={p.ProductName} Active={p.Active}");
            }

            var ovEvCandidates = products
                .Where(p =>
                    (p.ProductName ?? "").IndexOf("OV", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    (p.ProductName ?? "").IndexOf("EV", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    (p.ProductName ?? "").IndexOf("Organization", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    (p.ProductName ?? "").IndexOf("Extended Validation", StringComparison.OrdinalIgnoreCase) >= 0)
                .ToList();

            _output.WriteLine("");
            _output.WriteLine(ovEvCandidates.Count > 0
                ? $"=== {ovEvCandidates.Count} OV/EV-looking product(s) found — a live order-placement probe (issue 0028) is feasible: ==="
                : "=== No OV/EV-looking product found in this account's catalog — issue 0028's order-placement probe is NOT feasible on this sandbox account. ===");
            foreach (var p in ovEvCandidates)
                _output.WriteLine($"  ProductCode={p.ProductCode} ProductName={p.ProductName}");
        }

        /// <summary>
        /// Places ONE real V2 OV order with no <c>organization</c> block — i.e. exercises the
        /// exact code path issue 0028 flags as broken/degraded — and reports whether CERTInext
        /// rejects it (400/422, with body) or silently accepts it. Best-effort cancel afterward
        /// via a raw DELETE/cancel call (the plugin has no V2 CancelOrderAsync client method to
        /// reuse) so the order does not linger if the CA does accept it.
        ///
        /// Opt-in: requires BOTH CERTINEXT_PROBE_ORG_MISSING=1 and CERTINEXT_OV_PRODUCT_CODE to
        /// be set. Neither exists in ~/.env_certinext or ~/.env_certinext_v2 by default — an
        /// operator must deliberately add both after confirming (via
        /// Catalog_V2_ListsOrganizationVettedEntitlements above) that an OV/EV product is
        /// actually entitled on the target account.
        /// </summary>
        [SkippableFact]
        public async Task PlaceOvOrder_WithoutOrganizationBlock_ObservesCaResponse()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            string probeFlag = Environment.GetEnvironmentVariable("CERTINEXT_PROBE_ORG_MISSING");
            string ovProductCode = Environment.GetEnvironmentVariable("CERTINEXT_OV_PRODUCT_CODE");

            Skip.If(string.IsNullOrWhiteSpace(probeFlag) || probeFlag != "1",
                "CERTINEXT_PROBE_ORG_MISSING=1 not set — this probe places a real, potentially " +
                "cost-bearing OV order and is opt-in only. Skipping.");
            Skip.If(string.IsNullOrWhiteSpace(ovProductCode),
                "CERTINEXT_OV_PRODUCT_CODE not set — no confirmed-entitled OV/EV product code " +
                "was supplied. Run Catalog_V2_ListsOrganizationVettedEntitlements first. Skipping.");

            using var client = BuildV2Client();

            string domain = $"probe-0028-{DateTime.UtcNow:yyyyMMddHHmmss}.example.com";
            var orderReq = new V2CreateSslOrderRequest
            {
                ProductVariant = "ov",
                EmailNotifications = "all",
                Requestor = new V2Requestor
                {
                    Name = _fixture.IsConfigured ? _fixture.Config.RequestorName : "Keyfactor Test",
                    Email = _fixture.IsConfigured ? _fixture.Config.RequestorEmail : "test@example.com",
                    Phone = "0000000000",
                    Designation = "IT Administrator"
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
                Remarks = "Issue 0028 triage probe — no organization block sent on purpose."
            };
            // Deliberately NOT setting any organization/organizationNumber/preVetted field —
            // this is the exact gap issue 0028 describes.

            string outcome;
            string orderId = null;
            try
            {
                var resp = await client.PlaceOrderV2Async(Constants.ApiV2.FamilySsl, ovProductCode, orderReq);
                orderId = resp.OrderId;
                outcome = $"ACCEPTED — OrderId={resp.OrderId}, Status={resp.Status}. " +
                          "CERTInext did NOT reject the OV order for missing organization data.";
            }
            catch (Exception ex)
            {
                outcome = $"REJECTED — {ex.GetType().Name}: {ex.Message}";
            }

            _output.WriteLine("=== Issue 0028 live probe: OV order with no organization block ===");
            _output.WriteLine($"Domain={domain} ProductCode={ovProductCode}");
            _output.WriteLine(outcome);

            if (orderId != null)
            {
                _output.WriteLine($"Attempting best-effort cleanup: cancelling order {orderId}...");
                try
                {
                    await CancelSslOrderRawAsync(orderId,
                        "Issue 0028 triage probe — cleaning up after observing CA response.");
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

        /// <summary>
        /// Places ONE real V2 OV order WITH the fix's <c>organization</c> block populated
        /// (<c>organizationNumber</c> from <c>CERTINEXT_ORG_NUMBER</c>, <c>preVetted=true</c>)
        /// and asserts CERTInext accepts it — i.e. does NOT return the HTTP 422 EMS-1180
        /// "Organization Name cannot be empty" that test #2 above observes for the pre-fix,
        /// no-organization-block request. Best-effort cancels the order afterward via the same
        /// raw cancel helper.
        ///
        /// Opt-in: requires CERTINEXT_PROBE_ORG_FIX=1, CERTINEXT_OV_PRODUCT_CODE, AND a
        /// configured CERTINEXT_ORG_NUMBER (already present in most `~/.env_certinext` files
        /// per this repo's other live tests, e.g. DcvLifecycleTests). None of these are armed
        /// by default. This test was authored as part of the issue 0028 fix but deliberately
        /// NOT executed by the authoring agent — placing a real order has cost/state
        /// implications an operator should explicitly authorize, the same standard already
        /// applied to <see cref="PlaceOvOrder_WithoutOrganizationBlock_ObservesCaResponse"/>.
        /// </summary>
        [SkippableFact]
        public async Task PlaceOvOrder_WithOrganizationBlock_ExpectsAcceptance()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            string probeFlag = Environment.GetEnvironmentVariable("CERTINEXT_PROBE_ORG_FIX");
            string ovProductCode = Environment.GetEnvironmentVariable("CERTINEXT_OV_PRODUCT_CODE");
            string organizationNumber = _fixture.IsConfigured ? _fixture.OrgNumber : null;

            Skip.If(string.IsNullOrWhiteSpace(probeFlag) || probeFlag != "1",
                "CERTINEXT_PROBE_ORG_FIX=1 not set — this probe places a real, potentially " +
                "cost-bearing OV order and is opt-in only. Skipping.");
            Skip.If(string.IsNullOrWhiteSpace(ovProductCode),
                "CERTINEXT_OV_PRODUCT_CODE not set — no confirmed-entitled OV/EV product code " +
                "was supplied. Run Catalog_V2_ListsOrganizationVettedEntitlements first. Skipping.");
            Skip.If(string.IsNullOrWhiteSpace(organizationNumber),
                "CERTINEXT_ORG_NUMBER not set in ~/.env_certinext — no pre-vetted organization " +
                "number is available to populate the organization block. Skipping.");

            using var client = BuildV2Client();

            string domain = $"probe-0028-fix-{DateTime.UtcNow:yyyyMMddHHmmss}.example.com";
            var orderReq = new V2CreateSslOrderRequest
            {
                ProductVariant = "ov",
                EmailNotifications = "all",
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
                Remarks = "Issue 0028 fix-verification probe — organization block populated."
            };

            string orderId = null;
            try
            {
                var resp = await client.PlaceOrderV2Async(Constants.ApiV2.FamilySsl, ovProductCode, orderReq);
                orderId = resp.OrderId;

                _output.WriteLine("=== Issue 0028 fix-verification probe: OV order WITH organization block ===");
                _output.WriteLine($"Domain={domain} ProductCode={ovProductCode} OrganizationNumber={organizationNumber}");
                _output.WriteLine($"ACCEPTED — OrderId={resp.OrderId}, Status={resp.Status}.");

                resp.OrderId.Should().NotBeNullOrWhiteSpace();
                resp.Status.Should().NotBe("rejected");
            }
            catch (Exception ex)
            {
                _output.WriteLine("=== Issue 0028 fix-verification probe: OV order WITH organization block ===");
                _output.WriteLine($"Domain={domain} ProductCode={ovProductCode} OrganizationNumber={organizationNumber}");
                _output.WriteLine($"REJECTED — {ex.GetType().Name}: {ex.Message}");
                throw;
            }
            finally
            {
                if (orderId != null)
                {
                    _output.WriteLine($"Attempting best-effort cleanup: cancelling order {orderId}...");
                    try
                    {
                        await CancelSslOrderRawAsync(orderId,
                            "Issue 0028 fix-verification probe — cleaning up after confirming acceptance.");
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

        /// <summary>
        /// Standalone cancel call for triage cleanup only — the plugin's
        /// <see cref="ICERTInextClient"/> has no V2 CancelOrderAsync method to reuse (issue
        /// 0028's probe is the only caller), so this authenticates and calls
        /// POST /api/certinext/v2/ssl-certificates/{orderId}/cancel directly per the spec
        /// (docs/reference/specs/CERTInext API v2.postman_collection (1).json,
        /// "SSL/TLS Certificates/Cancel Order"). Not a product code path.
        /// </summary>
        private async Task CancelSslOrderRawAsync(string orderId, string reason)
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

            using var tokenDoc = System.Text.Json.JsonDocument.Parse(tokenResp.Content);
            string accessToken = tokenDoc.RootElement.GetProperty("access_token").GetString();

            using var apiClient = new RestClient(_v2ApiUrl.TrimEnd('/'));
            var cancelReq = new RestRequest($"/api/certinext/v2/ssl-certificates/{orderId}/cancel", Method.Post);
            cancelReq.AddHeader("Authorization", $"Bearer {accessToken}");
            cancelReq.AddJsonBody(new { reason });
            var cancelResp = await apiClient.ExecuteAsync(cancelReq);
            if (!cancelResp.IsSuccessful)
                throw new Exception(
                    $"Cancel request failed: {(int)cancelResp.StatusCode} {cancelResp.Content}");
        }

    }
}
