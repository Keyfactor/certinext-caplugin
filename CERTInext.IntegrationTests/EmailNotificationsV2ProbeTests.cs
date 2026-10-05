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
//
// --- Phase 2 (added 2026-09-28): real-inbox test, for the same open question this file's
// original probe above could not resolve ---
//
// The API-only probe above could not distinguish "CERTInext honors emailNotifications='0'"
// from "CERTInext silently coerces it back to 'all'" — the field is never echoed back in any
// response, create or Track Order. The user's chosen resolution (issues/
// V2_AUDIT_TRIAGE_HANDOFF.md, "EmailNotifications' open decision") is the strongest test
// available short of asking CERTInext directly: place two real V2 DV SSL orders, two minutes
// apart, one with emailNotifications="all" (baseline) and one with emailNotifications="0"
// (test), and have a human compare what actually arrives in the requestor's real inbox for
// each. Product: DV SSL, non-UCC, catalog code 842 — verified against the live catalog's
// productTypeID ("13" = DV SSL, non-UCC; see ProductDetail.ProductTypeId's own doc comment)
// before either order is placed, matched on productTypeID only, never productName (catalog
// productName strings are unstable across account/catalog-version — see this repo's Gotchas
// in issues/V2_AUDIT_TRIAGE_HANDOFF.md). No CSR is submitted and DCV is never invoked for
// either order.
//
// Both orders deliberately omit requestor.designation — the JSON key itself is absent, not
// null/empty, via the same global `DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull`
// serializer setting this file already relies on for other optional fields — which is also an
// (unplanned, incidental) live-answer opportunity for issue 0027 item 5e's still-open
// "requestor.designation hardcoded, no config field" design question: if either create call
// is rejected with a 4xx that mentions "designation", that rejection is logged verbatim as a
// live answer to 5e. The probe is not designed around that outcome, but it is free
// information if it happens. technicalPointOfContact is omitted entirely, matching this
// file's existing EmailNotifications_V2_NonAllValue_ObservesCaResponse probe above (which also
// never sets it). No delegation/recipientEmails field is set either (the DTO has none).
//
// Split into two [SkippableFact] tests, both gated behind a NEW flag,
// CERTINEXT_PROBE_EMAIL_NOTIFICATIONS_INBOX=1 — deliberately distinct from
// CERTINEXT_PROBE_EMAIL_NOTIFICATIONS above, since this test places two real orders and
// requires a human to manually check a real inbox afterward, a materially bigger commitment
// than the existing single-order, API-only probe. Not armed by default in ~/.env_certinext or
// ~/.env_certinext_v2.
//
//   Phase 1 — EmailNotifications_V2_RealInboxTest_PlaceOrders: verifies the catalog product
//   code resolves to productTypeID "13" (aborts before placing anything if it does not),
//   places the baseline ("all") order, waits 2 minutes, places the test ("0") order. Exactly
//   one create call per run — no retry path of any kind. A timeout or any non-2xx response on
//   either call logs the domain/timestamp/error, prints "STOP — check the orders report for
//   this domain before re-running" (per this file's own timeout gotcha above — a client-side
//   timeout does not mean the CA never processed the request), and skips placing the second
//   order. Never cancels either order in this phase — they are meant to sit open long enough
//   for notification emails to actually arrive. Ends with an ACTION REQUIRED block naming both
//   order IDs/domains and instructing the operator to check the inbox (including spam) at the
//   5- and 30-minute marks, recording subject/sender/time for every email that arrives, for
//   each run.
//
//   Phase 2 — EmailNotifications_V2_RealInboxTest_CancelOrders: run only after the human has
//   finished checking the inbox. Gated behind the same flag plus
//   CERTINEXT_INBOX_TEST_BASELINE_ORDER_ID / CERTINEXT_INBOX_TEST_ORDER_ID (the two order IDs
//   phase 1 printed in its ACTION REQUIRED block). Skips entirely if neither is set; if only
//   one is set (phase 1 stopped early after placing the baseline order but before the test
//   order), cancels only that one rather than requiring both. Cancels via this file's existing
//   CancelOrderRawAsync, then confirms cancellation via a follow-up read-only Track Order call
//   (orderState == "Order Cancelled").
//
// Like the probe above, this makes NO live API calls of any kind unless
// CERTINEXT_PROBE_EMAIL_NOTIFICATIONS_INBOX=1 is explicitly set.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
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
        private readonly string _dcvDomainBase;
        private readonly string _inboxTestEmail;
        private readonly bool _v2Enabled;

        /// <summary>
        /// Catalog product code for the phase 1/2 real-inbox probe — V2 DV SSL, non-UCC.
        /// Deliberately a fixed constant (not read from CERTINEXT_PRODUCT_CODE/
        /// CERTINEXT_OV_PRODUCT_CODE) per the approved design: this probe's product choice is
        /// locked in independently of whatever other env-configured product code a given shell
        /// session happens to have set for unrelated tests. Verified against the live catalog's
        /// productTypeID ("13") at the start of phase 1 before any order is placed — see
        /// <see cref="EmailNotifications_V2_RealInboxTest_PlaceOrders"/>.
        /// </summary>
        private const string InboxProbeProductCode = "842";

        public EmailNotificationsV2ProbeTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;

            var env = V2EnvHelper.LoadAndPromote();

            _v2ApiUrl = V2EnvHelper.GetEnv(env, "CERTINEXT_API_URL");
            _v2ClientId = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_ID");
            _v2ClientSecret = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_SECRET");
            _v2OvProductCode = V2EnvHelper.GetEnv(env, "CERTINEXT_OV_PRODUCT_CODE", "846");
            _dcvDomainBase = V2EnvHelper.GetEnv(env, "CERTINEXT_DCV_DOMAIN", "example.com");
            _inboxTestEmail = Environment.GetEnvironmentVariable("CERTINEXT_INBOX_TEST_EMAIL")?.Trim();

            _v2Enabled = !string.IsNullOrWhiteSpace(V2EnvHelper.GetEnv(env, "CERTINEXT_USE_V2_API"))
                         && !string.IsNullOrWhiteSpace(_v2ApiUrl)
                         && !string.IsNullOrWhiteSpace(_v2ClientId)
                         && !string.IsNullOrWhiteSpace(_v2ClientSecret);
        }

        /// <summary>
        /// Builds a typed <see cref="CERTInextClient"/> against the V2 API — needed only for
        /// <see cref="CERTInextClient.GetProductDetailsV2Async"/>'s catalog lookup (phase 1's
        /// productTypeID guard), which has no raw-HTTP equivalent already in this file. Mirrors
        /// <c>OrganizationBlockV2ProbeTests.BuildV2Client</c> exactly.
        /// </summary>
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
        // Phase 1/2 real-inbox probe (issue 0027 item 1b) — see this file's header comment
        // for the full design. Both phases share InboxProbeProductCode/_dcvDomainBase and the
        // CERTINEXT_PROBE_EMAIL_NOTIFICATIONS_INBOX gate.
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Phase 1 of the EmailNotifications real-inbox probe (issue 0027 item 1b). Verifies
        /// the catalog resolves <see cref="InboxProbeProductCode"/> to productTypeID "13" (DV
        /// SSL, non-UCC) — matched on productTypeID only, never productName — and aborts
        /// before placing any order if it does not. Places the baseline
        /// (<c>emailNotifications="all"</c>) order, waits 2 minutes, then places the test
        /// (<c>emailNotifications="0"</c>) order. Exactly one create call per run; no retry
        /// path of any kind. A timeout or any non-2xx response on either call stops the run
        /// (and, for the baseline call, skips the test order entirely) — see
        /// <see cref="RunInboxProbeOrderAsync"/>. Neither order is cancelled by this phase; run
        /// <see cref="EmailNotifications_V2_RealInboxTest_CancelOrders"/> after the human
        /// inbox-check window has elapsed.
        ///
        /// Opt-in: requires CERTINEXT_PROBE_EMAIL_NOTIFICATIONS_INBOX=1. Not armed by default
        /// in ~/.env_certinext or ~/.env_certinext_v2 — this places two real, potentially
        /// cost-bearing V2 DV SSL orders and requires a human to manually check a real inbox
        /// afterward, which cannot be automated or concluded by an agent.
        /// </summary>
        [SkippableFact]
        public async Task EmailNotifications_V2_RealInboxTest_PlaceOrders()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            string probeFlag = Environment.GetEnvironmentVariable("CERTINEXT_PROBE_EMAIL_NOTIFICATIONS_INBOX");
            Skip.If(string.IsNullOrWhiteSpace(probeFlag) || probeFlag != "1",
                "CERTINEXT_PROBE_EMAIL_NOTIFICATIONS_INBOX=1 not set — this probe places TWO real, " +
                "potentially cost-bearing V2 DV SSL orders and requires a human to manually check a " +
                "real inbox afterward. Opt-in only. Skipping.");

            // The inbox must be one a human actually reads — the env files' CERTINEXT_REQUESTOR_EMAIL
            // is a non-deliverable placeholder, so this probe never falls back to it.
            Skip.If(string.IsNullOrWhiteSpace(_inboxTestEmail),
                "CERTINEXT_INBOX_TEST_EMAIL not set — set it to the real mailbox that will be checked. Skipping.");

            _output.WriteLine("=== Issue 0027 item 1b real-inbox probe — phase 1: place baseline + test orders ===");
            _output.WriteLine($"Requestor email (inbox to check): {_inboxTestEmail}");

            // Catalog guard — abort before placing anything if the pinned product code does
            // not resolve to productTypeID "13" (DV SSL, non-UCC) on this account/catalog
            // version. Matched on productTypeID only, never productName (catalog productName
            // strings are unstable across account/catalog-version/spellings — see this
            // repo's Gotchas in issues/V2_AUDIT_TRIAGE_HANDOFF.md).
            using CERTInextClient catalogClient = BuildV2Client();
            List<ProductDetail> catalog = await catalogClient.GetProductDetailsV2Async();
            ProductDetail product = catalog.FirstOrDefault(p => p.ProductCode == InboxProbeProductCode);

            Skip.If(product == null,
                $"Catalog product code {InboxProbeProductCode} was not found in the live V2 catalog " +
                "for this account — aborting before placing any order.");
            Skip.If(product.ProductTypeId != "13",
                $"Catalog product code {InboxProbeProductCode} has productTypeID=\"{product.ProductTypeId}\" " +
                "(expected \"13\" for DV SSL, non-UCC) — aborting before placing any order.");

            _output.WriteLine($"Catalog check OK: ProductCode={product.ProductCode} " +
                               $"ProductTypeId={product.ProductTypeId} ProductName={product.ProductName}");

            DateTime baselineTs = DateTime.UtcNow;
            string baselineDomain = $"emailnotif-baseline-{baselineTs:yyyyMMddHHmmss}.{_dcvDomainBase}";

            InboxProbeRunResult baselineResult =
                await RunInboxProbeOrderAsync("BASELINE", baselineDomain, "all");

            if (!baselineResult.Success)
            {
                // RunInboxProbeOrderAsync already logged the domain/timestamp/error and the
                // STOP message (and the designation-answer block, if applicable). Per the
                // approved design, a failed baseline call means the test order must not be
                // placed at all.
                return;
            }

            _output.WriteLine("");
            _output.WriteLine("Waiting 2 minutes before placing the test (\"0\") order...");
            await Task.Delay(TimeSpan.FromMinutes(2));

            DateTime testTs = DateTime.UtcNow;
            string testDomain = $"emailnotif-test0-{testTs:yyyyMMddHHmmss}.{_dcvDomainBase}";

            InboxProbeRunResult testResult = await RunInboxProbeOrderAsync("TEST", testDomain, "0");

            _output.WriteLine("");
            _output.WriteLine("=== ACTION REQUIRED ===");
            _output.WriteLine($"Baseline (\"all\") order: OrderId={baselineResult.OrderId ?? "<none parsed>"} " +
                               $"Domain={baselineDomain}");
            _output.WriteLine(testResult.Success
                ? $"Test (\"0\") order: OrderId={testResult.OrderId ?? "<none parsed>"} Domain={testDomain}"
                : $"Test (\"0\") order: FAILED — see STOP message above. Domain={testDomain}");
            _output.WriteLine("");
            _output.WriteLine(
                "Check the requestor's real inbox (INCLUDING SPAM) at the 5-minute and 30-minute marks " +
                "after each order above was placed. For EVERY email that arrives for either domain, " +
                "record its subject, sender, and time received, and which run (baseline/test) it " +
                "corresponds to. This step cannot be automated or concluded by an agent — a human must " +
                "check the inbox and report back before issue 0027 item 1b can be closed.");
            _output.WriteLine("");
            _output.WriteLine(
                "When the inbox-check window is done, set CERTINEXT_INBOX_TEST_BASELINE_ORDER_ID / " +
                "CERTINEXT_INBOX_TEST_ORDER_ID to the order ID(s) above (whichever were placed) and run " +
                $"{nameof(EmailNotifications_V2_RealInboxTest_CancelOrders)} to clean up.");
        }

        /// <summary>
        /// Phase 2 of the EmailNotifications real-inbox probe (issue 0027 item 1b) — run only
        /// after the human inbox-check window from phase 1 has elapsed. Cancels whichever
        /// order ID(s) are supplied via CERTINEXT_INBOX_TEST_BASELINE_ORDER_ID /
        /// CERTINEXT_INBOX_TEST_ORDER_ID, then confirms cancellation via a follow-up read-only
        /// Track Order call (<c>orderState == "Order Cancelled"</c>).
        ///
        /// Opt-in: requires CERTINEXT_PROBE_EMAIL_NOTIFICATIONS_INBOX=1 (same flag as phase 1)
        /// plus at least one of the two order-ID env vars. Skips entirely if neither is set.
        /// If only one is set — e.g. phase 1 stopped early after the baseline order but before
        /// the test order — this cancels only that one rather than requiring both, so a
        /// partial phase 1 run is never stuck without a cleanup path.
        /// </summary>
        [SkippableFact]
        public async Task EmailNotifications_V2_RealInboxTest_CancelOrders()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            string probeFlag = Environment.GetEnvironmentVariable("CERTINEXT_PROBE_EMAIL_NOTIFICATIONS_INBOX");
            Skip.If(string.IsNullOrWhiteSpace(probeFlag) || probeFlag != "1",
                "CERTINEXT_PROBE_EMAIL_NOTIFICATIONS_INBOX=1 not set — skipping.");

            string baselineOrderId = Environment.GetEnvironmentVariable("CERTINEXT_INBOX_TEST_BASELINE_ORDER_ID");
            string testOrderId = Environment.GetEnvironmentVariable("CERTINEXT_INBOX_TEST_ORDER_ID");

            Skip.If(string.IsNullOrWhiteSpace(baselineOrderId) && string.IsNullOrWhiteSpace(testOrderId),
                "Neither CERTINEXT_INBOX_TEST_BASELINE_ORDER_ID nor CERTINEXT_INBOX_TEST_ORDER_ID is " +
                "set — nothing to cancel. Skipping.");

            _output.WriteLine("=== Issue 0027 item 1b real-inbox probe — phase 2: cancel + confirm ===");

            if (!string.IsNullOrWhiteSpace(baselineOrderId))
            {
                await CancelAndConfirmInboxProbeOrderAsync(baselineOrderId, "baseline (\"all\")");
            }
            else
            {
                _output.WriteLine(
                    "CERTINEXT_INBOX_TEST_BASELINE_ORDER_ID not set — skipping baseline-order cancel " +
                    "(phase 1 apparently never placed it, or it is being handled separately).");
            }

            if (!string.IsNullOrWhiteSpace(testOrderId))
            {
                await CancelAndConfirmInboxProbeOrderAsync(testOrderId, "test (\"0\")");
            }
            else
            {
                _output.WriteLine(
                    "CERTINEXT_INBOX_TEST_ORDER_ID not set — skipping test-order cancel " +
                    "(phase 1 apparently stopped before placing it, or it is being handled separately).");
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

        /// <summary>
        /// Best-effort extraction of a named top-level string field (e.g. <c>orderState</c>,
        /// <c>certificateState</c>) from a raw Track Order JSON response body. Returns null
        /// rather than throwing if the body is empty, malformed, or lacks the field.
        /// </summary>
        private static string TryExtractStringField(string body, string fieldName)
        {
            if (string.IsNullOrWhiteSpace(body))
                return null;

            try
            {
                using var doc = JsonDocument.Parse(body);
                return doc.RootElement.TryGetProperty(fieldName, out var el) ? el.GetString() : null;
            }
            catch (JsonException)
            {
                return null;
            }
        }

        // ---------------------------------------------------------------------------
        // Phase 1/2 real-inbox probe helpers (issue 0027 item 1b).
        // ---------------------------------------------------------------------------

        /// <summary>Outcome of a single create-order run inside <see cref="RunInboxProbeOrderAsync"/>.</summary>
        private sealed class InboxProbeRunResult
        {
            public bool Success { get; set; }
            public string OrderId { get; set; }
            public bool MentionsDesignation { get; set; }
        }

        /// <summary>
        /// Builds the request body for one baseline/test run — DV SSL, non-UCC, no CSR, no
        /// DCV. Only <c>requestor.email</c>/<c>requestor.name</c> are populated (from the
        /// fixture's requestor config); <c>requestor.phone</c> and, deliberately,
        /// <c>requestor.designation</c> are left unset so the global
        /// <c>DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull</c> serializer
        /// option (<see cref="GetJsonOptions"/>) omits the JSON key entirely rather than
        /// sending <c>null</c> or an empty string — issue 0027 item 5e's open design question.
        /// <c>technicalPointOfContact</c> is left unset for the same reason, matching this
        /// file's existing <see cref="EmailNotifications_V2_NonAllValue_ObservesCaResponse"/>
        /// probe (which also never sets it). No <c>organization</c> block (DV never requires
        /// one) and no delegation/recipientEmails field (the DTO has none).
        /// </summary>
        private V2CreateSslOrderRequest BuildInboxProbeOrderRequest(
            string domain, string emailNotificationsValue, string runLabel) =>
            new V2CreateSslOrderRequest
            {
                ProductVariant = "dv",
                EmailNotifications = emailNotificationsValue,
                Requestor = new V2Requestor
                {
                    Name = _fixture.IsConfigured ? _fixture.Config.RequestorName : "Keyfactor Test",
                    Email = _inboxTestEmail
                    // Phone and Designation deliberately left unset (null) — omitted from the
                    // wire body entirely, not sent as null/empty.
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
                // TechnicalPointOfContact deliberately left unset (null) — see doc comment above.
                Remarks = $"Issue 0027 item 1b real-inbox probe — {runLabel} run, " +
                          $"emailNotifications=\"{emailNotificationsValue}\", requestor.designation " +
                          "omitted (issue 0027 item 5e). No CSR submitted, DCV never invoked."
            };

        /// <summary>
        /// Runs one baseline/test create-order call for the phase 1 real-inbox probe: builds
        /// and logs the request body (no token in it to redact), places EXACTLY one
        /// create-order call (no retry of any kind), logs the HTTP status/full response
        /// body/order ID, and — on success — a follow-up read-only Track Order status. On a
        /// timeout or any non-2xx response, logs the domain/timestamp/error and prints "STOP —
        /// check the orders report for this domain before re-running" (a client-side timeout
        /// on this endpoint does not mean the CA never processed the request — see this file's
        /// header comment). If the failing response body mentions "designation", that is
        /// additionally logged verbatim as a live answer to issue 0027 item 5e.
        /// </summary>
        private async Task<InboxProbeRunResult> RunInboxProbeOrderAsync(
            string runLabel, string domain, string emailNotificationsValue)
        {
            var orderReq = BuildInboxProbeOrderRequest(domain, emailNotificationsValue, runLabel);
            string requestJson = JsonSerializer.Serialize(orderReq, GetJsonOptions());

            _output.WriteLine("");
            _output.WriteLine($"--- {runLabel} run: emailNotifications=\"{emailNotificationsValue}\", domain={domain} ---");
            _output.WriteLine($"Request body: {requestJson}");

            var createResp = await PlaceOrderRawAsync(InboxProbeProductCode, requestJson);
            _output.WriteLine($"Create-order response ({runLabel}): HTTP {createResp.StatusCode}");
            _output.WriteLine($"Body: {createResp.Body}");

            var result = new InboxProbeRunResult();

            if (!createResp.IsSuccessful)
            {
                result.Success = false;
                result.MentionsDesignation =
                    createResp.Body?.IndexOf("designation", StringComparison.OrdinalIgnoreCase) >= 0;

                _output.WriteLine("");
                _output.WriteLine($"=== {runLabel} run FAILED at {DateTime.UtcNow:O} — Domain={domain} " +
                                   $"HTTP {createResp.StatusCode}: {createResp.Body} ===");
                _output.WriteLine("STOP — check the orders report for this domain before re-running.");

                if (result.MentionsDesignation)
                {
                    _output.WriteLine("");
                    _output.WriteLine(
                        "=== DESIGNATION ANSWER (issue 0027 item 5e) — the create call was rejected and " +
                        $"the error mentions \"designation\"; verbatim response: {createResp.Body} ===");
                }

                return result;
            }

            result.Success = true;
            result.OrderId = TryExtractOrderId(createResp.Body);
            _output.WriteLine($"OrderId={result.OrderId ?? "<none parsed>"}");

            if (!string.IsNullOrWhiteSpace(result.OrderId))
            {
                try
                {
                    var trackResp = await TrackOrderRawAsync(result.OrderId);
                    string orderState = TryExtractStringField(trackResp.Body, "orderState");
                    string certState = TryExtractStringField(trackResp.Body, "certificateState");
                    _output.WriteLine(
                        $"Track Order ({runLabel}): HTTP {trackResp.StatusCode}, " +
                        $"orderState={orderState ?? "<none>"}, certificateState={certState ?? "<none>"}");
                }
                catch (Exception trackEx)
                {
                    _output.WriteLine($"Track Order call failed for {runLabel} (non-fatal to this probe): {trackEx.Message}");
                }
            }

            return result;
        }

        /// <summary>
        /// Cancels one order from the real-inbox probe (phase 2) via the existing
        /// <see cref="CancelOrderRawAsync"/> idiom, then confirms cancellation via a
        /// follow-up read-only Track Order call, logging whether <c>orderState</c> came back
        /// as <c>"Order Cancelled"</c>.
        /// </summary>
        private async Task CancelAndConfirmInboxProbeOrderAsync(string orderId, string label)
        {
            _output.WriteLine("");
            _output.WriteLine($"--- Cancelling {label} order {orderId} ---");

            var cancelResp = await CancelOrderRawAsync(orderId,
                "Issue 0027 item 1b real-inbox probe — cleanup after the inbox-check window.");
            _output.WriteLine($"Cancel response: HTTP {cancelResp.StatusCode}: {cancelResp.Body}");

            var trackResp = await TrackOrderRawAsync(orderId);
            _output.WriteLine($"Track Order (post-cancel) response: HTTP {trackResp.StatusCode}: {trackResp.Body}");

            string orderState = TryExtractStringField(trackResp.Body, "orderState");
            bool confirmed = string.Equals(orderState, "Order Cancelled", StringComparison.OrdinalIgnoreCase);

            _output.WriteLine(confirmed
                ? $"CONFIRMED: order {orderId} ({label}) orderState=\"Order Cancelled\"."
                : $"NOT CONFIRMED: order {orderId} ({label}) orderState=\"{orderState ?? "<none parsed>"}\" " +
                  "(expected \"Order Cancelled\"). Check manually in the CERTInext portal.");
        }
    }
}
