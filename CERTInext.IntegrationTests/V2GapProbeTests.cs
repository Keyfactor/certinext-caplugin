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
// Sandbox gap probes P1-P5 (issue 0058 — issues/0058-v2-sandbox-gap-probes.md), settling open
// V2 wire behaviors that the pending designs 0060 (multi-domain auto-resolve), 0062 (inline
// CSR lifecycle) and 0063 (UCC CSR SAN shape) depend on. All five probes place a real V2 SSL
// order on the sandbox, record what CERTInext does with it (never asserting on the CA's own
// answer — that is the finding, not a test failure), then cancel it in a `finally` and confirm
// the cancellation with a fresh read-only GET.
//
//   PRE  — read-only. Tracks the existing UCC order 9295677273 (already placed in issue 0047)
//          and logs its status/domain, so the probes below have a live wire-shape baseline
//          before placing anything new.
//   P1   — productVariant:"ov" + one additionalDomains entry + an organization block, with NO
//          X-Product-Code header. Does auto-resolve pick an OV UCC product? Records whatever
//          the response echoes back as a resolved product code (best-effort scan — none of
//          this repo's V2 response DTOs model a productCode field on any order response).
//   P2   — the same body, with X-Product-Code pinned to the catalog's live, non-UCC OV SSL
//          product (productTypeID 16 — Constants.Products.ProductTypeIdsV2[OvSsl] = "16"),
//          resolved from the live catalog at run time (never hard-coded). Records reject
//          (HTTP + EMS code), re-route to UCC, or a silently-dropped additionalDomains.
//   P3a/P3b — a DV create with an inline "csr" field the plugin's own V2CreateSslOrderRequest
//          DTO does not model (issue 0062) — added by hand to the raw JSON body, as PEM (P3a)
//          and as headerless Base64 DER exactly like the spec's own create-order samples
//          (P3b). Records whether the order skips Constants.ApiV2.StatusPendingCsr, then
//          attempts the documented follow-up PUT .../csr and records accepted vs rejected.
//   P4   — a DV UCC order (productTypeID 15, live-resolved) with 2 additionalDomains, followed
//          by PUT .../csr with a CN-only CSR — the spec's own documented shape for a UCC CSR
//          (SANs come from the order, not the CSR). Order 9295677273 (issue 0047) already
//          confirmed a CSR carrying every SAN is accepted; this probe covers the other shape
//          the spec itself documents. Records accepted vs EMS-921/EMS-922.
//   P5   — productVariant:"dv" with X-Product-Code pinned to the live, non-UCC OV SSL product
//          (same productTypeID 16 resolution as P2), and no organization block — issue 0059's
//          variant/product mismatch. Records reject, DV, or a stalled OV-shaped order.
//
// Pattern: raw-body place-then-cancel, same idiom as OrganizationBlockV2ProbeTests /
// IdempotencyKeyV2ProbeTests / EmailNotificationsV2ProbeTests — deliberately bypasses
// CERTInextClient's typed request/response DTOs so the exact, unmodified wire body can be
// inspected (several of this file's own findings are about fields those DTOs do not model at
// all). The two pre-existing files' token-fetch and cancel helpers are shared via
// V2RawProbeHelpers (issue 0058's helper-extraction requirement) rather than copied a third
// time; every other raw-HTTP helper below (place/track/submit-CSR, and a non-throwing cancel
// that reports rather than throws) is local to this file, matching this project's existing
// convention of small per-probe-file helpers for the parts that are NOT shared duplicates.
//
// Gating (deliberately layered, same two-part mechanism as PrivatePkiV2LiveTests, plus a third
// layer issue 0058 added to close a latent hole in V2EnvHelper itself):
//   1. CERTINEXT_V2_GAP_PROBES=1 must be set in the real process environment. It is read here
//      BEFORE V2EnvHelper.LoadAndPromote() runs, so a value left in ~/.env_certinext_v2 can
//      never arm THIS constructor, even if V2EnvHelper went on to promote it.
//   2. It has also been added to IntegrationTestFixture's own _optInOnlyFlags (same guard as
//      83968ee added for CERTINEXT_PRIVATE_PKI_LIVE), so a value left in ~/.env_certinext can
//      never arm it either.
//   3. V2EnvHelper.PromotableKeys itself now excludes every _optInOnlyFlags name (issue 0058),
//      not just the V1-shared keys it already excluded — without this, a value left in
//      ~/.env_certinext_v2 would be read as unset by whichever test class is constructed
//      FIRST in a run (this constructor runs before LoadAndPromote), but LoadAndPromote would
//      then still write it into real process env, silently arming every LATER-constructed test
//      class in the same run even though nothing was ever exported in the shell. See
//      V1FixtureApiUrlGuardTests.PromotableKeys_ExcludesEveryOptInOnlyFlag.
// All three layers must agree for this flag to ever be considered "on".
//   2. CERTINEXT_INBOX_TEST_EMAIL must be set (no fallback to CERTINEXT_REQUESTOR_EMAIL, which
//      is a non-deliverable placeholder — issue 0058's own constraint). Used as both the
//      requestor email and the technicalPointOfContact email; name and phone come from the V1
//      fixture's CERTINEXT_REQUESTOR_NAME plus the fixture's own ISD/mobile defaults via
//      CERTInextCAPlugin.ComposeV2Phone (issue 0027 item 5b's phone-composition helper).
//   3. Live V2 OAuth2 credentials (CERTINEXT_API_URL/CLIENT_ID/CLIENT_SECRET, ~/.env_certinext_v2
//      via V2EnvHelper) must be present.
//
// emailNotifications: every probe sends "all" (full notification set) rather than omitting the
// field or sending "0" — the user's explicit choice for these probes (issue 0058's Constraints
// section: "emailNotifications: confirm... whether the user wants CERTInext's emails"; resolved
// 2026-09-29 in favor of "all"). "all" is also the only value the V2 spec's own create-order
// examples ever show (docs/reference/specs/CERTInext API v2.postman_collection (1).json — every
// SSL/private-pki/signature create sample sends exactly "all"; see also
// EmailNotificationsV2ProbeTests's header comment, which independently confirms the same reading
// of the spec text for issue 0027 item 1b).
//
// Domains: unique subdomains of CERTINEXT_DCV_DOMAIN (via V2EnvHelper, default "example.com"),
// e.g. gap-p1-<UTC yyyyMMddHHmmss>.<domain> — never a real customer domain. Org number:
// CERTINEXT_ORG_NUMBER (via the V1 fixture). Every SSL create includes an `agreement` block
// with signerPlace populated (Constants default "Gateway Lab", matching this project's sibling
// V2 probes) — 0039 already made SignerPlace required for V2, so a raw body omitting it would
// only test 0039's own already-answered question, not one of P1-P5.
//
// CSRs: BouncyCastle only (repo convention — see CLAUDE.md). No System.Security.Cryptography
// anywhere in this file.
//
// Logging: every raw request/response body is passed through
// CERTInextClient.ApplyLoggingRedaction(body, logSensitiveRequestData: false) before being
// written via ITestOutputHelper, so the real inbox email these probes carry in
// requestor/technicalPointOfContact is never written to a log file in the clear (issue 0058
// constraint: "Logging: log each raw request and response through the redaction helpers
// (0040)"; ApplyLoggingRedaction is internal — reachable here via CERTInext's
// InternalsVisibleTo("CERTInext.IntegrationTests"), same access RedactPersonalDataTests uses).
// Each probe ends with one ITestOutputHelper summary line: probe id, HTTP status, EMS code (if
// any), status, orderId, cancel outcome.
//
// No automatic retries of any place call anywhere in this file — exactly one create call per
// probe, matching UccPendingSanOrderProbeTests/EmailNotificationsV2ProbeTests' documented
// no-retry rule for this sandbox (a client-side timeout does not prove the CA never processed
// the request).
//
// Run (after the user's go/no-go on this design):
//   set -a; . ~/.env_certinext; set +a
//   export CERTINEXT_V2_GAP_PROBES=1
//   export CERTINEXT_INBOX_TEST_EMAIL=<a real inbox you can check>
//   dotnet test CERTInext.IntegrationTests/CERTInext.IntegrationTests.csproj -c Release -p:DcvSupport=false \
//     --filter "FullyQualifiedName~V2GapProbeTests" --logger "console;verbosity=detailed" > /tmp/v2gap.log 2>&1
namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text.Json;
    using System.Text.Json.Nodes;
    using System.Text.Json.Serialization;
    using System.Text.RegularExpressions;
    using System.Threading.Tasks;
    using FluentAssertions;
    using Keyfactor.Extensions.CAPlugin.CERTInext.API;
    using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
    using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
    using Org.BouncyCastle.Asn1.X509;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Generators;
    using Org.BouncyCastle.Pkcs;
    using Org.BouncyCastle.Security;
    using RestSharp;
    using Xunit;
    using Xunit.Abstractions;

    public class V2GapProbeTests : IClassFixture<IntegrationTestFixture>
    {
        private const string OptInFlag = "CERTINEXT_V2_GAP_PROBES";

        /// <summary>Order placed for issue 0047's UCC CSR-shape probe; see this file's PRE probe.</summary>
        private const string TrackedOrderId = "9295677273";

        /// <summary>
        /// 120s — matches this repo's other slow-endpoint V2 probes (EmailNotificationsV2ProbeTests/
        /// UccDcvShapeV2ProbeTests/UccPendingSanOrderProbeTests' own NewApiClient timeout). Observed
        /// during earlier probe authoring: an OV/OV-shaped order-create call on this sandbox can
        /// exceed the framework's 100s default.
        /// </summary>
        private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(120);

        /// <summary>
        /// 300s — P1 and P2 both place an OV-shaped order (productVariant:"ov" + an
        /// organization block + an additionalDomains entry) and both hit the 120s
        /// <see cref="ProbeTimeout"/> as a client-side <c>TaskCanceledException</c> (HTTP 0)
        /// on a live sandbox run (issue 0058 sweep follow-up — see
        /// Sweep_FindsAndCancelsOrphanedGapProbeOrders's header comment). A client timeout does
        /// not prove CERTInext never created the order, so raising only the OV-create timeout
        /// (not every probe's) gives a future P1/P2 run enough headroom to get a real HTTP
        /// response — success or CA-side rejection — back from the create call itself.
        /// </summary>
        private static readonly TimeSpan OvCreateProbeTimeout = TimeSpan.FromSeconds(300);

        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;

        private readonly bool _armed;
        private readonly string _v2ApiUrl;
        private readonly string _v2ClientId;
        private readonly string _v2ClientSecret;
        private readonly string _dcvDomainBase;
        private readonly string _inboxTestEmail;
        private readonly bool _v2Enabled;

        public V2GapProbeTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;

            // Read the opt-in flag from the real process environment BEFORE promoting the V2 env
            // file (mirrors PrivatePkiV2LiveTests) — a value left in ~/.env_certinext_v2 must
            // never arm this file. IntegrationTestFixture's own _optInOnlyFlags list (this file's
            // constructor parameter) already keeps ~/.env_certinext from arming it either.
            _armed = Environment.GetEnvironmentVariable(OptInFlag)?.Trim() == "1";

            var env = V2EnvHelper.LoadAndPromote();
            _v2ApiUrl = V2EnvHelper.GetEnv(env, "CERTINEXT_API_URL");
            _v2ClientId = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_ID");
            _v2ClientSecret = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_SECRET");
            _dcvDomainBase = V2EnvHelper.GetEnv(env, "CERTINEXT_DCV_DOMAIN", "example.com");

            // Never falls back to CERTINEXT_REQUESTOR_EMAIL — that placeholder is non-deliverable
            // (issue 0058's own constraint; see also EmailNotificationsV2ProbeTests).
            _inboxTestEmail = Environment.GetEnvironmentVariable("CERTINEXT_INBOX_TEST_EMAIL")?.Trim();

            _v2Enabled = !string.IsNullOrWhiteSpace(V2EnvHelper.GetEnv(env, "CERTINEXT_USE_V2_API"))
                         && !string.IsNullOrWhiteSpace(_v2ApiUrl)
                         && !string.IsNullOrWhiteSpace(_v2ClientId)
                         && !string.IsNullOrWhiteSpace(_v2ClientSecret);
        }

        // ---------------------------------------------------------------------------
        // Shared skip guards
        // ---------------------------------------------------------------------------

        private void SkipUnlessArmedAndConfigured()
        {
            Skip.If(!_armed,
                $"{OptInFlag}=1 not set in the real process environment — these probes place real, " +
                "potentially cost-bearing V2 SSL orders and require the user's explicit go/no-go " +
                "(issue 0058). Skipping.");
            Skip.If(!_v2Enabled,
                "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");
            Skip.If(string.IsNullOrWhiteSpace(_inboxTestEmail),
                "CERTINEXT_INBOX_TEST_EMAIL not set — set it to a real inbox you can check, " +
                "never CERTINEXT_REQUESTOR_EMAIL (non-deliverable placeholder). Skipping.");
        }

        /// <summary>
        /// Narrower gate than <see cref="SkipUnlessArmedAndConfigured"/> for
        /// <see cref="Sweep_FindsAndCancelsOrphanedGapProbeOrders"/> — that sweep lists/tracks/
        /// cancels pre-existing orders rather than building a requestor/technicalPointOfContact
        /// block, so it does not need CERTINEXT_INBOX_TEST_EMAIL. Still requires the same
        /// go/no-go opt-in and live V2 credentials as P1-P5, since it can cancel real sandbox
        /// orders.
        /// </summary>
        private void SkipUnlessArmedForSweep()
        {
            Skip.If(!_armed,
                $"{OptInFlag}=1 not set in the real process environment — this sweep can cancel " +
                "real sandbox orders and requires the same explicit go/no-go as P1-P5 (issue 0058). Skipping.");
            Skip.If(!_v2Enabled,
                "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");
        }

        // ---------------------------------------------------------------------------
        // PRE — read-only baseline: order 9295677273 (issue 0047)
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Read-only. Tracks order <see cref="TrackedOrderId"/> and logs its status and, if the
        /// response carries them, its SAN(s) — a best-effort scan, since none of this repo's
        /// response DTOs model a confirmed SAN-array field on a Track Order response (issue
        /// 0042). Gated behind the same <see cref="OptInFlag"/> as P1-P5 even though it makes no
        /// mutating call, per issue 0058's explicit instruction.
        /// </summary>
        [SkippableFact]
        public async Task Pre_TrackOrder_V2_ExistingOrder9295677273_LogsStatusAndSans()
        {
            SkipUnlessArmedAndConfigured();

            var track = await TrackOrderRawAsync(TrackedOrderId);

            _output.WriteLine("=== Issue 0058 PRE probe: Track Order 9295677273 (issue 0047 baseline) ===");
            _output.WriteLine($"HTTP {track.StatusCode}");
            _output.WriteLine(RedactForLog(track.Body));

            string status = TryExtractStringField(track.Body, "status");
            string domain = TryExtractStringField(track.Body, "domain");
            List<string> sanFieldHits = ScanForKeyValues(track.Body, "domain");

            _output.WriteLine("");
            _output.WriteLine(sanFieldHits.Count > 0
                ? $"Domain-related fields found: {string.Join("; ", sanFieldHits.Select(RedactForLog))}"
                : "No domain-related fields found in the raw body.");

            _output.WriteLine("");
            _output.WriteLine(
                $"SUMMARY | Probe=PRE OrderId={TrackedOrderId} HTTP={track.StatusCode} " +
                $"Status={status ?? "<none>"} PrimaryDomain={domain ?? "<none>"} Cancel=N/A (read-only)");

            track.StatusCode.Should().NotBe(0,
                "the token call and the Track Order GET itself must succeed — HTTP 0 means a " +
                "transport-level failure reaching the CA, not a CA response to record");
        }

        // ---------------------------------------------------------------------------
        // P1 — OV + 1 additionalDomains + organization, NO X-Product-Code
        // ---------------------------------------------------------------------------

        /// <summary>
        /// productVariant:"ov" + one additionalDomains entry + an organization block, with NO
        /// X-Product-Code header at all. Records whatever the CA echoes back as a resolved
        /// product code (best-effort scan of the create/Track Order bodies).
        /// </summary>
        [SkippableFact]
        public async Task P1_OvWithAdditionalDomains_NoProductCodeHeader_RecordsAutoResolve()
        {
            SkipUnlessArmedAndConfigured();

            string organizationNumber = _fixture.IsConfigured ? _fixture.OrgNumber : null;
            Skip.If(string.IsNullOrWhiteSpace(organizationNumber),
                "CERTINEXT_ORG_NUMBER not set in ~/.env_certinext — P1 needs it for the OV order's " +
                "organization block. Skipping.");

            string stamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            string primary = $"gap-p1-{stamp}.{_dcvDomainBase}";
            string additional = $"gap-p1-{stamp}-b.{_dcvDomainBase}";

            var orderReq = new V2CreateSslOrderRequest
            {
                ProductVariant = "ov",
                EmailNotifications = "all",
                Requestor = BuildRequestor(),
                Organization = new V2OrganizationParams { OrganizationNumber = organizationNumber, PreVetted = true },
                Certificate = new V2CertificateParams { Domain = primary, AutoSecureWww = false, AdditionalDomains = new List<string> { additional } },
                Subscription = BuildSubscription(),
                Agreement = BuildAgreement(),
                TechnicalPointOfContact = BuildTechnicalPointOfContact(),
                Remarks = "Issue 0058 P1 probe — OV + additionalDomains, no X-Product-Code header."
            };
            string requestJson = JsonSerializer.Serialize(orderReq, GetJsonOptions());

            await RunCreateThenCancelAsync(
                probeId: "P1",
                productCodeOrNull: null,
                requestJson: requestJson,
                primaryDomain: primary,
                createTimeoutOverride: OvCreateProbeTimeout,
                extraProbeWork: async (createResp, orderId) =>
                {
                    List<string> productCodeHits = ScanForKeyValues(createResp.Body, "productcode");
                    _output.WriteLine(productCodeHits.Count > 0
                        ? $"resolvedProductCode candidate field(s): {string.Join("; ", productCodeHits)}"
                        : "resolvedProductCode: not echoed in the create response — check the order in the CERTInext portal.");

                    if (!string.IsNullOrWhiteSpace(orderId))
                    {
                        var track = await TrackOrderRawAsync(orderId);
                        _output.WriteLine("");
                        _output.WriteLine("--- Track Order (post-create) ---");
                        _output.WriteLine(RedactForLog(track.Body));
                        List<string> trackProductCodeHits = ScanForKeyValues(track.Body, "productcode");
                        if (trackProductCodeHits.Count > 0)
                            _output.WriteLine($"resolvedProductCode candidate field(s) in Track Order: {string.Join("; ", trackProductCodeHits)}");
                    }
                });
        }

        // ---------------------------------------------------------------------------
        // P2 — same body, X-Product-Code pinned to the live non-UCC OV SSL code
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Same body as P1, but with X-Product-Code pinned to the catalog's live, non-UCC OV
        /// SSL product (productTypeID 16), resolved from the live catalog at run time. Records
        /// rejected (HTTP + EMS code), re-routed to UCC, or additionalDomains silently dropped.
        /// </summary>
        [SkippableFact]
        public async Task P2_OvWithAdditionalDomains_PinnedNonUccProductCode_RecordsCaResponse()
        {
            SkipUnlessArmedAndConfigured();

            string organizationNumber = _fixture.IsConfigured ? _fixture.OrgNumber : null;
            Skip.If(string.IsNullOrWhiteSpace(organizationNumber),
                "CERTINEXT_ORG_NUMBER not set in ~/.env_certinext — P2 needs it for the OV order's " +
                "organization block. Skipping.");

            string ovSslProductCode = await ResolveProductCodeByTypeIdAsync(Constants.Products.ProductTypeIdsV2[Constants.Products.OvSsl]);
            Skip.If(ovSslProductCode == null,
                $"No live catalog product found with productTypeID=\"{Constants.Products.ProductTypeIdsV2[Constants.Products.OvSsl]}\" " +
                "(non-UCC OV SSL) on this account — P2 cannot resolve a product code to pin. Skipping.");

            string stamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            string primary = $"gap-p2-{stamp}.{_dcvDomainBase}";
            string additional = $"gap-p2-{stamp}-b.{_dcvDomainBase}";

            var orderReq = new V2CreateSslOrderRequest
            {
                ProductVariant = "ov",
                EmailNotifications = "all",
                Requestor = BuildRequestor(),
                Organization = new V2OrganizationParams { OrganizationNumber = organizationNumber, PreVetted = true },
                Certificate = new V2CertificateParams { Domain = primary, AutoSecureWww = false, AdditionalDomains = new List<string> { additional } },
                Subscription = BuildSubscription(),
                Agreement = BuildAgreement(),
                TechnicalPointOfContact = BuildTechnicalPointOfContact(),
                Remarks = "Issue 0058 P2 probe — OV + additionalDomains, X-Product-Code pinned to non-UCC OV SSL."
            };
            string requestJson = JsonSerializer.Serialize(orderReq, GetJsonOptions());

            _output.WriteLine($"Resolved non-UCC OV SSL product code from live catalog: {ovSslProductCode}");

            await RunCreateThenCancelAsync(
                probeId: "P2",
                productCodeOrNull: ovSslProductCode,
                requestJson: requestJson,
                primaryDomain: primary,
                createTimeoutOverride: OvCreateProbeTimeout,
                extraProbeWork: async (createResp, orderId) =>
                {
                    if (string.IsNullOrWhiteSpace(orderId))
                    {
                        _output.WriteLine("No orderId parsed — likely a hard rejection; see the create response above for the EMS code.");
                        return;
                    }

                    var track = await TrackOrderRawAsync(orderId);
                    _output.WriteLine("");
                    _output.WriteLine("--- Track Order (post-create) ---");
                    _output.WriteLine(RedactForLog(track.Body));

                    List<string> additionalDomainHits = ScanForKeyValues(track.Body, "additionaldomains");
                    _output.WriteLine(additionalDomainHits.Count > 0
                        ? $"additionalDomains field found on Track Order: {string.Join("; ", additionalDomainHits.Select(RedactForLog))} — NOT silently dropped."
                        : "No additionalDomains field found on Track Order — either silently dropped, or the field is never echoed back for this product (compare against the create response above).");
                });
        }

        // ---------------------------------------------------------------------------
        // P3a / P3b — DV create with an inline "csr" field (issue 0062)
        // ---------------------------------------------------------------------------

        /// <summary>P3a — inline csr as PEM (with BEGIN/END markers).</summary>
        [SkippableFact]
        public async Task P3a_DvCreate_InlineCsrPem_RecordsLifecycleAndFollowUpPut()
        {
            SkipUnlessArmedAndConfigured();
            await RunInlineCsrProbeAsync(probeId: "P3a", useDerEncoding: false);
        }

        /// <summary>P3b — inline csr as headerless Base64 DER, exactly like the spec's own samples.</summary>
        [SkippableFact]
        public async Task P3b_DvCreate_InlineCsrBase64Der_RecordsLifecycleAndFollowUpPut()
        {
            SkipUnlessArmedAndConfigured();
            await RunInlineCsrProbeAsync(probeId: "P3b", useDerEncoding: true);
        }

        private async Task RunInlineCsrProbeAsync(string probeId, bool useDerEncoding)
        {
            string stamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            string primary = $"gap-{probeId.ToLowerInvariant()}-{stamp}.{_dcvDomainBase}";

            // Resolved live, never from the V1 fixture's CERTINEXT_PRODUCT_CODE — Constants.cs
            // documents the V1-era numbering as wrong for V2 (issue 0036), same reasoning as
            // P2/P4/P5's own live catalog resolution below.
            string dvSslTypeId = Constants.Products.ProductTypeIdsV2[Constants.Products.DvSsl];
            string productCode = await ResolveProductCodeByTypeIdAsync(dvSslTypeId);
            Skip.If(productCode == null,
                $"No live catalog product found with productTypeID=\"{dvSslTypeId}\" (DV SSL) on " +
                $"this account — {probeId} cannot resolve a product code. Skipping.");

            var csr = GenerateCsr(primary);
            string inlineCsrValue = useDerEncoding ? CsrToBase64Der(csr) : CsrToPem(csr);

            var orderReq = new V2CreateSslOrderRequest
            {
                ProductVariant = "dv",
                EmailNotifications = "all",
                Requestor = BuildRequestor(),
                Certificate = new V2CertificateParams { Domain = primary, AutoSecureWww = false },
                Subscription = BuildSubscription(),
                Agreement = BuildAgreement(),
                TechnicalPointOfContact = BuildTechnicalPointOfContact(),
                Remarks = $"Issue 0058 {probeId} probe — DV create with an inline csr field " +
                          $"({(useDerEncoding ? "Base64 DER, no PEM markers" : "PEM")})."
            };
            string baseJson = JsonSerializer.Serialize(orderReq, GetJsonOptions());

            // V2CreateSslOrderRequest has no "csr" property (issue 0062 — the gap this probe
            // exists to test) — added by hand onto the serialized JSON so the exact wire body
            // matches what a hand-authored request could send.
            JsonNode node = JsonNode.Parse(baseJson)!;
            node["csr"] = inlineCsrValue;
            string requestJson = node.ToJsonString();

            _output.WriteLine($"Resolved DV SSL product code from live catalog: {productCode}");

            // Routed through RunCreateThenCancelAsync (rather than place/PUT/cancel inline) so
            // the cancel-in-finally guarantee applies to the follow-up PUT and its token fetch
            // too — either one throwing used to skip cleanup entirely.
            string putStatus = "not attempted (no orderId)";
            await RunCreateThenCancelAsync(
                probeId: probeId,
                productCodeOrNull: productCode,
                requestJson: requestJson,
                primaryDomain: primary,
                extraProbeWork: async (createResp, orderId) =>
                {
                    string createStatus = TryExtractStringField(createResp.Body, "status");
                    bool skippedPendingCsr = !string.IsNullOrWhiteSpace(createStatus)
                                              && !string.Equals(createStatus, Constants.ApiV2.StatusPendingCsr, StringComparison.OrdinalIgnoreCase);
                    _output.WriteLine("");
                    _output.WriteLine(!string.IsNullOrWhiteSpace(createStatus)
                        ? $"Order status after create: \"{createStatus}\" — {(skippedPendingCsr ? "skips" : "does NOT skip")} \"{Constants.ApiV2.StatusPendingCsr}\"."
                        : "No status field parsed from the create response.");

                    if (string.IsNullOrWhiteSpace(orderId))
                        return;

                    var freshCsr = GenerateCsr(primary);
                    var putResp = await SubmitCsrRawAsync(orderId, CsrToPem(freshCsr));
                    _output.WriteLine("");
                    _output.WriteLine("--- Follow-up PUT .../csr ---");
                    _output.WriteLine($"HTTP {putResp.StatusCode}");
                    _output.WriteLine(RedactForLog(putResp.Body));
                    putStatus = putResp.IsSuccessful
                        ? "ACCEPTED"
                        : $"REJECTED (HTTP {putResp.StatusCode}, EMS={TryExtractEmsCode(putResp.Body) ?? "<none>"})";
                });

            _output.WriteLine($"[{probeId}] FollowUpPut={putStatus}");
        }

        // ---------------------------------------------------------------------------
        // P4 — DV UCC order + 2 additionalDomains, then PUT .../csr with a CN-only CSR
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Places a DV UCC order (productTypeID 15, live-resolved) with 2 additionalDomains,
        /// then submits a CN-only CSR (the spec's own documented UCC CSR shape — SANs come from
        /// the order, not the CSR). Records accepted vs EMS-921/EMS-922.
        /// </summary>
        [SkippableFact]
        public async Task P4_DvUccOrder_TwoAdditionalDomains_CnOnlyCsr_RecordsAcceptance()
        {
            SkipUnlessArmedAndConfigured();

            string uccProductCode = await ResolveProductCodeByTypeIdAsync(Constants.Products.ProductTypeIdsV2[Constants.Products.DvSslUcc]);
            Skip.If(uccProductCode == null,
                $"No live catalog product found with productTypeID=\"{Constants.Products.ProductTypeIdsV2[Constants.Products.DvSslUcc]}\" " +
                "(DV SSL UCC) on this account — P4 cannot resolve a product code. Skipping.");

            string stamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            string primary = $"gap-p4-{stamp}.{_dcvDomainBase}";
            string sanA = $"gap-p4-{stamp}-a.{_dcvDomainBase}";
            string sanB = $"gap-p4-{stamp}-b.{_dcvDomainBase}";

            var orderReq = new V2CreateSslOrderRequest
            {
                ProductVariant = "dv",
                EmailNotifications = "all",
                Requestor = BuildRequestor(),
                Certificate = new V2CertificateParams { Domain = primary, AutoSecureWww = false, AdditionalDomains = new List<string> { sanA, sanB } },
                Subscription = BuildSubscription(),
                Agreement = BuildAgreement(),
                TechnicalPointOfContact = BuildTechnicalPointOfContact(),
                Remarks = "Issue 0058 P4 probe — DV UCC + 2 additionalDomains, CN-only follow-up CSR."
            };
            string requestJson = JsonSerializer.Serialize(orderReq, GetJsonOptions());

            _output.WriteLine($"Resolved DV SSL UCC product code from live catalog: {uccProductCode}");

            await RunCreateThenCancelAsync(
                probeId: "P4",
                productCodeOrNull: uccProductCode,
                requestJson: requestJson,
                primaryDomain: primary,
                extraProbeWork: async (createResp, orderId) =>
                {
                    if (string.IsNullOrWhiteSpace(orderId))
                    {
                        _output.WriteLine("No orderId parsed — the CN-only CSR follow-up cannot be attempted.");
                        return;
                    }

                    var cnOnlyCsr = GenerateCsr(primary);
                    var putResp = await SubmitCsrRawAsync(orderId, CsrToPem(cnOnlyCsr));
                    _output.WriteLine("");
                    _output.WriteLine("--- PUT .../csr with a CN-only CSR (spec's documented UCC shape) ---");
                    _output.WriteLine($"HTTP {putResp.StatusCode}");
                    _output.WriteLine(RedactForLog(putResp.Body));
                    string putEms = TryExtractEmsCode(putResp.Body);
                    _output.WriteLine(putResp.IsSuccessful
                        ? "CN-only CSR ACCEPTED."
                        : $"CN-only CSR REJECTED — EMS={putEms ?? "<none>"}. " +
                          "Compare against EMS-921/EMS-922 in v2-api-support-questions.md.");
                });
        }

        // ---------------------------------------------------------------------------
        // P5 — productVariant:"dv" + X-Product-Code pinned to the live OV SSL code, no organization
        // ---------------------------------------------------------------------------

        /// <summary>
        /// productVariant:"dv" with X-Product-Code pinned to the catalog's live, non-UCC OV SSL
        /// product (productTypeID 16, same resolution as P2) and no organization block — issue
        /// 0059's variant/product mismatch. Records reject, DV, or a stalled OV-shaped order.
        /// </summary>
        [SkippableFact]
        public async Task P5_DvVariant_PinnedOvProductCode_NoOrganization_RecordsMismatchBehavior()
        {
            SkipUnlessArmedAndConfigured();

            string ovSslProductCode = await ResolveProductCodeByTypeIdAsync(Constants.Products.ProductTypeIdsV2[Constants.Products.OvSsl]);
            Skip.If(ovSslProductCode == null,
                $"No live catalog product found with productTypeID=\"{Constants.Products.ProductTypeIdsV2[Constants.Products.OvSsl]}\" " +
                "(non-UCC OV SSL) on this account — P5 cannot resolve a product code to pin. Skipping.");

            string stamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            string primary = $"gap-p5-{stamp}.{_dcvDomainBase}";

            var orderReq = new V2CreateSslOrderRequest
            {
                ProductVariant = "dv", // deliberately mismatched against the pinned OV product code
                EmailNotifications = "all",
                Requestor = BuildRequestor(),
                // Deliberately NO Organization block — issue 0059's exact mismatch shape.
                Certificate = new V2CertificateParams { Domain = primary, AutoSecureWww = false },
                Subscription = BuildSubscription(),
                Agreement = BuildAgreement(),
                TechnicalPointOfContact = BuildTechnicalPointOfContact(),
                Remarks = "Issue 0058 P5 probe — productVariant:dv, X-Product-Code pinned to non-UCC OV SSL, no organization."
            };
            string requestJson = JsonSerializer.Serialize(orderReq, GetJsonOptions());

            _output.WriteLine($"Resolved non-UCC OV SSL product code from live catalog: {ovSslProductCode}");

            await RunCreateThenCancelAsync(
                probeId: "P5",
                productCodeOrNull: ovSslProductCode,
                requestJson: requestJson,
                primaryDomain: primary,
                extraProbeWork: async (createResp, orderId) =>
                {
                    if (string.IsNullOrWhiteSpace(orderId))
                    {
                        _output.WriteLine("No orderId parsed — likely a hard EMS-915-style reject; see the create response above.");
                        return;
                    }

                    var track = await TrackOrderRawAsync(orderId);
                    _output.WriteLine("");
                    _output.WriteLine("--- Track Order (post-create) ---");
                    _output.WriteLine(RedactForLog(track.Body));
                    string echoedVariant = TryExtractStringField(track.Body, "productVariant");
                    _output.WriteLine($"productVariant echoed on Track Order: {echoedVariant ?? "<none>"} " +
                                       "(compare against the pinned OV product code above to see which one 'won').");
                });
        }

        // ---------------------------------------------------------------------------
        // Sweep — find and clean up orders P1-P5 may have orphaned on the sandbox
        // ---------------------------------------------------------------------------

        /// <summary>
        /// P1 and P2 both place an OV-shaped order (productVariant:"ov" + an organization block
        /// + one additionalDomains entry) and both hit <see cref="ProbeTimeout"/> as a
        /// client-side <c>TaskCanceledException</c> (HTTP 0) on a live sandbox run. A client
        /// timeout does not prove CERTInext never created the order — if it did, that order is
        /// now orphaned on the sandbox with no <c>CARequestID</c> ever recorded by this test
        /// process. This sweep answers that by listing the V2 orders report for "today" (UTC),
        /// finding every row whose <c>domainName</c> starts with "gap-p" (covers all of
        /// P1-P5's own domain naming, not just P1/P2 — any of them could have left an orphan
        /// the same way), tracking each one raw, and cancelling it if it is not already
        /// cancelled/revoked/rejected — confirming with a fresh GET afterward.
        ///
        /// Read-only discovery, not a mutation gate: gated by the same <see cref="OptInFlag"/> +
        /// V2-credentials guard as P1-P5 (this sweep can cancel real sandbox orders), but — unlike
        /// <see cref="SkipUnlessArmedAndConfigured"/> — it does NOT require
        /// CERTINEXT_INBOX_TEST_EMAIL: it never builds a requestor/technicalPointOfContact block,
        /// so the placeholder email <see cref="BuildV2Client"/> otherwise threads through
        /// (CERTInextConfig.RequestorEmail) is immaterial to a report-list/track/cancel-only run.
        ///
        /// Uses <c>GET /api/certinext/v2/reports/orders</c> via the already-typed
        /// <see cref="CERTInextClient.ListOrdersV2Async"/> (paging handled internally,
        /// <c>domainName</c> confirmed live per <see cref="OrderReportEntryV2.DomainName"/>'s own
        /// doc comment) rather than hand-rolling pagination against
        /// <see cref="CERTInextClient.ProbeV2GetAsync"/> a second time. If that call throws, the
        /// finding is logged (nothing else in the report envelope carries a domain value to fall
        /// back to) and the exception is rethrown — a report failure is a probe-mechanism break,
        /// not a CA-response finding.
        /// </summary>
        [SkippableFact]
        public async Task Sweep_FindsAndCancelsOrphanedGapProbeOrders()
        {
            SkipUnlessArmedForSweep();

            DateTime todayUtc = DateTime.UtcNow.Date;
            string from = todayUtc.ToString("yyyy-MM-dd");
            string to = todayUtc.AddDays(1).ToString("yyyy-MM-dd"); // +1 day margin — Probe3 confirmed from/to are inclusive date brackets.

            _output.WriteLine("=== Issue 0058 sweep: orphaned gap-probe orders ===");
            _output.WriteLine($"Report window: GET {Constants.ApiV2.OrdersReportPath}?from={from}&to={to} (UTC 'today' + 1 day margin).");

            using CERTInextClient client = BuildV2Client();

            var candidates = new List<OrderReportEntryV2>();
            int rowsScanned = 0;
            try
            {
                await foreach (var row in client.ListOrdersV2Async(from, to, pageSize: 100))
                {
                    rowsScanned++;
                    if (!string.IsNullOrWhiteSpace(row.DomainName) &&
                        row.DomainName.StartsWith("gap-p", StringComparison.OrdinalIgnoreCase))
                    {
                        candidates.Add(row);
                    }
                }
            }
            catch (Exception ex)
            {
                _output.WriteLine($"FINDING: GET {Constants.ApiV2.OrdersReportPath} (paged) threw: " +
                                   $"{ex.GetType().Name}: {RedactForLog(ex.Message)}");
                _output.WriteLine("Tried: OrderReportEntryV2.DomainName (confirmed-live field) via " +
                                   "CERTInextClient.ListOrdersV2Async, paging page=1.. with size=100, " +
                                   $"from={from}&to={to}. No other field on this report row models a " +
                                   "domain value to fall back to.");
                throw;
            }

            _output.WriteLine($"Report rows scanned: {rowsScanned}. Candidates (domainName starts with \"gap-p\"): {candidates.Count}.");

            bool foundP1 = false, foundP2 = false;
            bool anyCancelFailed = false;

            foreach (var row in candidates)
            {
                string orderId = row.OrderNumber;
                string domainLower = row.DomainName?.ToLowerInvariant() ?? string.Empty;
                if (domainLower.StartsWith("gap-p1-")) foundP1 = true;
                if (domainLower.StartsWith("gap-p2-")) foundP2 = true;

                _output.WriteLine("");
                _output.WriteLine($"--- Candidate: OrderId={orderId ?? "<none>"} Domain={RedactForLog(row.DomainName)} " +
                                   $"OrderStatus={row.OrderStatus} CertificateStatus={row.CertificateStatus} OrderDate={row.OrderDate} ---");

                if (string.IsNullOrWhiteSpace(orderId))
                {
                    _output.WriteLine("No orderNumber on this report row — cannot track or cancel it. Skipping.");
                    _output.WriteLine($"SUMMARY | OrderId=<none> Domain={RedactForLog(row.DomainName)} " +
                                       "StatusBefore=<none> StatusAfter=<none> ProductVariant=<none> " +
                                       "ResolvedProductCode=<none> AdditionalDomainsPresent=False Cancel=SKIPPED (no orderNumber)");
                    continue;
                }

                var before = await TrackOrderRawAsync(orderId);
                _output.WriteLine($"Track (before): HTTP {before.StatusCode}");
                _output.WriteLine(RedactForLog(before.Body));

                string statusBefore = TryExtractStringField(before.Body, "status");
                string productVariant = TryExtractStringField(before.Body, "productVariant");
                List<string> productCodeHits = ScanForKeyValues(before.Body, "productcode");
                List<string> additionalDomainHits = ScanForKeyValues(before.Body, "additionaldomains");
                List<string> domainHits = ScanForKeyValues(before.Body, "domain");
                string resolvedProductCode = productCodeHits.Count > 0
                    ? string.Join("; ", productCodeHits)
                    : "<not echoed>";

                _output.WriteLine($"StatusBefore={statusBefore ?? "<none>"} ProductVariant={productVariant ?? "<none>"} " +
                                   $"ResolvedProductCode={resolvedProductCode}");
                _output.WriteLine(additionalDomainHits.Count > 0
                    ? $"additionalDomains field(s) found: {string.Join("; ", additionalDomainHits.Select(RedactForLog))}"
                    : "No additionalDomains field found on Track Order.");
                _output.WriteLine(domainHits.Count > 0
                    ? $"domain-related field(s) found: {string.Join("; ", domainHits.Select(RedactForLog))}"
                    : "No domain-related field found on Track Order.");

                bool alreadyTerminal =
                    string.Equals(statusBefore, Constants.ApiV2.StatusCancelled, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(statusBefore, Constants.ApiV2.StatusRevoked, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(statusBefore, Constants.ApiV2.StatusRejected, StringComparison.OrdinalIgnoreCase);

                string statusAfter = statusBefore;
                string cancelOutcome;

                if (alreadyTerminal)
                {
                    cancelOutcome = $"SKIPPED (already {statusBefore})";
                    _output.WriteLine($"Order is already terminal ({statusBefore}) — not cancelling.");
                }
                else
                {
                    try
                    {
                        V2CancelOrderOutcome outcome = await client.CancelOrderV2Async(
                            Constants.ApiV2.FamilySsl,
                            orderId,
                            "Issue 0058 sweep — cancelling an orphaned gap-probe order found via the orders report.");
                        cancelOutcome = outcome.ToString();
                        _output.WriteLine($"Cancel outcome: {cancelOutcome}");

                        var after = await TrackOrderRawAsync(orderId);
                        statusAfter = TryExtractStringField(after.Body, "status");
                        _output.WriteLine($"Track (after): HTTP {after.StatusCode}");
                        _output.WriteLine(RedactForLog(after.Body));
                    }
                    catch (Exception ex)
                    {
                        cancelOutcome = $"FAILED ({ex.GetType().Name}: {RedactForLog(ex.Message)})";
                        statusAfter = "<not re-checked — cancel call itself failed>";
                        anyCancelFailed = true;
                        _output.WriteLine($"Cancel call FAILED — not retried: {RedactForLog(ex.Message)}");
                    }
                }

                _output.WriteLine(
                    $"SUMMARY | OrderId={orderId} Domain={RedactForLog(row.DomainName)} " +
                    $"StatusBefore={statusBefore ?? "<none>"} StatusAfter={statusAfter ?? "<none>"} " +
                    $"ProductVariant={productVariant ?? "<none>"} ResolvedProductCode={resolvedProductCode} " +
                    $"AdditionalDomainsPresent={additionalDomainHits.Count > 0} Cancel={cancelOutcome}");
            }

            _output.WriteLine("");
            _output.WriteLine(
                $"SUMMARY | Sweep complete. RowsScanned={rowsScanned} CandidatesFound={candidates.Count} " +
                $"P1Found={foundP1} P2Found={foundP2}");

            anyCancelFailed.Should().BeFalse(
                "one or more gap-probe orders could not be cancelled during the sweep — see the FAILED " +
                "cancel outcome(s) logged above; per issue 0058's own rule, this sweep does not retry a " +
                "failed cancel automatically.");
        }

        // ---------------------------------------------------------------------------
        // Shared create-then-cancel runner
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Places exactly one raw SSL create-order call, logs and records the outcome, invokes
        /// <paramref name="extraProbeWork"/> for any probe-specific follow-up read/write, then
        /// unconditionally cancels the order in a <c>finally</c> and confirms cancellation with
        /// a fresh read-only GET — even if <paramref name="extraProbeWork"/> throws. Emits the
        /// probe's one-line summary at the end.
        /// </summary>
        private async Task RunCreateThenCancelAsync(
            string probeId,
            string productCodeOrNull,
            string requestJson,
            string primaryDomain,
            Func<RawApiResponse, string, Task> extraProbeWork,
            TimeSpan? createTimeoutOverride = null)
        {
            _output.WriteLine($"=== Issue 0058 {probeId} probe ===");
            _output.WriteLine($"Domain={primaryDomain} ProductCode={productCodeOrNull ?? "<omitted — no X-Product-Code header>"}");
            _output.WriteLine($"Request body: {RedactForLog(requestJson)}");

            string orderId = null;
            RawApiResponse createResp = null;
            try
            {
                createResp = await PlaceSslOrderRawAsync(productCodeOrNull, requestJson, createTimeoutOverride);
                _output.WriteLine("");
                _output.WriteLine("--- Create-order response ---");
                _output.WriteLine($"HTTP {createResp.StatusCode}");
                _output.WriteLine(RedactForLog(createResp.Body));

                orderId = TryExtractOrderId(createResp.Body);

                if (extraProbeWork != null)
                    await extraProbeWork(createResp, orderId);
            }
            finally
            {
                await CancelAndConfirmAsync(probeId, orderId);
            }

            string status = createResp != null ? TryExtractStringField(createResp.Body, "status") : null;
            string emsCode = createResp != null ? TryExtractEmsCode(createResp.Body) : null;
            _output.WriteLine("");
            _output.WriteLine(
                $"SUMMARY | Probe={probeId} HTTP={createResp?.StatusCode.ToString() ?? "<none>"} " +
                $"EMS={emsCode ?? "<none>"} Status={status ?? "<none>"} OrderId={orderId ?? "<none>"}");
        }

        /// <summary>
        /// Cancels <paramref name="orderId"/> (no-op, logged, if null/empty — some probes never
        /// get an orderId back), then always does a fresh read-only GET afterward so cleanup is
        /// verifiable regardless of the cancel outcome. A failed cancel call itself (not merely
        /// a non-2xx CANCEL response — see below) or a failed confirming GET is a probe-mechanism
        /// break and is asserted; the CA's own cancel response code is logged either way.
        /// </summary>
        private async Task CancelAndConfirmAsync(string probeId, string orderId)
        {
            if (string.IsNullOrWhiteSpace(orderId))
            {
                _output.WriteLine("");
                _output.WriteLine($"[{probeId}] No orderId to cancel — nothing to clean up.");
                return;
            }

            _output.WriteLine("");
            _output.WriteLine($"[{probeId}] Cancelling order {orderId}...");
            var cancelResp = await CancelOrderRawAsync(orderId,
                $"Issue 0058 {probeId} probe — cleaning up after recording the CA's response.");
            _output.WriteLine($"Cancel response: HTTP {cancelResp.StatusCode}: {RedactForLog(cancelResp.Body)}");

            var after = await TrackOrderRawAsync(orderId);
            _output.WriteLine($"Post-cancel status (fresh GET): HTTP {after.StatusCode}: {RedactForLog(after.Body)}");
            string afterStatus = TryExtractStringField(after.Body, "status");

            cancelResp.IsSuccessful.Should().BeTrue(
                $"[{probeId}] cleanup must succeed to avoid leaving a live order on the sandbox — " +
                $"HTTP {cancelResp.StatusCode}: {RedactForLog(cancelResp.Body)}");

            _output.WriteLine($"[{probeId}] Cancel outcome confirmed — post-cancel status: {afterStatus ?? "<none>"}.");
        }

        // ---------------------------------------------------------------------------
        // Shared request-body builders
        // ---------------------------------------------------------------------------

        private string RequestorName() => _fixture.IsConfigured && !string.IsNullOrWhiteSpace(_fixture.Config.RequestorName)
            ? _fixture.Config.RequestorName
            : "Keyfactor Test";

        private string RequestorPhone() => _fixture.IsConfigured
            ? CERTInextCAPlugin.ComposeV2Phone(_fixture.Config.RequestorIsdCode, _fixture.Config.RequestorMobileNumber)
            : "+10000000000";

        private V2Requestor BuildRequestor() => new V2Requestor
        {
            Name = RequestorName(),
            Email = _inboxTestEmail,
            Phone = RequestorPhone(),
            Designation = "IT Administrator"
        };

        private V2TechnicalPointOfContact BuildTechnicalPointOfContact() => new V2TechnicalPointOfContact
        {
            Name = RequestorName(),
            Email = _inboxTestEmail,
            Phone = RequestorPhone(),
            Designation = "Technical Contact"
        };

        private V2SubscriptionParams BuildSubscription() => new V2SubscriptionParams
        {
            ValidityYears = 1,
            AutoRenew = false,
            RenewBeforeDays = 30
        };

        private V2AgreementParams BuildAgreement() => new V2AgreementParams
        {
            SignerName = RequestorName(),
            SignerIp = "127.0.0.1",
            SignerPlace = "Gateway Lab",
            Accepted = true
        };

        // ---------------------------------------------------------------------------
        // Live catalog resolution (never hard-code a pinned code — issue 0058's own rule for P2,
        // applied here to P4/P5 too for the same reason)
        // ---------------------------------------------------------------------------

        private CERTInextClient BuildV2Client() => new CERTInextClient(new CERTInextConfig
        {
            ApiUrl = _v2ApiUrl,
            UseV2Api = true,
            OAuthClientId = _v2ClientId,
            OAuthClientSecret = _v2ClientSecret,
            RequestorName = RequestorName(),
            RequestorEmail = _inboxTestEmail,
            SignerIp = "127.0.0.1",
            SignerPlace = "Gateway Lab",
            PageSize = 100
        });

        private async Task<string> ResolveProductCodeByTypeIdAsync(string productTypeId)
        {
            using CERTInextClient client = BuildV2Client();
            List<ProductDetail> catalog = await client.GetProductDetailsV2Async();
            return catalog.FirstOrDefault(p => string.Equals(p.ProductTypeId, productTypeId, StringComparison.OrdinalIgnoreCase))
                          ?.ProductCode;
        }

        // ---------------------------------------------------------------------------
        // BouncyCastle CSR generation (repo convention — never System.Security.Cryptography)
        // ---------------------------------------------------------------------------

        private static Pkcs10CertificationRequest GenerateCsr(string commonName)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            var keyPair = keyGen.GenerateKeyPair();

            var subject = new X509Name($"CN={commonName}");
            return new Pkcs10CertificationRequest("SHA256withRSA", subject, keyPair.Public, null, keyPair.Private);
        }

        private static string CsrToPem(Pkcs10CertificationRequest csr) =>
            "-----BEGIN CERTIFICATE REQUEST-----\n"
            + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
            + "\n-----END CERTIFICATE REQUEST-----";

        /// <summary>Headerless Base64 DER — matches the V2 spec's own inline "csr" create-order samples (no PEM markers, no line breaks).</summary>
        private static string CsrToBase64Der(Pkcs10CertificationRequest csr) =>
            Convert.ToBase64String(csr.GetEncoded());

        // ---------------------------------------------------------------------------
        // Local raw-HTTP helpers (place/track/submit-csr/non-throwing-cancel) — NOT extracted
        // to V2RawProbeHelpers: only the token-fetch and throwing CancelSslOrderRawAsync were
        // shared duplicates across files (issue 0058's explicit ask); these are specific to this
        // file's non-throwing, raw-status/body-returning needs.
        // ---------------------------------------------------------------------------

        private sealed class RawApiResponse
        {
            public int StatusCode { get; set; }
            public string Body { get; set; }
            public bool IsSuccessful { get; set; }
        }

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
        /// Raw HTTP POST to /api/certinext/v2/ssl-certificates. When
        /// <paramref name="productCodeOrNull"/> is null, the X-Product-Code header is omitted
        /// entirely (not sent empty) — P1's exact probe condition. Does not throw on non-2xx.
        /// <paramref name="timeoutOverride"/> defaults to <see cref="ProbeTimeout"/>; P1/P2 pass
        /// <see cref="OvCreateProbeTimeout"/> instead (see that field's comment).
        /// </summary>
        private async Task<RawApiResponse> PlaceSslOrderRawAsync(
            string productCodeOrNull, string requestJson, TimeSpan? timeoutOverride = null)
        {
            TimeSpan timeout = timeoutOverride ?? ProbeTimeout;
            string accessToken = await V2RawProbeHelpers.GetV2AccessTokenAsync(_v2ApiUrl, _v2ClientId, _v2ClientSecret, timeout);

            using var apiClient = V2RawProbeHelpers.NewApiClient(_v2ApiUrl.TrimEnd('/'), timeout);
            var req = new RestRequest(Constants.ApiV2.SslCertificatesPath, Method.Post);
            req.AddHeader("Authorization", $"Bearer {accessToken}");
            req.AddHeader("Accept", "application/json");
            if (productCodeOrNull != null)
                req.AddHeader("X-Product-Code", productCodeOrNull);
            req.AddHeader("Idempotency-Key", Guid.NewGuid().ToString());
            req.AddJsonBody(requestJson);

            var resp = await apiClient.ExecuteAsync(req);
            return ToRawApiResponse(resp);
        }

        private async Task<RawApiResponse> TrackOrderRawAsync(string orderId)
        {
            string accessToken = await V2RawProbeHelpers.GetV2AccessTokenAsync(_v2ApiUrl, _v2ClientId, _v2ClientSecret, ProbeTimeout);

            using var apiClient = V2RawProbeHelpers.NewApiClient(_v2ApiUrl.TrimEnd('/'), ProbeTimeout);
            var req = new RestRequest($"{Constants.ApiV2.SslCertificatesPath}/{orderId}", Method.Get);
            req.AddHeader("Authorization", $"Bearer {accessToken}");
            req.AddHeader("Accept", "application/json");

            var resp = await apiClient.ExecuteAsync(req);
            return ToRawApiResponse(resp);
        }

        /// <summary>
        /// Raw HTTP PUT to /api/certinext/v2/ssl-certificates/{orderId}/csr — the same
        /// { "csr", "attested" } body shape as V2SubmitCsrRequest, sent raw (rather than via
        /// CERTInextClient.SubmitCsrV2Async, which throws on failure) so a rejection's exact
        /// HTTP status and EMS code can be recorded rather than only an exception message.
        /// </summary>
        private async Task<RawApiResponse> SubmitCsrRawAsync(string orderId, string csrPem, bool attested = false)
        {
            string accessToken = await V2RawProbeHelpers.GetV2AccessTokenAsync(_v2ApiUrl, _v2ClientId, _v2ClientSecret, ProbeTimeout);

            using var apiClient = V2RawProbeHelpers.NewApiClient(_v2ApiUrl.TrimEnd('/'), ProbeTimeout);
            var req = new RestRequest($"{Constants.ApiV2.SslCertificatesPath}/{orderId}/csr", Method.Put);
            req.AddHeader("Authorization", $"Bearer {accessToken}");
            req.AddHeader("Accept", "application/json");
            req.AddJsonBody(JsonSerializer.Serialize(new V2SubmitCsrRequest { Csr = csrPem, Attested = attested }, GetJsonOptions()));

            var resp = await apiClient.ExecuteAsync(req);
            return ToRawApiResponse(resp);
        }

        /// <summary>
        /// Raw HTTP POST to /api/certinext/v2/ssl-certificates/{orderId}/cancel — non-throwing
        /// (unlike V2RawProbeHelpers.CancelSslOrderRawAsync, which throws) so cleanup failure can
        /// be logged and asserted with full detail rather than only an exception message.
        /// </summary>
        private async Task<RawApiResponse> CancelOrderRawAsync(string orderId, string reason)
        {
            string accessToken = await V2RawProbeHelpers.GetV2AccessTokenAsync(_v2ApiUrl, _v2ClientId, _v2ClientSecret, ProbeTimeout);

            using var apiClient = V2RawProbeHelpers.NewApiClient(_v2ApiUrl.TrimEnd('/'), ProbeTimeout);
            var req = new RestRequest($"{Constants.ApiV2.SslCertificatesPath}/{orderId}/cancel", Method.Post);
            req.AddHeader("Authorization", $"Bearer {accessToken}");
            req.AddHeader("Accept", "application/json");
            req.AddJsonBody(new { reason });

            var resp = await apiClient.ExecuteAsync(req);
            return ToRawApiResponse(resp);
        }

        // ---------------------------------------------------------------------------
        // Parsing / redaction helpers
        // ---------------------------------------------------------------------------

        private static JsonSerializerOptions GetJsonOptions() => new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        /// <summary>
        /// Redacts credentials and personal data (emails/names) before any raw body reaches
        /// ITestOutputHelper — issue 0058's logging constraint. <c>logSensitiveRequestData:
        /// false</c> always, so the real inbox email this file carries is never written to a
        /// log file in the clear, matching the repo-wide default-off PII posture (see
        /// CERTInextClient.ApplyLoggingRedaction; reachable here via
        /// InternalsVisibleTo("CERTInext.IntegrationTests")). Domain names are never touched by
        /// this redaction — only email/other-personal-data fields are — so the DCV/order-shape
        /// detail these probes exist to observe is unaffected.
        /// </summary>
        private static string RedactForLog(string body) =>
            CERTInextClient.ApplyLoggingRedaction(body, logSensitiveRequestData: false);

        private static string TryExtractOrderId(string body)
        {
            if (string.IsNullOrWhiteSpace(body)) return null;
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

        private static string TryExtractStringField(string body, string fieldName)
        {
            if (string.IsNullOrWhiteSpace(body)) return null;
            try
            {
                using var doc = JsonDocument.Parse(body);
                return doc.RootElement.TryGetProperty(fieldName, out var el) && el.ValueKind == JsonValueKind.String
                    ? el.GetString()
                    : null;
            }
            catch (JsonException)
            {
                return null;
            }
        }

        private static readonly Regex EmsCodeRegex = new Regex(@"\[?EMS-(\d+)\]?", RegexOptions.Compiled);

        private static string TryExtractEmsCode(string body)
        {
            if (string.IsNullOrWhiteSpace(body)) return null;
            var match = EmsCodeRegex.Match(body);
            return match.Success ? $"EMS-{match.Groups[1].Value}" : null;
        }

        /// <summary>
        /// Best-effort recursive scan of a raw JSON body for any property whose name contains
        /// <paramref name="keyNameSubstring"/> (case-insensitive), returning "name=value" for
        /// each hit. Used where this repo's response DTOs do not model a confirmed field for
        /// what a probe needs to check (e.g. no productCode on any order response, no confirmed
        /// additionalDomains echo — issues 0042/0058). Never throws; returns an empty list for
        /// unparseable or empty bodies.
        /// </summary>
        private static List<string> ScanForKeyValues(string body, string keyNameSubstring)
        {
            var found = new List<string>();
            if (string.IsNullOrWhiteSpace(body)) return found;

            try
            {
                using var doc = JsonDocument.Parse(body);
                Walk(doc.RootElement, keyNameSubstring, found);
            }
            catch (JsonException)
            {
                // Unparseable body — nothing to scan; caller already logs the raw body separately.
            }

            return found;

            static void Walk(JsonElement element, string needle, List<string> accumulator)
            {
                switch (element.ValueKind)
                {
                    case JsonValueKind.Object:
                        foreach (JsonProperty prop in element.EnumerateObject())
                        {
                            if (prop.Name.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0)
                                accumulator.Add($"{prop.Name}={prop.Value}");
                            Walk(prop.Value, needle, accumulator);
                        }
                        break;
                    case JsonValueKind.Array:
                        foreach (JsonElement item in element.EnumerateArray())
                            Walk(item, needle, accumulator);
                        break;
                }
            }
        }
    }
}
