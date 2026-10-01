# 1.0.1

## Features
- feat(v2): Add opt-in CERTInext V2 REST API code path — OAuth2 `client_credentials` auth and V2 status mapping — controlled by `UseV2Api` config flag (defaults `false`; V1 unchanged).
- feat(v2): V2 enrollment handles all three `EnrollmentType` values (New/Reissue/RenewOrReissue) via a single V2 order placement; issued orders download the certificate immediately.
- feat(v2): V2 revocation resolves the order's product family (SSL → Private PKI → Signature) and revokes it there.
- feat(v2): V2 `GetSingleRecord` resolves order status across all three V2 product families without touching the V1 path.
- feat(v2): Synchronize now uses V2 `/reports/orders` when `UseV2Api` is true, with an incremental lookback window (`V2SyncLookbackHours`, default 72h) — V1 credentials are no longer required in V2 mode.
- feat(v2): Consolidated V2 config onto the existing `ApiUrl`/`OAuthClientId`/`OAuthClientSecret` fields; the never-shipped `ApiUrlV2`/`ClientId`/`ClientSecret` fields are removed.
- **Faster enrollment for quickly-issued certificates.** Enrollment now waits briefly and returns the certificate in the same request when it issues fast, instead of always waiting for the next sync. Configurable via `PickupRetries` (default 5, `0` disables) and `PickupDelay` (default 10s). Orders that don't issue in time (e.g. OV/EV) return pending and are picked up by the next sync, as before.
- feat(v2): V2 enrollment now supports multi-SAN (UCC) certificates. UCC products are detected from the live Catalog's `productTypeID`, and the SAN set is sent via `additionalDomains` (F3).

## Bug Fixes
- fix(revoke): V2 revoke denials (404/422) and the not-GENERATED/retry-failure paths now log an audit record (CARequestID, product family, HTTP status, EMS code).
- fix(enroll): a transport error or timeout on V2 CSR submission no longer cancels an order the CA may have accepted; the plugin tracks the order first and cancels only if it is still pending-csr.
- **UCC certificates no longer come back with only the common name.** The gateway sends SANs under the key `dnsname`, which the plugin didn't recognize, so orders went out with an empty domain list. SANs are now read from every key the gateway sends, plus from the CSR itself.
- **Renewals no longer lose their SANs.** Renewals were submitted with no additional domains and the wrong primary domain; both now come from the certificate being renewed.
- **Enrollment no longer fails on an order CERTInext auto-approves before it finishes issuing.** The plugin used to report these as issued with no certificate attached, which the gateway rejected. It now returns pending and picks up the certificate once CERTInext finishes issuing it.
- **Renewals now use the certificate template's product code.** Renewals previously always used the connector's `DefaultProductCode`, which could send an empty product code if that setting was never configured. Renewals now use the template's code, falling back to `DefaultProductCode` only when the template doesn't have one.
- **V2 OAuth errors now name the right cause.** 401 means a bad ClientId/ClientSecret; 403 means the key wasn't created in OAuth mode.
- **V2 error messages now include CERTInext's per-field validation errors.**
- **V2 revocation no longer fails with HTTP 400 for most reasons.** Reasons are now sent in the kebab-case form the API requires.
- **V2 revocation no longer fails when Command supplies no specific reason.** CERTInext rejects the "unspecified" reason value; the plugin now retries once with "cessation-of-operation" (0026).
- **V2 revocation now reports "not found or not revokable" instead of a misleading product-family error.**
- **V2 DCV now treats an already-verified domain (EMS-1080) as satisfied instead of deferring.**
- **V2 DCV now reads the live `token` field instead of the never-populated `fileNameContent` field**, so fresh-domain DV orders no longer get stuck at EXTERNALVALIDATION forever (0037).
- fix(config): `ValidateProductInfo` now validates template `ProductCode` against the V2 catalog when `UseV2Api=true`, instead of always calling the V1-only `GetProductDetails` (0025).
- fix(client): `ParseProductDetailsV2Response` now flattens the nested category envelope the live V2 catalog actually returns, instead of misreading it as flat rows (0016).
- fix(sync): `V2StatusToRequestDisposition` now maps all 11 V2 order statuses; OV/EV/DV orders in `pending-organization-verification`, `pending-documents`, or `pending-approval` no longer get misreported to Command as FAILED (0031).
- fix(enroll): V2 OV/EV orders now send an `organization` block from `OrganizationNumber`; CERTInext previously hard-rejected every V2 OV/EV enrollment with HTTP 422 `EMS-1180` (0028).
- fix(v2): V2 enroll and `ValidateProductInfo` now resolve/validate the product code from the live catalog by `productTypeID` instead of the V1-only `DefaultProductCodes` table, which could silently order the wrong assurance-level product (0036).
- fix(v2): V2 order create, catalog, and orders-report calls now send `GroupNumber` when configured, instead of always billing/scoping to the account's default group (0029).
- fix(v2): V2 SSL order create now sends a `technicalPointOfContact` block from the connector's `TechnicalContact*` config (falling back to `Requestor*` when blank), instead of never sending one (0030).
- fix(v2): V2 `GetSingleRecord`/`Synchronize` now populate `RevocationDate`/`RevocationReason` from the Track Order response's nested `revocation` object, instead of a flat DTO shape that never matched the live API and was never read anyway (0034).
- fix(sync): V2 `Synchronize` now falls back to an already-fetched Track Order `productVariant` when the orders-report row's `ProductCode` is empty, instead of always leaving `ProductID` blank in that case (0035).
- fix(sync): V2 `Synchronize` now honors `IgnoreExpired`, instead of always including expired certificates (0027).
- fix(v2): V2 DCV TXT record hostname now uses the configured `DcvTxtRecordTemplate` (falling back to the same default V1 uses), instead of a hardcoded `_emudhra-challenge` label (0027).
- fix(v2): V2 SSL order create now combines `RequestorIsdCode` with the mobile number for `Requestor.Phone`, instead of sending the bare mobile number (0027).
- fix(v2): V2 SSL order create now sends `Subscription.AutoRenew`/`RenewBeforeDays` from `SubscriptionAutoRenew`/`SubscriptionRenewCriteriaDays` config, instead of hardcoding `false`/`30` (0027).
- fix(config): `requestor.designation` (V2) and `requestorInformation.requestorDesignation` (V1) are now sourced from a new `RequestorDesignation` config field, instead of a hardcoded `"IT Administrator"` (V2) or never being sent at all (V1) (0027).
- fix(v2): V2 SSL order create now honors the connector's `EmailNotifications` setting (`"1"`→`"all"`, `"0"`→`"0"`, blank→omitted) instead of always sending `"all"`; V2 orders now default to `"0"` (reduced notifications), matching V1 (0027).
- fix(enroll): the V2 single-domain CSR-SAN-count guard now exempts UCC products, instead of rejecting every UCC CSR enrollment before it could reach the UCC path (0047).
- fix(audit): the "Enrollment complete" audit log now records the leaf serial for V2 chain PEMs instead of `(parse-error)` (0050).
- fix(v2): V2 enrollment now runs the same short certificate-pickup poll as V1 instead of returning pending when the order hasn't issued yet at the post-CSR check (0051).
- fix(v2): V2 DCV now runs for every SAN on a UCC order, not just the primary domain (0042).
- fix(sync): V2 `Synchronize`/`GetSingleRecord` no longer emit a body-less REVOKED record unless the gateway already holds a certificate body for that order, preventing a poisoned gateway row that broke every future Command scan of the CA (0049).
- fix(enroll): V2 `Enroll` no longer returns a body-less REVOKED result; a REVOKED disposition observed post-CSR-submit, post-DCV, or during the pickup poll is now reported as FAILED (0052).
- fix(v2): V2 `private-pki` enrollment now sends the Private PKI order body (`variant`, `hostname`, `additionalHosts` incl. IP SANs; no DCV) instead of the SSL body; `signature` enrollment fails fast until its subject mapping is designed (0033).
- fix(client): V1 calls that get a non-2xx response now include the HTTP status in the error and log the redacted response body (0044).
- fix(v2): V2 UCC enrollment now logs non-DNS SANs as excluded from `additionalDomains` instead of the V1 "submitted rather than dropped" warning (0046).
- fix(logging): requestor personal data (name, email, phone, org contact fields) and full CA request/response payloads are now redacted from gateway logs by default, gated behind a new opt-in `LogSensitiveRequestData` connector setting (0040).
- fix(logging): email SAN values are now masked in enrollment and SAN-resolution log lines unless `LogSensitiveRequestData` is on (0040).
- fix(logging): email SANs in Trace-logged `additionalDomains`/`additionalHosts` arrays and V1 `domainVerification` keys are now masked unless `LogSensitiveRequestData` is on (0040).
- fix(v2): if V2 CSR submission fails after the order is placed, the plugin now cancels the orphaned order once (best effort) and returns FAILED with its order ID (0039).
- fix(config): V2 connectors now require `SignerPlace` at save time, and V2 SSL enrollment fails fast if it resolves blank, since the Subscriber Agreement requires it (0039).
- fix(sync): the spec-documented V2 order status `unknown` now maps to pending instead of FAILED, so a possibly-live order isn't dropped (0039).
- fix(v2): V2 order create now omits `X-Product-Code` entirely for a null/blank product code instead of sending it empty (0054).
- fix(v2): non-UCC V2 enrollment now rejects extra SANs from Command's SAN dictionary instead of silently dropping them (0061).
- fix(v2): V2 SSL enrollment now derives `productVariant` from the product and rejects a mismatched override, instead of always sending `dv` (0059).
- fix(sync): V2 order status `expired` now maps to GENERATED instead of FAILED, matching V1 and the sync/report path.
- fix(config): `ApiUrl` now requires `https` (credentials would otherwise go out in cleartext); `http` remains allowed for loopback hosts only, for local test servers.
- fix(revoke): V2 revoke's reason-rejection retry now covers all 4 live-rejected CRL reasons (0, 2, 6, 10), not just "unspecified"; each retries once with an accepted fallback (0026).
- fix(enroll): V2 product resolution (no explicit ProductCode) now rejects an ambiguous catalog match instead of silently picking the first-listed entry, which on sandbox ordered an unorderable DV SSL variant; `DefaultProductCode` can disambiguate. Mirrored in `ValidateProductInfo`.
- fix(enroll): the V2 single-domain SAN guard now exempts a wildcard product's bare apex (e.g. `example.com` alongside `*.example.com`) instead of rejecting it as an extra SAN; the rejection message for wildcard products no longer suggests a UCC product.
- fix(crypto): DCV now derives the TXT record hostname (and DNS validator zone) from a wildcard domain's base domain instead of staging a literal `*.` DNS label, across the V1 and V2 single/multi-domain DCV paths; a UCC order listing both the apex and its wildcard now stages and cleans up one shared TXT record instead of two. CA-side acceptance of a base-domain TXT record for a wildcard domain entry is unverified against the live API.
- fix(config): `Initialize` now enforces the same https-or-loopback rule on `ApiUrl`/`OAuthTokenUrl` as `ValidateCAConnectionInfo`, closing a gap where a connector saved before that check existed kept sending credentials in cleartext on every gateway restart.
- fix(config): `OAuthTokenUrl` (V1 OAuth mode) now requires https-or-loopback, matching `ApiUrl`; it previously only checked for non-empty.

## Chores
- chore(tests): regression tests for the wildcard DCV hostname fix — hostname derivation, apex/wildcard hostname dedupe and single cleanup, and non-wildcard-unchanged, across V1 and V2 single/multi-domain paths.
- chore(tests): the V2 fresh-DCV integration tests now target a sibling of a genuinely unverified parent (`CERTINEXT_V2_FRESH_DCV_PARENT`) instead of a subdomain of `CERTINEXT_DCV_DOMAIN`, which that domain's own prior DCV already covers and could never actually exercise the publish path.
- chore(tests): the V2 wildcard+apex SAN integration test now records SAN coverage of the issued certificate (observation only) and describes the guard's wildcard-apex exemption instead of a stale "suspected guard bug NOT reproduced" comment.
- docs(v2): V2 renewal/reissue places a new order by design; the CA's `/reissue` endpoint is intentionally unused (0021, 0038).
- docs(v2): correct stale V2 claims about UCC, credentials, order IDs, idempotency, sync, revoke reasons, and product codes (0038).
- chore(scripts): `scripts/v2/*.sh` dev helpers now use `CERTINEXT_API_URL` + OAuth2 `client_credentials` from `~/.env_certinext_v2`; mutating scripts require `--yes-mutate` (0048).
- chore(tests): WireMock-based unit tests for all V2 client methods (token fetch, caching, PlaceOrder, TrackOrder, Download, Revoke, family resolution).
- chore(tests): Moq-based unit tests verifying V2 dispatch in `CERTInextCAPlugin` (Ping, Enroll, GetSingleRecord, Revoke, Synchronize) with `Times.Never` assertions on V1 paths.
- chore(tests): `StatusMapperV2Tests` covering all V2 status strings and CRL-to-V2-reason mappings.
- chore(tests): Integration test stubs in `V2ApiTests.cs` (gated behind `CERTINEXT_USE_V2_API=1`); skip gracefully when V2 credentials are absent.
- chore(tests): Unit tests for V2 `ValidateCAConnectionInfo`.
- chore(tests): Unit tests for V2 token caching and expiry (`refresh_token` grant never sent).
- chore(tests): DCV cleanup-concurrency test now checks peak concurrency instead of wall-clock time.
- chore(tests): `ValidateProductInfo` coverage in V1 and V2 modes, plus V2 catalog-parser unit and live-integration tests (0025).
- chore(tests): regression tests for the V2 `organization` block (populated for OV/EV, omitted for DV, fail-fast without `OrganizationNumber`); live acceptance against the sandbox confirmed CERTInext accepts the fixed request (0028).
- chore(tests): regression coverage pinning the live V2 DCV response shape (`token`/`tokenExpiryDate` only) against both the client deserializer and the plugin's DCV staging path (0037).
- chore(tests): regression tests for `productVariant` derivation/validation at enroll and template save, including the OV/EV organization-block interaction (0059).
- chore(tests): regression coverage for V2 `productTypeID`-based product code resolution/validation and the V1-fallback-unaffected guarantee (0036).
- chore(tests): regression coverage for `GroupNumber` on V2 order create, catalog, and orders-report calls (0029).
- chore(tests): regression coverage for `technicalPointOfContact` (configured, blank-fallback, and per-field-fallback) on V2 SSL orders (0030).
- chore(tests): regression coverage for the nested V2 `revocation` DTO shape and `RevocationDate`/`RevocationReason` population in `GetSingleRecord`/`Synchronize` (0034).
- chore(tests): regression coverage for `Synchronize`'s ProductID preference order — report row's `ProductCode` first, then a lazily-fetched `productVariant`, then empty (0035).
- chore(tests): regression coverage for `IgnoreExpired` in V2 `Synchronize`, the configurable V2 DCV TXT record template, and ISD-code composition for `Requestor.Phone` (0027).
- chore(tests): regression coverage for `EmailNotifications` mapping (`"1"`/`"0"`/blank/invalid) on V2 order create (0027).
- chore(tests): regression coverage for the V2 CSR-SAN-count guard through `Enroll` for both UCC (order placed, SANs as `additionalDomains`) and non-UCC (FAILED, no order placed) products (0047).
- chore(tests): regression coverage for the V2 bodyless-REVOKED guard — gateway-holds-body, no-body, no-row, reader-failure, and GENERATED-unaffected cases, in both `Synchronize` and `GetSingleRecord` (0049).
- chore(tests): regression coverage for the V2 `Enroll` REVOKED→FAILED normalization — post-CSR-submit, mid-pickup-poll, post-DCV-recheck, and FAILED/GENERATED-unaffected cases (0052).
- chore(tests): regression coverage for `RedactPersonalData`/`ApplyLoggingRedaction` against realistic V1/V2 order payloads, `LogSanitizer.MaskEmail`, the `LogSensitiveRequestData` config default/annotation, and the flag's on/off behavior in `Enroll`'s audit log line (0040).
- chore(tests): opt-in live V2 lifecycle coverage for DV UCC, OV, OV UCC, EV, wildcard DV (both CSR shapes), renew/reissue, and DCV against a fresh unverified domain — product shapes the V2 suite had no assertion-bearing live test for.
- chore(tests): the renew/reissue lifecycle test now fails on a FAILED order instead of just recording it; OV/OV UCC skip cleanly (and sweep for an orphaned order) on the known 120s client-timeout condition (0064); EV now requires its own `CERTINEXT_EV_ORG_NUMBER`; a new wildcard fresh-subdomain DCV test records the staged TXT hostname and Track Order's per-domain verification detail.
- chore(tests): add an opt-in `CERTINEXT_V2_SWEEP_FROM`/`_TO` orders-report sweep that lists, and via `CERTINEXT_V2_SWEEP_CANCEL_IDS` optionally cancels, orders in an arbitrary UTC window.
- **`OrganizationNumber`, `DefaultProductCode`, and `GroupNumber` are now visible in the startup log.** Whether each is set is now logged alongside the other connector settings, making a misconfigured connector easier to diagnose from logs alone.
- **Corrected the `AutoApprove` template setting's description.** It previously implied the plugin would attempt automatic approval of pending certificates; it does not currently do this.

## Upgrade Notes
- **Non-DNS SANs (IP, email, URI) are now submitted instead of silently dropped.** CERTInext can't validate them, so such an order won't issue until the SAN is removed. Set `SubmitNonDnsSans` to `false` to restore the old drop-silently behavior.
- **No more duplicate or orphaned orders after a network timeout.** Order/CSR submissions no longer auto-retry after a timeout, since the CA may have already created the order. If it was created, the next sync imports it.

# 1.0.0

Initial release of the CERTInext (emSign Hub) AnyCA REST Gateway plugin.

## Features
- feat(enroll): Certificate enrollment for CERTInext SSL products — DV, OV, and EV SSL, including Wildcard and Multi-Domain (UCC) variants — with connector- and template-level overrides for product code, requestor identity, organization/group, and validity.
- feat(dcv): End-to-end DNS-01 domain validation for DV SSL through a pluggable `IDomainValidatorFactory` (Cloudflare provider included). Publishes the TXT challenge, asks CERTInext to verify, waits for issuance, and returns the issued certificate directly from `Enroll`. (DCV build — AnyCA Gateway 26.x.)
- feat(sync): Full and incremental CA synchronization via paginated `GetOrderReport`. Issued certificates carry their full PEM body; revoked certificates carry revocation metadata.
- feat(sync): Sync-driven DCV retry drives orders left pending validation to completion on later sync passes, bounded by configurable `DcvSyncMaxOrderAgeHours` and `DcvSyncMaxPerPass` caps so large accounts stay fast.
- feat(revoke): Certificate revocation via `RevokeOrder` with RFC 5280 reason-code mapping.
- feat(auth): AccessKey (HMAC-SHA256) and OAuth client-credentials authentication modes.
- feat(build): Single `DcvSupport` MSBuild flag selects the host-matched build from one codebase — default no-DCV (IAnyCAPlugin `3.2.0`, AnyCA Gateway 25.5.x) or `-p:DcvSupport=true` for the DCV build (IAnyCAPlugin `3.3.0-PRERELEASE`, 26.x). Records persist only when the build matches the host's IAnyCAPlugin version.
- feat(config): Connector-level configuration for pre-vetted organization/group/technical-contact injection, DCV timing knobs (challenge/issuance waits), and SSL order defaults.
- feat(sync): `IgnoreExpired` flag to exclude expired certificates from synchronization.

## Bug Fixes
- fix(sync): Issued certificates now synchronize with their full PEM body — the `GetOrderReport` listing carries no body, so the plugin refetches the full certificate for issued/revoked records. Previously issued certs synced empty and never appeared in Command.
- fix(sync): Preserve listing metadata (`Subject`, `ProductID`, order date) when refetching the certificate body during synchronization, so issued records are not emitted with null fields.
- fix(diagnostics): Every CERTInext API failure logs the HTTP status plus the CA's error code and message; transient rate-limit responses are retried with exponential backoff and jitter.

## Chores
- chore(crypto): All cryptographic operations (CSR/key generation, hashing, the auth nonce) use BouncyCastle exclusively — no `System.Security.Cryptography`.
- chore(deps): `BouncyCastle.Cryptography` 2.6.2 (closes 3 moderate-severity CVEs).
- chore(compat): Ship builds for both `net8.0` and `net10.0`.
- chore(logging): Verbose Debug/Trace logging across the sync flow with method entry/exit tracing.
- chore(tests): Live integration tests covering all supported SSL/TLS product types, the DCV enroll → issue → sync flow, and a key-algorithm matrix — confirms CERTInext issues RSA 2048/3072/4096 and ECC P-256/P-384, and rejects larger RSA, ECC P-521, and Ed25519/Ed448.
- chore(scripts): API smoke-test scripts for every endpoint, including `reject-order` / `reject-all-pending` for cancelling pending orders.

