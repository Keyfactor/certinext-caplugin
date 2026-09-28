# 1.0.1

## Features
- feat(v2): Add opt-in CERTInext V2 REST API code path — OAuth2 `client_credentials` auth, `ord_`-prefixed order IDs, and V2 status mapping — controlled by `UseV2Api` config flag (defaults `false`; V1 unchanged).
- feat(v2): V2 enrollment handles all three `EnrollmentType` values (New/Reissue/RenewOrReissue) via a single V2 order placement; issued orders download the certificate immediately.
- feat(v2): V2 revocation probes SSL → PrivatePKI → Signature families to locate and revoke an order by its `ord_` ID.
- feat(v2): V2 `GetSingleRecord` resolves order status across all three V2 product families without touching the V1 path.
- feat(v2): Synchronize now uses V2 `/reports/orders` when `UseV2Api` is true, with an incremental lookback window (`V2SyncLookbackHours`, default 72h) — V1 credentials are no longer required in V2 mode.
- feat(v2): Consolidated V2 config onto the existing `ApiUrl`/`OAuthClientId`/`OAuthClientSecret` fields; the never-shipped `ApiUrlV2`/`ClientId`/`ClientSecret` fields are removed.
- **Faster enrollment for quickly-issued certificates.** Enrollment now waits briefly and returns the certificate in the same request when it issues fast, instead of always waiting for the next sync. Configurable via `PickupRetries` (default 5, `0` disables) and `PickupDelay` (default 10s). Orders that don't issue in time (e.g. OV/EV) return pending and are picked up by the next sync, as before.
- feat(v2): V2 enrollment now supports multi-SAN (UCC) certificates. UCC products are detected from the live Catalog's `productTypeID`, and the SAN set is sent via `additionalDomains`; DCV for the extra SANs is not yet automated (see 0042) (F3).

## Bug Fixes
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

## Chores
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
- chore(tests): regression coverage for V2 `productTypeID`-based product code resolution/validation and the V1-fallback-unaffected guarantee (0036).
- chore(tests): regression coverage for `GroupNumber` on V2 order create, catalog, and orders-report calls (0029).
- chore(tests): regression coverage for `technicalPointOfContact` (configured, blank-fallback, and per-field-fallback) on V2 SSL orders (0030).
- chore(tests): regression coverage for the nested V2 `revocation` DTO shape and `RevocationDate`/`RevocationReason` population in `GetSingleRecord`/`Synchronize` (0034).
- chore(tests): regression coverage for `Synchronize`'s ProductID preference order — report row's `ProductCode` first, then a lazily-fetched `productVariant`, then empty (0035).
- chore(tests): regression coverage for `IgnoreExpired` in V2 `Synchronize`, the configurable V2 DCV TXT record template, and ISD-code composition for `Requestor.Phone` (0027).
- chore(tests): regression coverage for `EmailNotifications` mapping (`"1"`/`"0"`/blank/invalid) on V2 order create (0027).
- chore(tests): regression coverage for the V2 CSR-SAN-count guard through `Enroll` for both UCC (order placed, SANs as `additionalDomains`) and non-UCC (FAILED, no order placed) products (0047).
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

