# 2.0.0

## Breaking Changes
- **Plugin 1.x and the CERTInext V1 API no longer work, because of changes CERTInext made to its API. Customers must upgrade to 2.0.0 and move every connector to the V2 API.** See Upgrade Notes for the V2 settings that differ from V1.
- `UseV2Api` is optional and now defaults to `true`. A connector that doesn't set it, including every connector created under 1.x, runs on V2 after the upgrade, and its CA calls (sync, enroll, revoke) fail until it has a V2 `ApiUrl` (the bare host, without `/emSignHub-API/`), `OAuthClientId`, `OAuthClientSecret` and `SignerPlace`. Only `UseV2Api = false` selects the legacy V1 API.
- AnyCA Gateway REST 25.5.x isn't supported; upgrade the gateway to 26.2.0 or later (Command 25.5 or later works with it). The plugin is built against `IAnyCAPlugin` 3.3.0 with DNS-01 DCV included, and the separate no-DCV build for 25.5.x is gone.
- `DcvEnabled` now defaults to `true`. Without a DNS provider plugin, orders needing validation stay pending; set it to `false` if you validate domains another way.
- `ApiUrl` must use https (loopback hosts excepted). Connectors saved with an `http` `ApiUrl` fail to start until the URL is changed.
- Synced certificates report the product name (for example `DV SSL`) as their `ProductID` instead of CERTInext's product code. Reports, scripts or templates keyed on the code see a different value.
- The in-call pickup wait is capped at 75 s (was 180 s) and bounded by `EnrollmentCallBudgetSeconds` (default 50) measured from the start of `Enroll`. Connectors with a longer `PickupRetries` × `PickupDelay` return pending sooner, and the certificate arrives through sync.

## Features
- feat(v2): CERTInext V2 REST API, selected by `UseV2Api` (optional, default `true`), authenticated with OAuth2 `client_credentials`.
- feat(v2): Enroll, renew, reissue, revoke, and synchronize SSL/TLS and Private PKI products, selected with the `ProductFamily` and `ProductVariant` template parameters.
- feat(v2): Multi-domain (UCC) and wildcard SSL/TLS enrollment, with extra SANs sent as `additionalDomains`. CERTInext picks the product from the variant and domains; a template's `ProductCode` overrides it.
- feat(v2): SSL/TLS reissue through CERTInext's reissue endpoint. New setting `V2ReissueRevokePrevious` (default `false`) also revokes the previous certificate.
- feat(v2): OV and EV orders check the organization's SSL.com validation first. New settings `SslComSubmitOrganization` (default `false`; enabling it accepts SSL.com's subscriber agreement on the organization's behalf) and `SslComAdminEmail`.
- feat(v2): New OV template parameters `OrgRepresentativeName`, `OrgRepresentativeEmail`, `OrgRepresentativePhone`, `OrgRepresentativeDesignation` and `OrgRepresentativeEmployeeId` register a new Organization Representative on an order.
- feat(v2): An order waiting at `pending-agreement` gets the Subscriber Agreement accepted with the connector's signer values.
- feat(dcv): DNS-01 domain validation for V2 SSL/TLS orders, including every SAN on a UCC order and domains validated by SSL.com.
- feat(config): New setting `RequestorDesignation`.
- feat(logging): Each time the gateway initializes the plugin, it logs the plugin's version, whether the build includes DCV support, and its target framework, even when initialization then fails.

## Bug Fixes
- fix(enroll): New setting `EnrollmentCallBudgetSeconds` (default 50, `0` disables, at most 90). It bounds the in-call pickup wait by a deadline measured from the start of `Enroll`, so time spent creating or reissuing the order counts against it. Before, the 55 s default pickup started only after the create, so Command failed the enrollment at its 60 s Workflow Step Run Timeout while the order went on at CERTInext. That invited a resubmit and a duplicate order. The pickup now shortens its waits, skips the delay after its last poll, and returns pending with one Information line when no further poll fits. Calls already in flight are never cut short, and `PickupRetries=0` still disables the pickup. Set it about 10 s below Command's Workflow Step Run Timeout if you raise that (V1 and V2).
- fix(enroll): The in-call pickup wait is now capped at 75 s (it was 180 s) for V1 and V2, inside Command's roughly 100 s enrollment-call timeout, so a pickup that used its whole budget is no longer abandoned by Command. The 55 s default (`PickupRetries` 5, `PickupDelay` 10) is unaffected.
- fix(sync): An order cancelled or rejected at CERTInext that the gateway still holds as pending is now emitted once as failed (V1 and V2). Both syncs skip cancelled and rejected orders, so such an order used to stay pending in the gateway indefinitely. The sync asks the gateway for the order's status first: an order it doesn't hold is still skipped, so no row is created for every cancelled order in the account, and an issued or revoked row is never changed. The sync summary gains `FailedPropagated`.
- fix(sync): Synced certificates now report the product name (for example `DV SSL`) as their `ProductID`, not CERTInext's product code (V1 and V2), so the gateway can match them to a configured template and Command imports them with one. The gateway matches `ProductID` exactly against the templates' product names, so a code such as `842` never matched, and certificates ordered outside Command arrived in Command with no template. The code is named through the account's own product catalog (code → product type → name), read once per sync pass; a code the catalog can't name, or a catalog that can't be read (one warning), keeps the code as before. The sync summary gains `ProductNames: Resolved=…, Unresolved=…`. This includes accounts that issue through SSL.com (product codes such as `1011`-`1020`). Certificates enrolled through Command keep the template Command recorded at enrollment.
- fix(dcv): Wildcard TXT records are published at the base domain and shared with the apex.
- fix(config): `ApiUrl` must use https (loopback hosts excepted), checked on save and at startup.
- fix(logging): Email addresses inside CA error text in logged response bodies (problem+json `detail`/`title`, `message`, V1 `errorMessage`) are masked unless `LogSensitiveRequestData` is on. Before, only the exception message was masked.
- fix(logging): Log redaction no longer leaks the rest of a value after an escaped quote, CERTInext error text has email addresses masked unless `LogSensitiveRequestData` is on, and `mailto:` and userinfo are masked in URI SANs in enrollment logs (V1 and V2).

## Chores
- chore(compat): The plugin targets both `net8.0` and `net10.0`.
- chore(v2): The V2 organization block's optional pre-vetting token serializes as the spec's `prevettingToken` (was `preVettingToken`). Nothing sets it yet, so requests are unchanged.

## Upgrade Notes

### Moving a connector from V1 to V2
- Orders placed under 1.x still sync after the switch to V2. Certificates that chain to eMudhra's emSign G1 root are losing browser trust (Chrome and Firefox for certificates logged after November 16, 2026; Apple for all of them from November 30, 2026); replace them by enrolling again through V2.
- V2 connectors require `SignerPlace`, and V2 OV/EV orders require `OrganizationNumber`.
- `DefaultProductCode` doesn't apply to V2 orders, and V2 sends `X-Product-Code` only when the template sets `ProductCode`. A template that needs a specific one of several matching catalog products must set `ProductCode`.
- V2 `ProductVariant` is derived from the selected product when unset.
- `SignerIp` (connector and template) is V1 only: V2 doesn't send `agreement.signerIp`, which the V2 spec's agreement schema doesn't define.
- V2 renewals place a new order and don't revoke the original. V2 SSL/TLS reissues go through the reissue endpoint and produce derived order ids such as `1984857369R001`, which aren't numeric. Scripts or reports that assume numeric `CARequestID`s need updating. Set `V2ReissueRevokePrevious` to `true` if a reissue should revoke the previous certificate.
- V2 revoke reasons CERTInext rejects are retried with a substitute (see Revocation Reason Codes in the README). `privilege-withdrawn`, which CERTInext no longer accepts for SSL/TLS, is sent first and falls back to `cessation-of-operation`.
- V2 `expired` orders are reported as issued, and revoking one is sent to the CA.
- On V2 accounts whose domains SSL.com validates, DCV publishes SSL.com's record name and value, not `DcvTxtRecordTemplate`. The DNS provider plugin must be able to write those names (for example `_pki-validation.<domain>`).

## Known Limitations
- OV and OV UCC order placement under V2 can exceed the fixed 120s request timeout, and the order may still be created.
- V1 `AuthMode=OAuth` isn't supported: the V1 API ignores the bearer token, so V1 needs an access key.
- Without a template `ProductCode`, the product CERTInext resolves depends on the account's catalog. Where several products match a variant, CERTInext may pick one that rejects a client CSR. Set `ProductCode` on the template to choose the product.
- On some accounts CERTInext rejects a request with a wildcard only in the SANs (CN `example.com`, SAN `*.example.com`) and no `ProductCode` with `EMS-1173 Invalid Additional Domain Names`. Set `ProductCode` on the template to the account's Wildcard UCC product code.
- For domains validated by SSL.com, DCV can publish only SSL.com's `dns-txt` option, because the DNS provider interface publishes TXT records only; a domain offered only `dns-cname` or `http-url` stays pending.
- Inline DCV during `Enroll` isn't bounded by `EnrollmentCallBudgetSeconds` (it has its own `DcvTimeoutMinutes`), so an enrollment that runs DCV inline can still outlast Command's Workflow Step Run Timeout (60 s by default). Command then records the enrollment as failed even though the order continues at CERTInext, and the certificate arrives through a later sync. Raise that Command setting if inline DCV is slow.

# 1.0.2

## Bug Fixes
- fix(sync): `Synchronize` and `GetSingleRecord` no longer send the gateway a revoked record without a certificate unless the gateway already stores that certificate. Such a record made the gateway's revoked-certificate search fail, which stopped every Command scan of the CA. A revoked order the gateway has without a certificate is now reported as failed; one the gateway has never seen is skipped. Rows already stored this way must be repaired in the gateway database.
- fix(sync): Incremental sync no longer re-downloads every issued or revoked order placed that day on every pass. An order the gateway already stores with the same status and its certificate is skipped; new orders, status changes and orders stored without a certificate are fetched as before. Full sync is unchanged. On a day with many orders, incremental passes previously made two API calls per order and could run longer than the sync interval.

## Documentation
- docs: Added steps for the change of issuing CA after eMudhra's exit from public TLS (SSL.com for InCommon members, Sectigo offered by eMudhra), with the emSign G1 distrust dates. No plugin change is needed; Command, gateway and orchestrator trust stores and the gateway's CA certificate need the new chain.

# 1.0.1

## Bug Fixes
- fix(enroll): Pickup now waits briefly and returns the issued certificate in-band when the CA issues fast, otherwise returning pending as before (`PickupRetries` default 5, `0` disables; `PickupDelay` default 10s).
- fix(enroll): SANs are now read from every key the gateway sends (including `dnsname`), and from the CSR when it sends none, so UCC certificates return all domains.
- fix(enroll): Renewal SANs now come from the renewal request (subject CN, request SANs or CSR), not the prior order.
- fix(enroll): Orders auto-approved by CERTInext before issuance completes now return pending; the next sync picks up the certificate.
- fix(enroll): Renewals now use the template's product code instead of always using `DefaultProductCode`.
- fix(enroll): A blank `RequestorName` or `SignerPlace` now sends the placeholders `Keyfactor Gateway` and `Gateway` instead of an empty subscriber agreement signer.
- fix(enroll): `SignerName`, `SignerPlace`, and `SignerIp` template parameters now override connector values for the subscriber agreement on new orders and renewals.
- fix(enroll): A `SignerIp` that is not a valid IP address now logs a Warning naming whether it came from the template or the connector; the value is still sent unchanged.
- fix(enroll): A Warning is now logged when `SignerName` or `SignerPlace` fall back to their placeholders, naming what to set.
- fix(enroll): `GroupNumber`, `AutoSecureWww`, and the technical contact now send in the correct request fields CERTInext reads.
- fix(enroll): Renewals no longer fail with `EMS-918: Additional Information cannot be empty`; the renewal order now sends `additionalInformation.remarks`.
- fix(enroll): Renewals now send the full order details (group, `AutoSecureWww`, technical contact, organization, remarks), matching a new enrollment.
- fix(enroll): A failed status check or DCV step after placing an order now returns pending with the order number so sync can finish the order and a retry cannot place a duplicate.
- fix(enroll): Non-DNS SANs (IP, email, URI) are now submitted instead of silently dropped; set `SubmitNonDnsSans` to `false` to restore the old behavior.
- fix(enroll): Order/CSR submissions no longer auto-retry after a timeout so a timeout cannot create a duplicate order; if the CA did create one, the next sync imports it.
- fix(enroll): `www.` is no longer added to orders by default because `AutoSecureWww` (default `0`) is now honored; set it to `1` to keep the old behavior.
- fix(enroll): Orders now route to the configured `GroupNumber`, which previously was not applied to orders.
- fix(enroll): Renewals now follow the connector's `SubscriptionAutoRenew`, `EmailNotifications`, and validity settings instead of fixed 1-year validity with auto-renew and notifications on.
- fix(enroll): The `ValidityYears` template parameter now takes effect, and the order term is the larger of `ValidityYears` and `ValidityDays` (rounded up to years) so templates saved with only `ValidityDays` keep their term.
- fix(enroll): The technical contact is omitted, with a Warning, when no contact name or email resolves, since CERTInext requires both once the block is sent.
- fix(logging): The V1 API error log line now reads `CERTInext API non-success. Operation=...` instead of `CERTInext API error during ...`; update any log alerts keyed on the old text.
- fix(dcv): A DV order that cannot issue (IP or email SAN, no DNS provider) now returns pending immediately; sync finishes the order.
- fix(dcv): A DV renewal waiting on DNS-01 validation now returns pending immediately instead of blocking a gateway worker for the pickup wait.
- fix(config): Connector and template validation no longer leaks an HTTP client per check.
- fix(sync): Sync holds back pending or issued orders created in the last 120 s (`SyncRecentOrderGraceSeconds`, `0` disables), making a duplicate-key failure on an in-flight enrollment's save much less likely; enrollments longer than about 2 minutes can still race.

## Chores
- chore(logging): Startup log now shows whether `OrganizationNumber`, `DefaultProductCode`, `GroupNumber`, `SubmitNonDnsSans`, and `LogSensitiveRequestData` are set, and warns when `LogSensitiveRequestData` is on.
- chore(config): Field descriptions and configuration docs now match the code for `DefaultProductCode`, `ValidityYears`, signer fallbacks, `LogSensitiveRequestData`, and the pickup clamps.
- chore(config): Corrected the `AutoApprove` template setting's description, which previously implied the plugin attempts automatic approval of pending certificates.
- chore(tests): Opt-in live sandbox test that renews through `plugin.Enroll(RenewOrReissue)` end to end (`CERTINEXT_RENEWAL_E2E=1`).

# 1.0.0

Initial release of the CERTInext (emSign Hub) AnyCA Gateway REST plugin.

## Features
- feat(enroll): Certificate enrollment for CERTInext SSL products — DV, OV, and EV SSL, including Wildcard and Multi-Domain (UCC) variants — with connector- and template-level overrides for product code, requestor identity, organization/group, and validity.
- feat(dcv): End-to-end DNS-01 domain validation for DV SSL through a pluggable `IDomainValidatorFactory` (Cloudflare provider included). Publishes the TXT challenge, asks CERTInext to verify, waits for issuance, and returns the issued certificate directly from `Enroll`. (DCV build, AnyCA Gateway 26.x; in 2.0.0 DCV is part of the default build.)
- feat(sync): Full and incremental CA synchronization via paginated `GetOrderReport`. Issued certificates carry their full PEM body; revoked certificates carry revocation metadata.
- feat(sync): Sync-driven DCV retry drives orders left pending validation to completion on later sync passes, bounded by configurable `DcvSyncMaxOrderAgeHours` and `DcvSyncMaxPerPass` caps so large accounts stay fast.
- feat(revoke): Certificate revocation via `RevokeOrder` with RFC 5280 reason-code mapping.
- feat(auth): AccessKey authentication (a SHA-256 `authKey`) and an OAuth client-credentials mode (not supported by the live V1 API; see 2.0.0).
- feat(build): Single `DcvSupport` MSBuild flag selects the host-matched build from one codebase — default no-DCV (IAnyCAPlugin `3.2.0`, AnyCA Gateway 25.5.x) or `-p:DcvSupport=true` for the DCV build (IAnyCAPlugin `3.3.0-PRERELEASE`, 26.x). Records persist only when the build matches the host's IAnyCAPlugin version. (In 2.0.0 the default is the DCV build.)
- feat(config): Connector-level configuration for pre-vetted organization/group/technical-contact injection, DCV timing knobs (challenge/issuance waits), and SSL order defaults.
- feat(sync): `IgnoreExpired` flag to exclude expired certificates from synchronization (not applied on V1 yet; see 2.0.0).

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

