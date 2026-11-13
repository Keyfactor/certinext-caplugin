# 2.0.0

## Features
- feat(v2): Opt-in CERTInext V2 REST API via `UseV2Api` (default `false`), authenticated with OAuth2 `client_credentials`.
- feat(v2): Enroll, renew, reissue, revoke, and synchronize SSL/TLS and Private PKI products, selected with the `ProductFamily` and `ProductVariant` template parameters.
- feat(v2): A template's `ProductCode` is validated against the V2 catalog when saved.
- feat(v2): Multi-domain (UCC) and wildcard SSL/TLS enrollment, with extra SANs sent as `additionalDomains`.
- feat(v2): V2 OV and EV SSL/TLS orders check the organization's SSL.com validation first (status read, one refresh, and an optional submission). New settings `SslComSubmitOrganization` (default `false`; enabling it accepts SSL.com's subscriber agreement on the organization's behalf, audit-logged) and `SslComAdminEmail`. A not-validated organization or a failed SSL.com call only warns, and the order is placed anyway.
- feat(v2): An SSL/TLS order that Track Order shows at `pending-agreement` gets the Subscriber Agreement accepted via `POST /ssl-certificates/{orderId}/agreement`, using the same signer values as create: at most once per order per enroll call or sync pass, audit-logged first, and a failure only warns.
- feat(v2): The create call no longer sends `X-Product-Code` unless the template sets `ProductCode` (SSL/TLS and Private PKI): CERTInext resolves the product from the variant, wildcard shape and `additionalDomains`, and the response's `resolvedProductCode` is logged. An ambiguous catalog match is no longer an error, Private PKI no longer needs `ProductCode`, and without one a wildcard is detected from the `*.` domain and a UCC order from the template's product or extra DNS SANs.
- feat(v2): V2 SSL/TLS enrollment sends the CSR inline in one create call (`V2InlineCsr`, default `true`). Setting it to `false` selects create + Submit CSR, which fails for a domain the account has already validated; Private PKI stays two-call.
- feat(v2): An SSL/TLS reissue (`Reissue`, or `RenewOrReissue` outside `RenewalWindowDays`) calls `POST /ssl-certificates/{orderId}/reissue` in `rekey` mode with the new CSR, and the derived order (for example `1984857369R001`) becomes the new `CARequestID`. New setting `V2ReissueRevokePrevious` (default `false`) also revokes the previous certificate as `superseded`, audit-logged first. A missing prior order or a 404/422 places a new order instead and says so; a 5xx or lost response fails with "do not resubmit". Not verified live: the sandbox no longer generates certificates.
- feat(v2): Synchronize reads `/reports/orders` and honors `IgnoreExpired`.
- feat(v2): Incremental syncs look back `V2SyncLookbackHours` (default 72).
- feat(dcv): DNS-01 domain validation for V2 SSL/TLS orders, including every SAN on a UCC order.
- feat(dcv): V2 DCV for domains SSL.com validates: the plugin looks each pending domain up (`GET /domains`) and, for `validatedBy: SSLCOM`, publishes SSL.com's own `dns-txt` record from `GET /domains/{id}/dcv` (not `DcvTxtRecordTemplate`) and verifies it with `POST /domains/{id}/dcv/verify`. SSL.com outages (502), `UNDER_REVIEW`/`PENDING` results, and domains with no `dns-txt` option leave the order pending for the next sync; emSign domains keep the order-level flow.
- feat(dcv): `DcvEnabled` now defaults to `true`; it needs a DNS provider plugin, or set it to `false`.
- feat(enroll): V2 orders also return a quickly issued certificate in the same `Enroll` call, using the `PickupRetries` and `PickupDelay` settings V1 gained in 1.0.1.
- feat(config): New settings `RequestorDesignation` and `V2SyncLookbackHours`.
- feat(config): V2 orders honor `GroupNumber`, `OrganizationNumber`, `TechnicalContact*`, `EmailNotifications`, and the subscription renewal settings.

## Bug Fixes
- fix(v2): A 422 `EMS-1165` from Download Certificate on an order CERTInext reports as `issued` is treated as "certificate not generated yet": the enrollment pickup keeps polling and returns pending, logging per attempt at Debug and one Information summary instead of a warning each time. `GetSingleRecord` and Synchronize log it quietly too (the sync summary gains `IssuedNotGeneratedYet`), and the log lines include CERTInext's `orderState` and `certificateState`. Other download errors still warn.
- fix(v2): `EmailNotifications=0` (silent) is sent as `consent-only` on V2 order create, the quietest value in the spec's `consent-only | all` enum; the old `"0"` isn't a member of it.
- fix(v2): Order create no longer sends `agreement.signerIp`, which isn't in the V2 spec's `Agreement` schema; the `SignerIp` settings now apply to V1 only.
- fix(enroll): V2 UCC and renewal orders keep their SANs and primary domain, and renewals use the template's product code, as V1 does from 1.0.1.
- fix(enroll): A V2 order auto-approved before it finishes issuing returns pending, not an issued result with no certificate.
- fix(dcv): Wildcard TXT records are published at the base domain and shared with the apex.
- fix(config): `ApiUrl` must use https (loopback hosts excepted), checked on save and at startup.
- fix(logging): V2 requestor personal data, email SANs, and request/response payloads are redacted unless `LogSensitiveRequestData` is on.
- fix(logging): Email addresses in CERTInext V2 error text (the problem+json `title`, `detail`, and `errors[]` that end up in exception messages and logs) are masked unless `LogSensitiveRequestData` is on, as V1 error text is.
- fix(logging): V2 payload dumps no longer run redaction when Trace logging is off.
- fix(enroll): V2 order and CSR submissions are never auto-retried after a timeout, which could create duplicate orders (V1 since 1.0.1).
- fix(v2): A V2 OAuth2 token request that gets no HTTP response (a dropped connection or other transport error) is retried twice, after 1 s and 3 s, so one network blip no longer fails an enrollment, a sync or a connector save. HTTP errors (400/401/403) are not retried, and order creates are still never retried. Token failures and other V2 calls with no response now log the transport detail (`TransportDetail=`: RestSharp's response status and the exception types and messages, with credentials removed) and include a short form in the error, instead of only `HttpStatus=0`.
- fix(sync): The V2 sync also holds back pending and issued orders created in the last 120 s (`SyncRecentOrderGraceSeconds`, `0` disables), so an in-flight enrollment no longer fails with a duplicate key (V1 since 1.0.1).
- fix(enroll): The in-call pickup wait is now capped at 75 s (it was 180 s) for V1 and V2, inside Command's roughly 100 s enrollment-call timeout, so a pickup that used its whole budget is no longer abandoned by Command. The 55 s default (`PickupRetries` 5, `PickupDelay` 10) is unaffected.
- fix(logging): Log redaction no longer leaks the rest of a value after an escaped quote, CERTInext error text has email addresses masked unless `LogSensitiveRequestData` is on, and `mailto:` and userinfo are masked in URI SANs in enrollment logs (V1 and V2).

## Chores
- chore(compat): Requires AnyCA Gateway REST 26.2.0 or later; built against `IAnyCAPlugin` 3.3.0 with DNS-01 DCV included.
- chore(compat): The plugin targets both `net8.0` and `net10.0`.
- chore(v2): The V2 organization block's optional pre-vetting token serializes as the spec's `prevettingToken` (was `preVettingToken`). Nothing sets it yet, so requests are unchanged.

## Upgrade Notes
- AnyCA Gateway REST 25.5.x isn't supported; upgrade the gateway to 26.2.0 or later (Command 25.5 or later works with it).
- `DcvEnabled` now defaults to `true`, so without a DNS provider plugin, orders needing validation stay pending; set it to `false` if you validate domains another way.
- Connectors saved with an `http` `ApiUrl` fail to start until the URL uses https.
- V2 no longer sends `X-Product-Code` unless the template sets `ProductCode`, and `DefaultProductCode` no longer applies to V2 orders. A template that needs a specific one of several matching catalog products must set `ProductCode`.
- V2 connectors require `SignerPlace`, and V2 OV/EV orders require `OrganizationNumber`.
- `V2InlineCsr` now defaults to `true`. A connector that already has `V2InlineCsr = false` saved, as connectors created with an earlier 2.0 build do, keeps the two-call flow, which fails for already-validated domains. Set it to `true` on those connectors.
- `SignerIp` (connector and template) is V1 only: V2 no longer sends `agreement.signerIp`, which the V2 spec's agreement schema doesn't define.
- V2 `ProductVariant` is derived from the selected product when unset.
- V2 revoke reasons CERTInext rejects are retried with a substitute (see Revocation Reason Codes in the README). `privilege-withdrawn`, which the 2.0.0 V2 spec dropped from the SSL/TLS enum and CERTInext rejected live on 2026-11-13, is still sent first and now falls back to `cessation-of-operation`. The retry also recognizes CERTInext's newer 422 wording, "Revocation reason {reason} is not allowed."
- V2 `expired` orders are reported as issued, and revoking one is sent to the CA.
- V2 renewals place a new order and don't revoke the original. V2 SSL/TLS reissues now go through the reissue endpoint and produce derived order ids such as `1984857369R001`, which aren't numeric. Scripts or reports that assume numeric `CARequestID`s need updating. Set `V2ReissueRevokePrevious` to `true` if a reissue should revoke the previous certificate.
- On V2 accounts whose domains SSL.com validates, DCV now publishes SSL.com's record name and value, not `DcvTxtRecordTemplate`. The DNS provider plugin must be able to write those names (for example `_pki-validation.<domain>`).
- Upgrading from 1.0.0 also brings the changes in 1.0.1 and 1.0.2 above. For example, V1 now submits non-DNS SANs; set `SubmitNonDnsSans` to `false` to drop them.

## Known Limitations
- OV and OV UCC order placement under V2 can exceed the fixed 120s request timeout, and the order may still be created.
- EV orders under V2 aren't validated end to end.
- Document Signer (`ProductFamily=signature`) enrollment isn't supported under V2.
- Per-SAN DCV on UCC orders, DCV for a never-validated domain, and wildcard DCV aren't validated end to end against the CA.
- Rolling a connector back to V1 after it has issued V2 certificates isn't validated.
- V2 SSL/TLS reissue through the reissue endpoint isn't verified live (the sandbox stopped generating certificates), and it always uses `rekey`, never `update-sans`.
- V1 `IgnoreExpired` isn't applied yet; it works on V2.
- V1 `AuthMode=OAuth` isn't supported: the live V1 API ignores the bearer token, so V1 needs an access key.
- The V2 incremental sync doesn't yet skip orders the gateway already holds unchanged, as the V1 incremental sync does from 1.0.2, so it re-reads each order listed.
- Without a template `ProductCode`, the product CERTInext resolves depends on the account's catalog. Where several products match a variant, CERTInext may pick one that rejects a client CSR. On the sandbox, plain DV resolves to `917` "SSL DV 1 month" instead of `842`. Set `ProductCode` on the template to choose the product.
- DCV for domains validated by SSL.com is built from the V2 spec and unit-tested but not verified live (the sandbox has no SSL.com-validated domains). Only SSL.com's `dns-txt` option can be published, because the DNS provider interface publishes TXT records only; a domain offered only `dns-cname` or `http-url` stays pending.
- Command's enrollment workflow can give up at 60 s, before the 75 s pickup ceiling. When it does, Command records the enrollment as failed even though the order continues at CERTInext, so the certificate can only arrive through a later sync.

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

