# 2.0.0

## Features
- feat(v2): Opt-in CERTInext V2 REST API via `UseV2Api` (default `false`), authenticated with OAuth2 `client_credentials`.
- feat(v2): Enroll, renew, reissue, revoke, and synchronize SSL/TLS and Private PKI products, selected with the `ProductFamily` and `ProductVariant` template parameters.
- feat(v2): A template's `ProductCode` is validated against the V2 catalog when saved.
- feat(v2): Multi-domain (UCC) and wildcard SSL/TLS enrollment, with extra SANs sent as `additionalDomains`.
- feat(v2): Opt-in `V2InlineCsr` (default `false`) sends the CSR inline in one SSL/TLS create call instead of create + Submit CSR; Private PKI stays two-call.
- feat(v2): Synchronize reads `/reports/orders` and honors `IgnoreExpired`.
- feat(v2): Incremental syncs look back `V2SyncLookbackHours` (default 72).
- feat(dcv): DNS-01 domain validation for V2 SSL/TLS orders, including every SAN on a UCC order.
- feat(dcv): `DcvEnabled` now defaults to `true`; it needs a DNS provider plugin, or set it to `false`.
- feat(enroll): Quickly issued certificates return in the same `Enroll` call (`PickupRetries` default 5, `PickupDelay` default 10s).
- feat(config): New settings `RequestorDesignation`, `SubmitNonDnsSans`, `V2SyncLookbackHours`, and `LogSensitiveRequestData`.
- feat(config): V2 orders honor `GroupNumber`, `OrganizationNumber`, `TechnicalContact*`, `EmailNotifications`, and the subscription renewal settings.

## Bug Fixes
- fix(enroll): UCC certificates keep their SANs, read from every key the gateway sends or from the CSR.
- fix(enroll): Renewals keep their SANs and primary domain and use the template's product code.
- fix(enroll): An order auto-approved before it finishes issuing returns pending, not an issued result with no certificate.
- fix(dcv): Wildcard TXT records are published at the base domain and shared with the apex.
- fix(config): `ApiUrl` must use https (loopback hosts excepted), checked on save and at startup.
- fix(logging): Requestor personal data, email SANs, and request/response payloads are redacted unless `LogSensitiveRequestData` is on.
- fix(enroll): Order and CSR submissions are no longer auto-retried after a timeout, which could create duplicate orders.
- fix(sync): Sync holds back pending and issued orders created in the last 120 s (`SyncRecentOrderGraceSeconds`, `0` disables), so an in-flight enrollment no longer fails with a duplicate key.

## Chores
- chore(compat): Requires AnyCA Gateway REST 26.2.0 or later; built against `IAnyCAPlugin` 3.3.0 with DNS-01 DCV included.
- chore(compat): The plugin targets both `net8.0` and `net10.0`.

## Upgrade Notes
- AnyCA Gateway REST 25.5.x isn't supported; upgrade the gateway to 26.2.0 or later (Command 25.5 or later works with it).
- `DcvEnabled` now defaults to `true`, so without a DNS provider plugin, orders needing validation stay pending; set it to `false` if you validate domains another way.
- Connectors saved with an `http` `ApiUrl` fail to start until the URL uses https.
- V2 templates with only `ProductId` need `ProductCode` or `DefaultProductCode` when the catalog has several matching products.
- V2 connectors require `SignerPlace`, and V2 OV/EV orders require `OrganizationNumber`.
- V2 `ProductVariant` is derived from the selected product when unset.
- V2 revoke reasons CERTInext rejects are retried with a substitute (see Revocation Reason Codes in the README).
- V2 `expired` orders are reported as issued, and revoking one is sent to the CA.
- V2 renew and reissue place a new order and don't revoke the original.
- V1 now submits non-DNS SANs; set `SubmitNonDnsSans` to `false` to drop them.

## Known Limitations
- OV and OV UCC order placement under V2 can exceed the fixed 120s request timeout, and the order may still be created.
- EV orders under V2 aren't validated end to end.
- Document Signer (`ProductFamily=signature`) enrollment isn't supported under V2.
- Per-SAN DCV on UCC orders, DCV for a never-validated domain, and wildcard DCV aren't validated end to end against the CA.
- Rolling a connector back to V1 after it has issued V2 certificates isn't validated.
- V1 `IgnoreExpired` isn't applied yet; it works on V2.
- V1 `AuthMode=OAuth` isn't supported: the live V1 API ignores the bearer token, so V1 needs an access key.

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

