# 2.0.0

## Features
- feat(v2): Opt-in CERTInext V2 REST API via `UseV2Api` (default `false`; V1 is unchanged), authenticating with OAuth2 `client_credentials` through the existing `ApiUrl`/`OAuthClientId`/`OAuthClientSecret` settings. V1 credentials are not needed in V2 mode.
- feat(v2): Enroll, renew, reissue, revoke, and synchronize SSL/TLS and Private PKI products under V2, selected with the `ProductFamily` and `ProductVariant` template parameters; a template's `ProductCode` is validated against the V2 catalog when saved.
- feat(v2): Multi-domain (UCC) and wildcard SSL/TLS enrollment under V2, with additional SANs sent as `additionalDomains`.
- feat(dcv): DNS-01 domain validation for V2 SSL/TLS orders, including every SAN on a UCC order.
- feat(dcv): DCV is on by default (`DcvEnabled` defaults to `true`); it needs a DNS provider plugin deployed on the gateway.
- feat(v2): Synchronize reads V2 `/reports/orders`; incremental syncs look back `V2SyncLookbackHours` (default 72) and honor `IgnoreExpired`.
- feat(enroll): Quickly-issued certificates are returned in the same `Enroll` call. Tune with `PickupRetries` (default 5, `0` disables) and `PickupDelay` (default 10s); slower orders stay pending and are picked up by the next sync.
- feat(config): New settings `RequestorDesignation`, `SubmitNonDnsSans`, `V2SyncLookbackHours`, and `LogSensitiveRequestData`.
- feat(config): V2 orders honor `GroupNumber`, `OrganizationNumber` (required for OV/EV), the `TechnicalContact*` fields, `SubscriptionAutoRenew`/`SubscriptionRenewCriteriaDays`, and `EmailNotifications`.

## Bug Fixes
- fix(enroll): UCC certificates no longer come back with only the common name; SANs are read from every key the gateway sends (including `dnsname`), and from the CSR when the gateway sends none.
- fix(enroll): Renewals keep their SANs and primary domain, and use the template's product code (falling back to `DefaultProductCode`).
- fix(enroll): An order CERTInext auto-approves before it finishes issuing now returns pending instead of an issued result with no certificate.
- fix(dcv): Wildcard domains publish their TXT record at the base domain instead of a literal `*.` label, and a wildcard and its apex share one record.
- fix(config): `ApiUrl` and, for V1 OAuth, `OAuthTokenUrl` must use https (http is allowed only for loopback hosts), enforced on save and at startup, so existing http connectors fail to start.
- fix(logging): Requestor personal data, email SANs, and full request/response payloads are redacted from gateway logs unless `LogSensitiveRequestData` is enabled.
- fix(enroll): Order and CSR submissions are no longer auto-retried after a timeout, which could create duplicate orders; if the CA did create the order, the next sync imports it.

## Chores
- chore(compat): Requires AnyCA Gateway REST framework 26.2.0 or later; the plugin is built against `IAnyCAPlugin` 3.3.0 with DNS-01 DCV included.

## Upgrade Notes
- AnyCA Gateway REST 25.5.x is not supported; upgrade the gateway to 26.2.0 or later before installing 2.0.0.
- `DcvEnabled` now defaults to `true` for connectors that don't already store a value. It needs a DNS provider plugin on the gateway; without one, orders that need domain validation stay pending and the plugin logs why. Set `DcvEnabled` to `false` if you validate domains another way.
- V2 templates with only `ProductId` need `ProductCode` or the connector's `DefaultProductCode` when the catalog has several products of that type; otherwise enrollment fails and lists the candidates.
- V2 connectors require `SignerPlace`, and V2 OV/EV orders require `OrganizationNumber`; `ProductVariant` is derived from the selected product when unset.
- V2 revoke reasons CERTInext rejects are substituted: CA/AA compromise becomes key-compromise, and unspecified/certificate-hold become cessation-of-operation.
- V2 `expired` orders are reported as issued, and revoking one is sent to the CA.
- V2 renew and reissue place a new order; the original order is not revoked.
- V1 connectors now submit non-DNS SANs (IP, email, URI) instead of dropping them, so such an order won't issue until the SAN is removed; set `SubmitNonDnsSans` to `false` to drop them as before.

## Known Limitations
- OV and OV UCC order placement under V2 can exceed the plugin's fixed 120s request timeout; the order may still be created on the CA and is imported by the next sync. EV orders under V2 are not validated end to end.
- Document Signer (`ProductFamily=signature`) enrollment is not supported under V2.
- Per-SAN DCV on UCC orders, DCV for a domain that has never been validated, and wildcard DCV are not validated end to end against the CA.
- Rolling a connector back to V1 after it has issued V2 certificates is not validated.

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

