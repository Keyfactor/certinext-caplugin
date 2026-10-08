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
- fix(enroll): Renewals now send the full order details (group, `AutoSecureWww`, technical contact, organization, remarks), matching a new enrollment.
- fix(enroll): A failed status check or DCV step after placing an order now returns pending with the order number so sync can finish the order and a retry cannot place a duplicate.
- fix(enroll): Non-DNS SANs (IP, email, URI) are now submitted instead of silently dropped; set `SubmitNonDnsSans` to `false` to restore the old behavior.
- fix(enroll): Order/CSR submissions no longer auto-retry after a timeout so a timeout cannot create a duplicate order; if the CA did create one, the next sync imports it.
- fix(enroll): `www.` is no longer added to orders by default because `AutoSecureWww` (default `0`) is now honored; set it to `1` to keep the old behavior.
- fix(enroll): Orders now route to the configured `GroupNumber`, which previously was not applied to orders.
- fix(enroll): Renewals now follow the connector's `SubscriptionAutoRenew`, `EmailNotifications`, and validity settings instead of fixed 1-year validity with auto-renew and notifications on.
- fix(enroll): The `ValidityYears` template parameter now takes effect and wins over `ValidityDays`, so templates with `ValidityYears` 2 or 3 order multi-year subscriptions, and a template value overrides `SubscriptionValidityYears`.
- fix(enroll): The technical contact is omitted, with a Warning, when no contact name or email resolves, since CERTInext requires both once the block is sent.
- fix(logging): The V1 API error log line now reads `CERTInext API non-success. Operation=...` instead of `CERTInext API error during ...`; update any log alerts keyed on the old text.
- fix(dcv): A DV order that cannot issue (IP or email SAN, no DNS provider) now returns pending immediately; sync finishes the order.
- fix(dcv): A DV renewal waiting on DNS-01 validation now returns pending immediately instead of blocking a gateway worker for the pickup wait.
- fix(config): Connector and template validation no longer leaks an HTTP client per check.

## Chores
- chore(logging): Startup log now shows whether `OrganizationNumber`, `DefaultProductCode`, `GroupNumber`, `SubmitNonDnsSans`, and `LogSensitiveRequestData` are set, and warns when `LogSensitiveRequestData` is on.
- chore(config): Field descriptions and configuration docs now match the code for `DefaultProductCode`, `ValidityYears`, signer fallbacks, `LogSensitiveRequestData`, and the pickup clamps.
- chore(config): Corrected the `AutoApprove` template setting's description, which previously implied the plugin attempts automatic approval of pending certificates.

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

