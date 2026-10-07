# 1.0.1

## Features
- **Faster enrollment for quickly-issued certificates.** Enrollment now waits briefly and returns the certificate in the same call when it issues fast, otherwise returning pending as before (`PickupRetries` default 5, `0` disables; `PickupDelay` default 10s).

## Bug Fixes
- **UCC certificates no longer come back with only the common name.** SANs are now read from every key the gateway sends (including `dnsname`), and from the CSR when it sends none.
- **Renewals no longer lose their SANs.** The primary domain and SANs now come from the renewal request (subject CN, request SANs or CSR), not the prior order.
- **Enrollment no longer fails on an order CERTInext auto-approves before it finishes issuing.** It now returns pending and the next sync picks up the certificate.
- **Renewals now use the template's product code** instead of always using `DefaultProductCode`.
- **A blank `RequestorName` or `SignerPlace` no longer sends an empty agreement signer.** The placeholders `Keyfactor Gateway` and `Gateway` are sent instead.
- **The `SignerName`, `SignerPlace`, and `SignerIp` template parameters now take effect.** They were accepted but ignored; they now override the connector values for the subscriber agreement on both new orders and renewals.
- **A `SignerIp` that isn't an IP address now logs a Warning** naming whether it came from the template or the connector; the value is still sent unchanged and enrollment is never blocked.
- **A Warning is now logged when `SignerName` or `SignerPlace` fall back to their placeholders**, naming what to set (`SignerIp` already warned on its `127.0.0.1` fallback).
- **`GroupNumber`, `AutoSecureWww`, and the technical contact now reach CERTInext**; they were previously sent in fields CERTInext doesn't read.
- **Renewals now send the full order details** (group, `AutoSecureWww`, technical contact, organization, remarks), the same as a new enrollment.
- **Unexpected CERTInext error responses are now diagnosable from the logs.** Non-2xx responses with an unrecognised body include the HTTP status and log the redacted body.
- **Gateway logs no longer contain the `authKey` or requestor personal data by default**; set `LogSensitiveRequestData` to log PII temporarily (credentials stay redacted).
- **Log redaction no longer leaks the rest of a value after an escaped quote** (e.g. `"authKey":"ab\"cd"`, `"requestorName":"Jane \"JD\" Doe"`).
- **CERTInext error text in logs and error messages now has email addresses masked** unless `LogSensitiveRequestData` is set.
- **URI SANs in enrollment logs no longer leak personal data by default.** `mailto:` addresses are masked and `user:pw@` userinfo is replaced with `***` unless `LogSensitiveRequestData` is set.
- **Enrollment and renewal no longer fail after the order is placed.** A failed status check or DCV step now returns pending with the order number, so sync finishes the order and a retry can't place a duplicate.
- **Enrollment no longer waits for issuance on a DV order that cannot issue** (e.g. an IP or email SAN with no DNS provider); it returns pending and sync finishes the order.
- **With DCV enabled, a renewal waiting on DNS-01 validation now returns pending at once** instead of holding a gateway worker for the pickup wait.
- **Connector and template validation no longer leaks an HTTP client per check.**

## Chores
- **The startup log now shows whether `OrganizationNumber`, `DefaultProductCode`, and `GroupNumber` are set, plus `SubmitNonDnsSans` and `LogSensitiveRequestData`**, and logs a Warning when `LogSensitiveRequestData` is on.
- **Configuration docs and field descriptions now match the code**, including `DefaultProductCode`, `ValidityYears`, the signer fallbacks, `LogSensitiveRequestData`, and the pickup clamps.
- **Corrected the `AutoApprove` template setting's description.** It previously implied the plugin would attempt automatic approval of pending certificates; it does not currently do this.

## Upgrade Notes
- **Non-DNS SANs (IP, email, URI) are now submitted instead of silently dropped**, so such an order won't issue until they are removed; set `SubmitNonDnsSans` to `false` to restore the old behavior.
- **Order/CSR submissions no longer auto-retry after a timeout**, so a timeout can't create a duplicate order; if the CA did create one, the next sync imports it.
- **`www.` is no longer added to orders by default**, because `AutoSecureWww` (default `0`) is now honored; set it to `1` to keep the old behavior.
- **Orders now route to the configured `GroupNumber`**, which previously was not applied to orders.
- **Renewals follow the connector's `SubscriptionAutoRenew`, `EmailNotifications`, and validity settings** instead of fixed 1-year validity with auto-renew and notifications on.
- **The `ValidityYears` template parameter now takes effect and wins over `ValidityDays`**, so templates with `ValidityYears` 2 or 3 now order multi-year subscriptions, and a template value overrides `SubscriptionValidityYears`.
- **The technical contact is omitted, with a Warning, when no contact name or email resolves**, since CERTInext requires both once the block is sent.
- **The V1 API error log line now reads `CERTInext API non-success. Operation=...`** instead of `CERTInext API error during ...`; update any log alerts keyed on the old text.

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

