# 1.0.1

## Features
- **Faster enrollment for quickly-issued certificates.** Enrollment now waits briefly and returns the certificate in the same request when it issues fast, instead of always waiting for the next sync. Configurable via `PickupRetries` (default 5, `0` disables) and `PickupDelay` (default 10s). Orders that don't issue in time (e.g. OV/EV) return pending and are picked up by the next sync, as before.

## Bug Fixes
- **UCC certificates no longer come back with only the common name.** The gateway sends SANs under the key `dnsname`, which the plugin didn't recognize, so orders went out with an empty domain list. SANs are now read from every key the gateway sends, plus from the CSR itself.
- **Renewals no longer lose their SANs.** Renewals were submitted with no additional domains and the wrong primary domain; both now come from the certificate being renewed.
- **Enrollment no longer fails on an order CERTInext auto-approves before it finishes issuing.** The plugin used to report these as issued with no certificate attached, which the gateway rejected. It now returns pending and picks up the certificate once CERTInext finishes issuing it.

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

