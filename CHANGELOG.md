# 1.1.0

## Features
- feat(dcv): Support DNS CNAME-delegated DCV challenges — when a validation hostname is CNAMEd to a separate zone (e.g. to keep automation credentials out of the production zone), the plugin now follows the chain and routes both the TXT record and the DNS provider lookup to the terminal name. Off by default; opt in with the new `DcvFollowCnameDelegation` setting.
- feat(dcv): When DCV is enabled but no DNS provider plugin is configured, the enrollment result now surfaces the exact TXT record name and value to publish manually, instead of leaving the order pending with no guidance beyond the plugin log.

## Bug Fixes
- fix(enroll): The per-template `ValidityYears` parameter now actually controls subscription validity. Previously it was exposed in Command's UI but silently ignored, with the connector-level default always winning.

## Build
- build!: Target `net10.0` only — dropped `net8.0` multi-targeting across the plugin, tests, and integration runner.
- build!: `DcvSupport` now defaults to `true`. The default/CI-shipped build targets DCV-capable AnyCA Gateway 26.x (`IAnyCAPlugin 3.3.0`, now stable); the previous default — `IAnyCAPlugin 3.2.0`, AnyCA Gateway 25.5.x, no DCV — is available via `-p:DcvSupport=false`.
- chore(deps): Added `DnsClient.NET` for CNAME resolution. Pinned `WireMock.Net` and its transitive `Scriban.Signed` / `System.Linq.Dynamic.Core` / `OpenTelemetry.*` dependencies past several CVEs that only surfaced once `net10.0` became the sole restore target.

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

