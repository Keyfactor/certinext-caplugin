## Developer Guide

This document covers local development, testing, and live API smoke-testing for the CERTInext AnyCA Gateway REST plugin. For production deployment and CA connector configuration, see [configuration.md](configuration.md).

## Prerequisites

| Tool | Used for |
|---|---|
| .NET 10 SDK | Building the solution. The plugin multi-targets `net8.0` and `net10.0`. |
| .NET 8 runtime | Running the unit and integration test projects, which target `net8.0`. |
| `bash`, `curl` | The API smoke-test scripts under `scripts/` |
| `python3` | The scripts compute the SHA-256 `authKey`, random transaction IDs, and V2 idempotency UUIDs with it. |
| `jq` | Pretty-printing JSON in the scripts |
| `openssl` | `make generate-test-csr` and the CSR helper scripts |
| `~/.env_certinext` | Credentials for the V1 targets and tests (see below). The V2 targets and tests also need `~/.env_certinext_v2`. |

## Credential Files

Both files hold `KEY=VALUE` lines and are **never committed**. Keep them in `$HOME`, or add them to your global `.gitignore`. The tests and runner let real environment variables override values in `~/.env_certinext`; the scripts source the file, so the file wins there.

| File | API | Contents |
|---|---|---|
| `~/.env_certinext` | V1 | Access key, account number, and the V1 `emSignHub-API` URL |
| `~/.env_certinext_v2` | V2 | OAuth client ID and secret, and the bare V2 host URL |

Set `CERTINEXT_V2_ENV_FILE` to point the `v2-*` Makefile targets at a different V2 file. The V2 integration tests always read `~/.env_certinext_v2`.

| Variable | `~/.env_certinext` (V1) | `~/.env_certinext_v2` | Used by |
|---|---|---|---|
| `CERTINEXT_API_URL` | `https://sandbox-us-api.certinext.io/emSignHub-API` (scripts append `/<Endpoint>`) | `https://sandbox-us-api.certinext.io` (V2 host, no path) | All scripts, tests, and the runner |
| `CERTINEXT_ACCESS_KEY` | Access key from Integrations → APIs | n/a | V1 scripts, tests, runner |
| `CERTINEXT_ACCOUNT_NUMBER` | Numeric account ID from the account profile | n/a | V1 scripts, tests, runner |
| `CERTINEXT_GROUP_NUMBER` | Group number from the credential row | n/a | V1 scripts, tests, runner |
| `CERTINEXT_ORG_NUMBER` | Organization ID, for OV and EV orders | n/a | V1 and V2 OV/EV tests |
| `CERTINEXT_PRODUCT_CODE` | Default product code for `generate-order` (for example `838`) | V2 product code | Scripts and tests |
| `CERTINEXT_REQUESTOR_EMAIL` | Email on your CERTInext account | n/a | Scripts, tests, runner |
| `CERTINEXT_REQUESTOR_NAME` | Requestor or automation account name | n/a | Scripts, tests, runner |
| `CERTINEXT_REQUESTOR_MOBILE` | Digits only, no country code | n/a | `generate-order` |
| `CERTINEXT_SIGNER_IP` | Public IP of this machine; blank auto-detects via `api.ipify.org` | n/a | `generate-order` |
| `CERTINEXT_CLIENT_ID` | n/a | OAuth client ID | V2 targets and tests |
| `CERTINEXT_CLIENT_SECRET` | n/a | OAuth client secret | V2 targets and tests |
| `CERTINEXT_USE_V2_API` | n/a | `1` enables the V2 integration tests | V2 tests |
| `CERTINEXT_CF_API_TOKEN` | Cloudflare token with DNS:Edit on the zone | n/a | DCV tests (both API generations) |
| `CERTINEXT_CF_ZONE_ID` | Cloudflare zone ID | n/a | DCV tests |
| `CERTINEXT_DCV_DOMAIN` | Domain in that zone used by the DCV tests | n/a | DCV tests |
| `CERTINEXT_ORDER_ID` | Existing V1 order for the order-lookup smoke tests | n/a | `SmokeTests` |
| `CERTINEXT_V2_ORDER_ID` | n/a | Existing V2 order for the V2 lifecycle tests | `V2LifecycleTests` |
| `CERTINEXT_TEST_ORDER_NUMBER` | Order for the runner to track | n/a | `CERTInext.IntegrationRunner` |

> **Note:** `CERTINEXT_GROUP_NUMBER` and `CERTINEXT_ORG_NUMBER` are distinct. The group number is the delegation unit (cost center or department) used in every order request. The org number is the validated organization record used for OV and EV orders.

The V2 file reuses the key names `CERTINEXT_API_URL` and `CERTINEXT_PRODUCT_CODE` with V2 values. Source only `~/.env_certinext` into your shell, never the V2 file; the V2 tests read it from disk themselves. For the V2 helper scripts, see [scripts/v2/README.md](../scripts/v2/README.md).

### Opt-in flags

Tests that place real orders, publish DNS records, or cancel orders run only when you export the matching flag in your shell. The test fixture deliberately ignores these flags in both env files, so a flag left in a file can't arm every run.

| Flag | Arms |
|---|---|
| `CERTINEXT_COMPLETE_PENDING` | Complete every pending DV order (needs Cloudflare) |
| `CERTINEXT_RUN_BULK_TEST`, `CERTINEXT_V2_RUN_BULK_TEST` | V1 and V2 bulk enrollment and pagination tests |
| `CERTINEXT_PRIVATE_PKI_LIVE` | One live Private PKI order and revoke |
| `CERTINEXT_V2_OPS_TESTS` | V2 order-window sweep (maintenance tool) |
| `CERTINEXT_V2_LIFECYCLE_DV_UCC`, `_OV`, `_OV_UCC`, `_EV`, `_WILDCARD_DV`, `_RENEW_REISSUE`, `_FRESH_DCV` | The matching V2 full-lifecycle test |
| `CERTINEXT_V2_LIFECYCLE_REISSUE_ENDPOINT` (plus `CERTINEXT_V2_REISSUE_SOURCE_ORDER_ID`) | One reissue of an issued order through `/reissue`; creates a derived order and cleans it up |
| `CERTINEXT_V2_SSLCOM_DCV_PROBE`, `CERTINEXT_V2_UNRESOLVED_STATUS_PROBE` | Read-only probes: SSL.com domain lookup and DCV shape; report status pairs the sync can't map |
| `CERTINEXT_V2_REVOKE_PRIVILEGE_WITHDRAWN` | Places its own DV order and revokes it with `privilege-withdrawn` |

Set each to `1`. [INTEGRATION_TESTING.md](../CERTInext.IntegrationTests/INTEGRATION_TESTING.md) lists the remaining flags, such as the algorithm matrices, and the extra variables each test needs. To load `~/.env_certinext` into a shell that also exports a flag, use `set -a; . ~/.env_certinext; set +a`.

## Build and Test Targets

| Target | Command | Description |
|---|---|---|
| Build | `make build` | `dotnet build` the solution |
| All tests | `make test` | `dotnet test` the whole solution, **including the live integration tests** (they skip when credentials are absent) |
| Unit tests only | `dotnet test CERTInext.Tests/` | Mock and contract tests with no external services |
| Integration tests | `make integration-test` | Live API tests only (requires the env files; tests skip automatically when credentials are absent) |
| Coverage report (terminal) | `make coverage` | Run the solution's tests with XPlat coverage and print a summary |
| Coverage report (browser) | `make coverage-report` | Same as `coverage`, then opens the HTML report with macOS `open` (on Linux, open `/tmp/certinext-coverage-report/index.html` yourself) |
| Clean | `make clean` | `dotnet clean` and wipe coverage output directories |

## DCV Build and Code Layout

DNS-01 domain control validation (DCV) is part of the standard build. For how the flow behaves, see [Domain Control Validation](architecture.md#domain-control-validation); for the connector settings, see the `Dcv*` rows in [configuration.md](configuration.md#ca-configuration).

### Build

- **Package and gateway.** The plugin compiles against `Keyfactor.AnyGateway.IAnyCAPlugin` **3.3.0**, which provides `IDomainValidatorFactory`, and targets AnyCA Gateway REST **26.2.0** and later.
- **One MSBuild property.** `CERTInext/CERTInext.csproj` sets `DcvSupport` to `true` by default. It selects the IAnyCAPlugin package version, defines the `SUPPORTS_DCV` compile constant, and includes the DCV test files in the test projects. Plain `dotnet build` and `make build` produce the DCV build, and release builds use the same default.
- **Test projects mirror it.** `CERTInext.Tests/CERTInext.Tests.csproj` and `CERTInext.IntegrationTests/CERTInext.IntegrationTests.csproj` define the same property so the DCV test files compile with it.
- **Target frameworks.** The plugin targets `net8.0` and `net10.0`; both test projects target `net8.0`.

### Where the DCV code lives

The DCV code is in `CERTInext/CERTInextCAPlugin.cs`, compiled under `#if SUPPORTS_DCV`:

| Member | What it does |
|---|---|
| `using` alias and `DomainValidatorFactory` property | Name the `IDomainValidatorFactory` type and cast the stored factory to it |
| Internal test constructor taking an `IDomainValidatorFactory` | Lets tests inject a fake or real DNS validator |
| `SetDomainValidatorFactory(object)` | Receives the gateway's DNS provider factory and logs which type was offered |
| `EnrollNewAsync` (V1) | Runs DCV right after a new order is placed, then waits for issuance |
| `EnrollV2Async` (V2) | Runs DCV when the new order is pending, then re-checks its status |
| `Synchronize` / `SynchronizeV2Async` | Drive recently placed pending orders through DCV, bounded by `DcvSyncMaxOrderAgeHours` and `DcvSyncMaxPerPass` |
| `GetSingleRecord` / `GetSingleRecordV2Async` | Drive a pending order through DCV on a manual refresh |
| `TryRunDcvDuringSyncAsync` | V1 sync and single-record wrapper: in-flight guard, bounded timeout, swallows non-cancellation errors |
| `PerformDcvIfNeededAsync` | The V1 flow: wait for the challenge, `GetDcv`, publish TXT, `VerifyDcv`, poll, clean up |
| `PerformDcvV2IfNeededAsync` | The V2 entry point; dispatches to the single-domain or multi-domain V2 flow |

The stored factory is held as `object` and cast inside method bodies, so the plugin class loads even when the host doesn't supply `IDomainValidatorFactory`. DCV is then inactive: with `DcvEnabled` set to `true`, the plugin logs a warning at startup, and orders that need validation stay pending until a DNS provider is available or `DcvEnabled` is set to `false`.

The DNS provider side is a separate gateway plugin that implements `IDomainValidator` (for example `azure-azuredns-dnsplugin`). The integration tests include a Cloudflare-backed validator (`CloudflareDomainValidator`) and a recording wrapper for exercising the flow against the live sandbox.

## API Smoke-Test Targets

All V1 targets source `~/.env_certinext`, compute `authKey` as the SHA-256 digest `SHA256(accessKey + ts + txn)`, and call the live V1 API with `curl`. JSON responses are piped through `jq`. The V2 equivalents are the `v2-*` targets (for example `make v2-ping`, `make v2-list-products`, `make v2-orders-report`), which read `~/.env_certinext_v2`.

**Start here when setting up a new environment:**

```bash
make ping       # should return {"meta": {"status": "1", ...}}
make products   # lists product codes for your account
make orders     # lists recent orders; useful to find an ORDER_NUMBER to test with
```

| Target | Command | Description |
|---|---|---|
| Verify credentials | `make ping` | `ValidateCredentials`: confirms the access key and account number are accepted |
| List products | `make products` | `GetProductDetails`: shows all certificate product codes available to your group |
| List orders | `make orders [PAGE=1] [PAGE_SIZE=10]` | `GetOrderReport`: paginated order listing |
| Track an order | `make get-order ORDER_NUMBER=NNNNN` | `TrackOrder`: returns current status for a specific order |
| Download a certificate | `make get-cert ORDER_NUMBER=NNNNN` | `GetCertificate`: returns the PEM chain for a specific order |
| Place a draft order | `make generate-order DOMAIN=example.com [CSR_FILE=req.pem] [VALIDITY=1] [SAVE_AND_HOLD=1]` | `GenerateOrderSSL`: places a new order; `SAVE_AND_HOLD=1` (default) creates a draft |
| Revoke an order | `make revoke-order ORDER_NUMBER=NNNNN [REASON_ID=1]` | `RevokeOrder`: revokes an issued certificate |
| Attach a CSR to a draft | `make submit-csr ORDER_NUMBER=NNNNN CSR_FILE=req.pem` | `SubmitCSR`: attaches a CSR to a `saveAndHold` draft order |
| Discover product codes | `make probe-products` | Places `saveAndHold=1` draft orders for all known SSL/TLS product codes and reports which ones the account accepts |
| Cancel one pending order | `ORDER_NUMBER=NNNNN scripts/reject-order.sh` | Shell script that cancels a single pending order (not a `make` target); optional `REMARKS=...` |
| Cancel all pending orders | `scripts/reject-all-pending.sh` | Shell script, dry-run by default; set `REJECT_ALL_PENDING=1` to fire (not a `make` target) |
| Show API target help | `make api-help` | Prints usage for the V1 API targets |

> **Note:** `TrackOrder` and `GetCertificate` require a formal `orderNumber`, which is only assigned after a draft order is submitted and approved. Draft orders (created with `saveAndHold:"1"`) have a `requestNumber` but no `orderNumber` until that point.

### V2 targets

The `v2-*` targets that create, verify, submit, accept, cancel, or revoke only **preview** the request by default. To send it, add `V2_ARGS=--yes-mutate`:

```bash
make v2-revoke-ssl ORDER_ID=123 V2_ARGS=--yes-mutate
```

Read-only targets such as `v2-ping`, `v2-list-products`, `v2-track-order`, and `v2-orders-report` run without it. See [scripts/v2/README.md](../scripts/v2/README.md) for all V2 scripts.

## Draft Orders (saveAndHold)

Setting `SAVE_AND_HOLD=1` (the default) on `make generate-order` places an order in the "On Hold" state without triggering billing, DCV, or CA issuance. This is useful for validating that an order payload is accepted by the API.

Draft orders behave as follows:

- Assigned a `requestNumber` immediately on creation.
- Do **not** receive an `orderNumber` until the draft is formally submitted and approved.
- Appear in `GetOrderReport` and are included in gateway synchronization runs.
- Cannot be passed to `TrackOrder` or `GetCertificate`, because those endpoints require an `orderNumber`.

The gateway does not use `saveAndHold` in normal enrollment flows. It is strictly a developer testing mechanism for validating order payloads against the live API.

## Tests

The solution has two test projects, and a small runner that is not part of the solution:

| Project | Purpose |
|---|---|
| `CERTInext.Tests` | Unit and contract tests. No external services: HTTP is served in-process by WireMock.Net, and the client is replaced by Moq mocks. See `CERTInext.Tests/TESTING.md`. |
| `CERTInext.IntegrationTests` | Live-API tests. Every test skips automatically when credentials are absent, and destructive or order-placing tests are additionally gated behind the opt-in flags above. See `CERTInext.IntegrationTests/TESTING.md` and `CERTInext.IntegrationTests/INTEGRATION_TESTING.md`. |
| `CERTInext.IntegrationRunner` | A read-only console program that exercises the V1 client against the live API: `Ping`, then a `GetOrderReport` listing, then `TrackOrder` for one order. It is not in `certinext-caplugin.sln`. |

- **Unit tests only:** `dotnet test CERTInext.Tests/`
- **Live tests only:** `make integration-test`
- **Everything:** `make test`
- **Runner:** `dotnet run --project CERTInext.IntegrationRunner -- [ORDER_NUMBER]`. Without an argument it uses `CERTINEXT_TEST_ORDER_NUMBER` from `~/.env_certinext`, and it skips the `TrackOrder` step if neither is set.

Drive live-API verification through the integration tests and the runner rather than ad-hoc scripts, so every check is repeatable.

## Product Integration Test Coverage

Draft-order and track-order semantics are covered by `LifecycleTests`, which creates its own order and asserts on it without relying on account-specific identifiers.

Product codes are provisioned per account by eMudhra and are not portable across accounts (see [Product Codes](configuration.md#product-codes) in configuration.md). To discover which codes and required fields apply to *your* account:

```bash
make probe-products
```

This places `saveAndHold=1` draft orders for all known SSL/TLS product codes and reports which return a `requestNumber` (valid and provisioned) versus an error (invalid or not provisioned). See `CERTInext.IntegrationTests/TESTING.md` for the expected test results.
