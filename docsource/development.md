## Developer Guide

This document covers local development, testing, and live API smoke-testing for the CERTInext AnyCA Gateway REST plugin. For production deployment and CA connector configuration, see [configuration.md](configuration.md).

## Prerequisites

- .NET 10 SDK (the plugin project multi-targets `net8.0` and `net10.0`; the unit and integration test projects target `net8.0`)
- `python3` (used for HMAC computation in the V1 Makefile API targets)
- `jq` (used for JSON pretty-printing in Makefile API targets)
- `~/.env_certinext` populated with credentials (see below); for V2 targets and tests, `~/.env_certinext_v2` as well

## Credentials Files

Create `~/.env_certinext` with the following variables for the V1 API targets and tests. This file is **never committed** — add it to your global `.gitignore` or keep it only in `$HOME`.

```bash
CERTINEXT_API_URL=https://api.certinext.io/emSignHub-API   # or sandbox URL
CERTINEXT_ACCESS_KEY=<your access key from Integrations → APIs>
CERTINEXT_ACCOUNT_NUMBER=<your numeric account ID from account profile>
CERTINEXT_GROUP_NUMBER=<group number from Integrations → APIs credential row>
CERTINEXT_ORG_NUMBER=<org ID from Organizations page>
CERTINEXT_PRODUCT_CODE=838                                  # default product used by generate-order
CERTINEXT_REQUESTOR_EMAIL=<email associated with your CERTInext account>
CERTINEXT_REQUESTOR_NAME=<name of the requestor or automation account>
CERTINEXT_REQUESTOR_MOBILE=<digits only, no country code>
# Public IP of the machine running generate-order. Leave blank to auto-detect via api.ipify.org.
CERTINEXT_SIGNER_IP=
```

> Note: `CERTINEXT_GROUP_NUMBER` and `CERTINEXT_ORG_NUMBER` are distinct. The group number is the delegation unit (cost center/department) used in every order request. The org number is the validated organization record used for OV and EV orders.

The V2 API uses a separate file, `~/.env_certinext_v2` (override the path with `CERTINEXT_V2_ENV_FILE` for the `v2-*` Makefile targets):

```bash
CERTINEXT_API_URL=https://sandbox-us-api.certinext.io       # V2 base URL: no /emSignHub-API suffix
CERTINEXT_CLIENT_ID=<OAuth client ID from Integrations → APIs>
CERTINEXT_CLIENT_SECRET=<OAuth client secret>
CERTINEXT_USE_V2_API=1                                      # enables the V2 integration tests
```

The V2 file reuses the key names `CERTINEXT_API_URL` and `CERTINEXT_PRODUCT_CODE` with V2 values. Source only `~/.env_certinext` into your shell, never the V2 file — the V2 tests read it from disk themselves. See [scripts/v2/README.md](https://github.com/Keyfactor/certinext-caplugin/blob/main/scripts/v2/README.md) for the V2 helper scripts.

## Build and Test Targets

| Target | Command | Description |
|---|---|---|
| Build | `make build` | `dotnet build` the solution |
| Unit tests | `make test` | Run all mock/unit tests |
| Integration tests | `make integration-test` | Run live API tests (requires `~/.env_certinext`; tests skip automatically if credentials are absent) |
| Coverage report (terminal) | `make coverage` | Run tests with XPlat coverage and print summary |
| Coverage report (browser) | `make coverage-report` | Same as `coverage`, then opens HTML report in the default browser |
| Clean | `make clean` | `dotnet clean` and wipe coverage output directories |

### DCV build

The plugin builds against `Keyfactor.AnyGateway.IAnyCAPlugin` 3.3.0 with DNS-01 domain control validation (DCV) included, and targets AnyCA Gateway REST 26.2.0 and later. No build flag is needed: `dotnet build` and `make build` produce the DCV build, and the DCV unit and integration test files compile in with it. Release builds use the same default. See [DCV_BUILD_SUPPORT.md](https://github.com/Keyfactor/certinext-caplugin/blob/main/DCV_BUILD_SUPPORT.md) for how the DCV code is organized.

## API Smoke-Test Targets

All V1 API targets source `~/.env_certinext`, compute the HMAC `authKey` (`SHA256(accessKey + ts + txn)`), and call the live CERTInext V1 API via `curl`. All JSON responses are piped through `jq`. The V2 equivalents are the `v2-*` targets (for example `make v2-ping`, `make v2-list-products`, `make v2-orders-report`), which read `~/.env_certinext_v2`.

**Start here when setting up a new environment:**

```bash
make ping       # should return {"meta": {"status": "1", ...}}
make products   # lists product codes for your account
make orders     # lists recent orders — useful to find an ORDER_NUMBER to test with
```

| Target | Command | Description |
|---|---|---|
| Verify credentials | `make ping` | `ValidateCredentials` — confirms the access key and account number are accepted |
| List products | `make products` | `GetProductDetails` — shows all certificate product codes available to your group |
| List orders | `make orders [PAGE=1] [PAGE_SIZE=10]` | `GetOrderReport` — paginated order listing |
| Track an order | `make get-order ORDER_NUMBER=NNNNN` | `TrackOrder` — returns current status for a specific order |
| Download a certificate | `make get-cert ORDER_NUMBER=NNNNN` | `GetCertificate` — returns the PEM chain for a specific order |
| Place a draft order | `make generate-order DOMAIN=example.com [CSR_FILE=req.pem] [VALIDITY=1] [SAVE_AND_HOLD=1]` | `GenerateOrderSSL` — places a new order; `SAVE_AND_HOLD=1` (default) creates a draft |
| Revoke an order | `make revoke-order ORDER_NUMBER=NNNNN [REASON_ID=1]` | `RevokeOrder` — revokes an issued certificate |
| Attach a CSR to a draft | `make submit-csr ORDER_NUMBER=NNNNN CSR_FILE=req.pem` | `SubmitCSR` — attaches a CSR to a saveAndHold draft order |
| Discover product codes | `make probe-products` | Places `saveAndHold=1` draft orders for all known SSL/TLS product codes and reports which ones the account accepts |
| Cancel one pending order | `scripts/reject-order.sh ORDER_NUMBER=NNNNN` | Shell script — cancels a single pending order (not a `make` target) |
| Cancel all pending orders | `scripts/reject-all-pending.sh` | Shell script — dry-run by default; set `REJECT_ALL_PENDING=1` to fire (not a `make` target) |
| Show API target help | `make api-help` | Prints usage for the V1 API targets |

> Note: `TrackOrder` and `GetCertificate` require a formal `orderNumber`, which is only assigned after a draft order is submitted and approved. Draft orders (created with `saveAndHold:"1"`) have a `requestNumber` but no `orderNumber` until that point.

## Draft Orders (saveAndHold)

Setting `SAVE_AND_HOLD=1` (the default) on `make generate-order` places an order in "On Hold" state without triggering billing, DCV, or CA issuance. This is useful for validating that an order payload is accepted by the API.

Draft orders behave as follows:

- Assigned a `requestNumber` immediately on creation.
- Do **not** receive an `orderNumber` until the draft is formally submitted and approved.
- Appear in `GetOrderReport` and are included in gateway synchronization runs.
- Cannot be passed to `TrackOrder` or `GetCertificate` — those endpoints require an `orderNumber`.

The gateway does not use `saveAndHold` in normal enrollment flows. It is strictly a developer testing mechanism for validating order payloads against the live API.

## Tests

The solution has two test projects and a small runner:

| Project | Purpose |
|---|---|
| `CERTInext.Tests` | Unit and contract tests. No external services: HTTP is served in-process by WireMock.Net, and the client is replaced by Moq mocks. See `CERTInext.Tests/TESTING.md`. |
| `CERTInext.IntegrationTests` | Live-API tests. Every test skips automatically when credentials are absent, and destructive or order-placing tests are additionally gated behind opt-in environment flags. See `CERTInext.IntegrationTests/TESTING.md` and `CERTInext.IntegrationTests/INTEGRATION_TESTING.md`. |
| `CERTInext.IntegrationRunner` | A read-only console program that exercises the client against the live API: `Ping`, then a `GetOrderReport` listing, then `TrackOrder` for an order number passed as the first argument or in `CERTINEXT_TEST_ORDER_NUMBER`. |

Run the unit tests with `make test`, and the live tests with `make integration-test`.

Drive live-API verification through the integration tests and the runner rather than ad-hoc scripts, so every check is repeatable.

## Product Integration Test Coverage

Draft-order and track-order semantics are covered by `LifecycleTests`, which creates its own order and asserts on it without relying on account-specific identifiers.

Product codes are provisioned per account by eMudhra and are not portable across accounts (see the [Product Codes](configuration.md#product-codes) section in configuration.md). To discover which codes and required fields apply to *your* account:

```bash
make probe-products
```

This places `saveAndHold=1` draft orders for all known SSL/TLS product codes and reports which return a `requestNumber` (valid/provisioned) versus an error (invalid or not provisioned). See `CERTInext.IntegrationTests/TESTING.md` for the expected test results.
