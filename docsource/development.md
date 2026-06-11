## Developer Guide

This document covers local development, testing, and live API smoke-testing for the CERTInext AnyCA Gateway REST plugin. For production deployment and CA connector configuration, see [configuration.md](configuration.md).

## Prerequisites

- .NET SDK 8.0 or later
- `python3` (used for HMAC computation in Makefile API targets)
- `jq` (used for JSON pretty-printing in Makefile API targets)
- `~/.env_certinext` populated with credentials (see below)

## Credentials File

Create `~/.env_certinext` with the following variables. This file is **never committed** — add it to your global `.gitignore` or keep it only in `$HOME`.

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

## Build and Test Targets

| Target | Command | Description |
|---|---|---|
| Build | `make build` | `dotnet build` the solution |
| Unit tests | `make test` | Run all mock/unit tests |
| Integration tests | `make integration-test` | Run live API tests (requires `~/.env_certinext`; tests skip automatically if credentials are absent) |
| Coverage report (terminal) | `make coverage` | Run tests with XPlat coverage and print summary |
| Coverage report (browser) | `make coverage-report` | Same as `coverage`, then opens HTML report in the default browser |
| Clean | `make clean` | `dotnet clean` and wipe coverage output directories |

### Build variants — `DcvSupport` (DCV vs no-DCV)

The plugin builds against two `Keyfactor.AnyGateway.IAnyCAPlugin` contracts from a single
codebase, selected by the `DcvSupport` MSBuild property. The plugin's `AnyCAPluginCertificate`
records must match the gateway host's IAnyCAPlugin version to persist, so the build must target
the host (see issue 0003).

| Build | Command | IAnyCAPlugin | DCV | Target gateway host |
|---|---|---|---|---|
| **No-DCV (default)** | `make build` / `dotnet build` | `3.2.0` (stable) | fenced out (`#if SUPPORTS_DCV`) | AnyCA Gateway **25.5.x** (IAnyCAPlugin 3.2.0) |
| **DCV** | `dotnet build -p:DcvSupport=true` | `3.3.0-PRERELEASE` | enabled | AnyCA Gateway **26.x** (IAnyCAPlugin ≥ 3.3) |

The **default is the no-DCV / 3.2.0 build** — it is the GA artifact that loads and persists on the
current GA gateway (25.5.x) and depends only on a stable package, so it is what CI ships. Build the
DCV variant explicitly with `-p:DcvSupport=true` for 26.x hosts. The one property drives the package
version, the `SUPPORTS_DCV` compile constant, and DCV test-file inclusion across all three projects,
so the two host targets are a build flag rather than a maintained fork.

## API Smoke-Test Targets

All API targets source `~/.env_certinext`, compute the HMAC `authKey` (`SHA256(accessKey + ts + txn)`), and call the live CERTInext API via `curl`. All JSON responses are piped through `jq`.

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
| Show API target help | `make api-help` | Prints usage for all API targets |

> Note: `TrackOrder` and `GetCertificate` require a formal `orderNumber`, which is only assigned after a draft order is submitted and approved. Draft orders (created with `saveAndHold:"1"`) have a `requestNumber` but no `orderNumber` until that point.

## Draft Orders (saveAndHold)

Setting `SAVE_AND_HOLD=1` (the default) on `make generate-order` places an order in "On Hold" state without triggering billing, DCV, or CA issuance. This is useful for validating that an order payload is accepted by the API.

Draft orders behave as follows:

- Assigned a `requestNumber` immediately on creation.
- Do **not** receive an `orderNumber` until the draft is formally submitted and approved.
- Appear in `GetOrderReport` and are included in gateway synchronization runs.
- Cannot be passed to `TrackOrder` or `GetCertificate` — those endpoints require an `orderNumber`.

The gateway does not use `saveAndHold` in normal enrollment flows. It is strictly a developer testing mechanism for validating order payloads against the live API.

## Integration Tests

The `CERTInext.IntegrationTests/` project contains live API tests that run against the production India instance (`api.certinext.io`). All tests use `[SkippableFact]` and skip automatically when `~/.env_certinext` is absent or incomplete.

Run them with:

```bash
make integration-test
```

See `CERTInext.IntegrationTests/INTEGRATION_TESTING.md` for a full description of each test, what it validates, and the expected API state.

## Product Integration Test Coverage

The table below records live draft-order results against the Production — India instance. Orders were placed with `saveAndHold:"1"` so no billing, DCV, or CA issuance was triggered. Tests are in `CERTInext.IntegrationTests/DraftOrderTests.cs`.

| Product | Code | Test Status | requestNumber | Notes |
|---|---|---|---|---|
| DV SSL | `838` | ✓ Tested | 4572531551 | Base domain; no extra fields required beyond base set |
| DV SSL Wildcard | `839` | ✓ Tested | 9149755266 | CSR CN must be `*.domain`; `domainName` must also use wildcard format |
| DV SSL UCC | `840` | ✓ Tested | 1611445122 | `certificateInformation.additionalDomains` array required |
| DV SSL Wildcard UCC | `841` | ✗ Blocked | — | EMS-918: "Additional Information cannot be empty" — required fields for this product not yet identified |
| OV SSL | `842` | ✓ Tested | 5546366498 | Requires `locality` and `postalCode` in `certificateInformation` |
| OV SSL Wildcard | `843` | ✗ Not tested | — | Draft order not yet placed |
| OV SSL UCC | `844` | ✗ Not tested | — | Draft order not yet placed |
| OV SSL Wildcard UCC | `845` | ✗ Blocked | — | EMS-918: "Additional Information cannot be empty" — required fields for this product not yet identified |
| EV SSL | `846` | ✓ Tested | 3932332114 | Requires `contractSignerInfo`, `certificateApproverInfo`, non-empty `streetAddress2`, `companyRegistrationNumber` |
| EV SSL UCC | `847` | ✗ Blocked | — | EMS-918: "Additional Information cannot be empty" — required fields for this product not yet identified |
| DV SSL 1 Month | N/A | ✗ Not supported | — | Visible in portal but not returned by `GetProductDetails` API; no product code available. Not supported by plugin. |
| DV SSL Wildcard 1 Month | N/A | ✗ Not supported | — | Visible in portal but not returned by `GetProductDetails` API; no product code available. Not supported by plugin. |
| emSign Intranet SSL | `100` | ✗ Not tested | — | EMS-1162: not provisioned on this account type |
| IGTF Host | `104` | ✗ Not tested | — | EMS-1162: not provisioned on this account type |
| S/MIME | `894` | ✗ Not tested | — | EMS-1162: not provisioned on this account type |
| Natural Person Doc Signer | `825` | ✗ Not tested | — | EMS-1162: not provisioned on this account type |
| Legal Entity Doc Signer | `819` | ✗ Not tested | — | EMS-1162: not provisioned on this account type |

Products returning EMS-1162 require special provisioning by eMudhra that is not included on a standard SSL/TLS account. The plugin code supports submitting orders for any product code; whether the order is accepted depends on what is provisioned for your account.
