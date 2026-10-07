# CERTInext Integration Tests — Setup and Running

This project contains xUnit integration tests that exercise the CERTInext plugin against the
live CERTInext REST API (V1 and V2). Every test skips automatically when credentials are absent,
so the project is safe to include in CI pipelines that have no API access. Tests that place
orders, publish DNS records, or cancel orders are additionally gated behind opt-in environment
flags. For the list of tests and what each checks, see [TESTING.md](TESTING.md).

---

## Prerequisites

- .NET 10 SDK (the test project targets `net8.0`)
- Access to a CERTInext account (a sandbox account is recommended)
- For V1 tests: an API Access Key from the CERTInext portal under **Integrations → APIs**
- For V2 tests: an OAuth-mode credential (client ID and secret) from the same page
- For DNS-01 DCV tests: a Cloudflare API token and zone ID for a domain you control

---

## Credential Setup

### V1: `~/.env_certinext`

```sh
# CERTInext V1 API credentials
CERTINEXT_API_URL=https://sandbox-us-api.certinext.io/emSignHub-API/
CERTINEXT_ACCESS_KEY=your-access-key-here
CERTINEXT_ACCOUNT_NUMBER=your-account-number
CERTINEXT_GROUP_NUMBER=your-group-number
CERTINEXT_ORG_NUMBER=your-org-number
CERTINEXT_PRODUCT_CODE=842
CERTINEXT_REQUESTOR_EMAIL=you@example.com
CERTINEXT_REQUESTOR_NAME=Your Name
```

| Variable | Required | Description |
|----------|----------|-------------|
| `CERTINEXT_API_URL` | Yes | V1 base URL, including the `/emSignHub-API` path segment |
| `CERTINEXT_ACCESS_KEY` | Yes | REST API Access Key from the CERTInext portal |
| `CERTINEXT_ACCOUNT_NUMBER` | Yes | Your CERTInext account number (numeric string) |
| `CERTINEXT_GROUP_NUMBER` | No | Group number for order placement and `GetProductDetails`; some accounts need it for the product list to be non-empty |
| `CERTINEXT_ORG_NUMBER` | No | Pre-vetted organization number for OV/EV order placement |
| `CERTINEXT_PRODUCT_CODE` | For order-placing tests | Numeric product code for your account. **Product codes are per account** — find yours with `make get-product-details-group` or `make probe-products` |
| `CERTINEXT_REQUESTOR_EMAIL`, `CERTINEXT_REQUESTOR_NAME` | For order-placing tests | Requestor submitted with test orders; the email must be registered in the account |
| `CERTINEXT_CF_API_TOKEN`, `CERTINEXT_CF_ZONE_ID` | For DNS-01 DCV tests | Cloudflare token with DNS edit permission on the zone, and the zone ID |
| `CERTINEXT_DCV_DOMAIN` | For DNS-01 DCV tests | A domain inside that zone that test orders use |
| `CERTINEXT_ORDER_ID` | For `SmokeTests` order lookups | An existing order number |

| Environment | V1 `CERTINEXT_API_URL` |
|-------------|------------------------|
| Sandbox (US) | `https://sandbox-us-api.certinext.io/emSignHub-API/` |
| Production (US) | `https://us-api.certinext.io/emSignHub-API/` |
| Production (Global/India) | `https://api.certinext.io/emSignHub-API/` |

### V2: `~/.env_certinext_v2`

The V2 tests read this file themselves.

```sh
# CERTInext V2 API credentials
CERTINEXT_API_URL=https://sandbox-us-api.certinext.io      # V2 base URL: no /emSignHub-API suffix
CERTINEXT_CLIENT_ID=your-oauth-client-id
CERTINEXT_CLIENT_SECRET=your-oauth-client-secret
CERTINEXT_USE_V2_API=1                                     # any non-empty value enables the V2 tests
CERTINEXT_PRODUCT_CODE=842                                 # optional; V2 catalog code, default 842
```

The V2 file reuses key names from the V1 file (`CERTINEXT_API_URL`, `CERTINEXT_PRODUCT_CODE`, the
Cloudflare keys, `CERTINEXT_DCV_DOMAIN`) with V2 values, so source only `~/.env_certinext` into
your shell and never `~/.env_certinext_v2`. The V2 test classes never write those shared keys
into the process environment.

### File format

- Lines starting with `#` and blank lines are ignored.
- Each line is `KEY=VALUE`. One pair of matching surrounding single or double quotes is stripped from the value.
- Real environment variables override values from the V1 file, which makes CI injection easy.
- The V1 fixture fails fast, with an actionable message, if the resolved `CERTINEXT_API_URL` lacks
  `/emSignHub-API`, which indicates a V2 URL leaked into the V1 side.
- When running from a shell that needs the opt-in flags below, load the V1 file with
  `set -a; . ~/.env_certinext; set +a`.

---

## Running the Tests

```sh
# all integration tests (live tests skip when credentials are absent)
dotnet test CERTInext.IntegrationTests/CERTInext.IntegrationTests.csproj -c Release --verbosity normal

# or via the Makefile
make integration-test

# a single class
dotnet test CERTInext.IntegrationTests/ --filter "FullyQualifiedName~LifecycleTests" -v normal

# from the solution root, including the unit tests
dotnet test certinext-caplugin.sln --verbosity normal
```

The DCV test classes compile into the default build; no build flag is needed.

---

## Skip Behaviour

- **V1 tests** call `IntegrationSkip.IfNotConfigured(fixture)` first. When `~/.env_certinext` is
  absent, or `CERTINEXT_API_URL` or `CERTINEXT_ACCESS_KEY` is empty, the test is reported as
  **Skipped**, not failed.
- **V2 tests** skip unless `CERTINEXT_USE_V2_API`, `CERTINEXT_API_URL`, `CERTINEXT_CLIENT_ID`, and
  `CERTINEXT_CLIENT_SECRET` are all set (in `~/.env_certinext_v2` or the environment).
- **DCV tests** additionally skip unless the Cloudflare token and zone ID are set.
- Some tests skip when the account lacks the state they need, such as no existing orders or an
  order that has not yet reached an issued state.

### Opt-in flags

Tests that place real orders, publish DNS records, or cancel orders only run when you export the
matching flag in your shell. These flags are deliberately **not** read from `~/.env_certinext` or
`~/.env_certinext_v2`, so a flag left in a file can't arm them on every run.

| Flag | Arms |
|------|------|
| `CERTINEXT_ALGO_MATRIX=1` | `AlgorithmMatrixTests.Enroll_AcceptsKeyAlgorithm` — one sandbox order per key algorithm |
| `CERTINEXT_ALGO_MATRIX_DCV=1` | `DcvLifecycleTests.EnrollWithDcvOn_IssuesPerKeyAlgorithm` (also needs Cloudflare) |
| `CERTINEXT_RUN_BULK_TEST=1` | `DcvLifecycleTests.BulkDvEnrollment_AllOrdersIssue_AndPaginationWorks` (also needs Cloudflare); tune with `CERTINEXT_BULK_TEST_COUNT` and `CERTINEXT_BULK_TEST_PARALLEL` |
| `CERTINEXT_COMPLETE_PENDING=1` | `DcvLifecycleTests.CompleteAllPendingDvOrders` (also needs Cloudflare) — repeated full syncs until no DV order is pending |
| `CERTINEXT_V2_ALGO_MATRIX=1` | `V2DcvLifecycleTests.EnrollWithDcvOn_V2_IssuesPerKeyAlgorithm` (also needs Cloudflare) |
| `CERTINEXT_V2_RUN_BULK_TEST=1` | `V2DcvLifecycleTests.BulkV2Enrollment_AllOrdersIssue_AndPaginationWorks` (also needs Cloudflare); tune with `CERTINEXT_V2_BULK_TEST_COUNT` and `CERTINEXT_V2_BULK_TEST_PARALLEL` |
| `CERTINEXT_V2_LIFECYCLE_DV_UCC=1`, `_OV=1`, `_OV_UCC=1`, `_EV=1`, `_WILDCARD_DV=1`, `_RENEW_REISSUE=1` | The matching `V2FullLifecycleTests` method; the OV and OV UCC tests also need `CERTINEXT_ORG_NUMBER`, and the EV test needs its own pre-vetted `CERTINEXT_EV_ORG_NUMBER` |
| `CERTINEXT_V2_LIFECYCLE_FRESH_DCV=1` | `V2FreshDomainDcvLifecycleTests` (also needs Cloudflare and `CERTINEXT_V2_FRESH_DCV_PARENT`, the parent domain that fresh subdomains are created under) |
| `CERTINEXT_PRIVATE_PKI_LIVE=1` | `PrivatePkiV2LiveTests.PrivatePki_V2_EnrollIntranetSsl_ThenRevoke_Live`; override the product code and CN with `CERTINEXT_PRIVATE_PKI_PRODUCT_CODE` and `CERTINEXT_PRIVATE_PKI_CN` |
| `CERTINEXT_V2_OPS_TESTS=1` | `V2OrderWindowSweepTests` — see below |

Further variables select existing orders for specific tests: `CERTINEXT_PENDING_ORDER_ID`
(`DcvLifecycleTests.GetSingleRecord_DrivesDcvForPendingOrder`), `CERTINEXT_V2_PENDING_ORDER_ID`,
`CERTINEXT_V2_ORDER_ID`, `CERTINEXT_V2_ISSUED_ORDER_ID`, and `CERTINEXT_REVOKE_ORDER_ID` (V2
lifecycle and revoke tests), and `CERTINEXT_V2_FULL_SYNC_TEST` (any value enables the V2 full-history
sync test, which can be slow on a shared account).

### Operations and diagnostic tests

Two opt-in tests are maintenance tools rather than checks:

- **`V2OrderWindowSweepTests`** lists every V2 order in a date window and can cancel specific
  orders. It needs `CERTINEXT_V2_OPS_TESTS=1`, `CERTINEXT_V2_SWEEP_FROM` and `CERTINEXT_V2_SWEEP_TO`
  (UTC ISO-8601 timestamps), and is read-only unless `CERTINEXT_V2_SWEEP_CANCEL_IDS` lists order
  IDs, in which case it cancels exactly those orders if they are found in the window and not already
  in a terminal state.
- **`PendingDvDiagnosticsTests`** dumps the DCV state of pending V1 orders. It needs
  `CERTINEXT_DIAG_ORDER_IDS="orderId|domain,orderId|domain"` and makes read-only calls.

### Completing pending DV orders

To drive every pending DV order on a sandbox account to issuance (needs a DNS provider, so the
Cloudflare variables):

```sh
set -a; . ~/.env_certinext; set +a
export CERTINEXT_COMPLETE_PENDING=1
dotnet test CERTInext.IntegrationTests/CERTInext.IntegrationTests.csproj -c Release \
  --filter "FullyQualifiedName~CompleteAllPendingDvOrders" \
  --logger "console;verbosity=detailed" > /tmp/dvrun.log 2>&1
```

xUnit buffers test output until the test ends, so read the per-pass report at the end of the log.
Run only one full-history synchronization at a time against a shared account; full syncs are
slow.

---

## Authentication

V1 uses the AccessKey digest the plugin computes for every request:

```
authKey = SHA256(accessKey + ts + txn)   (lowercase hex)
```

`accessKey` is `CERTINEXT_ACCESS_KEY`, `ts` is the current ISO 8601 timestamp, and `txn` is a random
numeric transaction ID. The client computes this itself, and the raw access key is never transmitted.
V2 tests authenticate with OAuth2 `client_credentials` using `CERTINEXT_CLIENT_ID` and
`CERTINEXT_CLIENT_SECRET`.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| All tests skipped | Missing or empty `~/.env_certinext` (V1) or `~/.env_certinext_v2` (V2) | Create the file with the required variables |
| V1 fixture throws about `/emSignHub-API` | A V2 `CERTINEXT_API_URL` leaked into the shell | Run `unset CERTINEXT_API_URL`, or open a fresh shell, and source only `~/.env_certinext` |
| `Ping` fails with 401/403 | Wrong `CERTINEXT_ACCESS_KEY` | Regenerate the key under Integrations → APIs |
| `Ping` fails with a timeout or 404 | Wrong `CERTINEXT_API_URL` | Check the URL against your account's region (V1 needs the `/emSignHub-API` path) |
| V2 token request fails with 401 | Wrong client ID or secret | Check `CERTINEXT_CLIENT_ID` and `CERTINEXT_CLIENT_SECRET` |
| V2 token request fails with 403 | Key not generated in OAuth mode | Create a new OAuth-mode key in the portal |
| `Enroll` fails with "Invalid Product Code" (EMS-1162) | `CERTINEXT_PRODUCT_CODE` isn't provisioned for the account | Run `make probe-products` and use a code the account accepts |
| `GetProductDetails` returns an empty list | `CERTINEXT_GROUP_NUMBER` not set | Add your group number; some accounts need it |
| `Enroll` fails with "Invalid Organization Number" (EMS-1073) | OV/EV order with an unregistered organization | Use a DV product for automated tests, or register and approve the organization |
| Revoke step skips with "not GENERATED" | A sandbox DV order needs domain validation before it is issued | Expected without DCV; run the DCV tests with Cloudflare configured, or approve the order in the portal |
| `OrderReportTests` skip | The account has no orders | Run `LifecycleTests` first to place one |
