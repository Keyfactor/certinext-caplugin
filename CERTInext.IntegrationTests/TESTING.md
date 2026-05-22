# CERTInext Integration Tests

This project contains xUnit integration tests that exercise the CERTInext plugin against
the live CERTInext REST API.  All tests skip automatically when credentials are absent,
so the project is safe to include in CI pipelines that do not have API access.

---

## Product Codes Are Per-Account

**CERTInext product codes are provisioned per account by eMudhra.** The codes available
to your account are established when the account is created and may differ from any
documentation examples or from codes used by other accounts.

Key findings verified against sandbox account `9374221333` in April 2026:

- `GetProductDetails` returns an empty list when called without `groupNumber` in the
  `productDetails` block on some sandbox accounts.  The plugin now passes `groupNumber`
  automatically when `GroupNumber` is set in the connector config.
- The SSL/TLS product codes on this sandbox account are `842–851` (not `838–847` as on
  the prior dev account).  DV SSL is `842` on this account.
- Product code `100` (Private PKI / emSign Intranet SSL) is not provisioned on this
  account — `GenerateOrderSSL` returns `EMS-1162: Invalid Product Code`.
- Product code `149` (Sandbox emSign Intranet SSL) appears in `GetProductDetails` for
  this account but also returns `EMS-1162` when ordering — it is not usable for orders.
- EV SSL (codes `850`, `851`) requires an `organizationNumber` that is registered and
  approved in CERTInext; using an unregistered org returns `EMS-1073: Invalid Organization Number`.
- The `GenerateOrderSSL` API requires `additionalInformation.remarks` in the request body.
  Omitting it returns `EMS-918: Additional Information cannot be empty`.

To discover the valid product codes for a new account, use:

```sh
make probe-products
```

This places `saveAndHold=1` draft orders for all known SSL/TLS product codes and reports
which ones return a `requestNumber` (valid) vs. an error (invalid or not provisioned).

---

## Prerequisites

- .NET 8 SDK
- Access to a CERTInext sandbox or production account
- An API Access Key generated in the CERTInext portal under **Integrations → APIs**

---

## Credential Setup

Create the file `~/.env_certinext` with the following content:

```sh
# CERTInext API credentials
CERTINEXT_API_URL=https://sandbox-us-api.certinext.io/emSignHub-API
CERTINEXT_ACCESS_KEY=your-access-key-here
CERTINEXT_ACCOUNT_NUMBER=your-account-number
CERTINEXT_GROUP_NUMBER=your-group-number
CERTINEXT_ORG_NUMBER=your-org-number
CERTINEXT_PRODUCT_CODE=842
CERTINEXT_REQUESTOR_EMAIL=you@example.com
CERTINEXT_REQUESTOR_NAME=Your Name
CERTINEXT_REQUESTOR_MOBILE=0000000000
```

### Field reference

| Variable | Required | Description |
|----------|----------|-------------|
| `CERTINEXT_API_URL` | Yes | Base URL of the CERTInext API (no trailing slash) |
| `CERTINEXT_ACCESS_KEY` | Yes | REST API Access Key from the CERTInext portal (Integrations → APIs) |
| `CERTINEXT_ACCOUNT_NUMBER` | Yes | Your CERTInext account number (numeric string) |
| `CERTINEXT_GROUP_NUMBER` | No | Group number for order placement, filtering, and `GetProductDetails`. Required on some sandbox accounts for `GetProductDetails` to return a non-empty list. |
| `CERTINEXT_ORG_NUMBER` | No | Organization number for OV/EV order placement |
| `CERTINEXT_PRODUCT_CODE` | Yes | Numeric product code for the target account. **This is per-account** — obtain the correct code for your account by calling `GetProductDetails` (or `make probe-products`). Default shown is for sandbox account `9374221333`. |
| `CERTINEXT_REQUESTOR_EMAIL` | Yes | Email submitted with test orders — must be registered in the account |
| `CERTINEXT_REQUESTOR_NAME` | Yes | Name submitted with test orders |
| `CERTINEXT_REQUESTOR_MOBILE` | No | Mobile number submitted with test orders |

### API URL reference

| Environment | URL |
|-------------|-----|
| Sandbox (US) | `https://sandbox-us-api.certinext.io/emSignHub-API` |
| Production (US) | `https://us-api.certinext.io/emSignHub-API` |
| Production (Global/India) | `https://api.certinext.io/emSignHub-API` |

### Credential file format

The file is parsed line by line:
- Lines starting with `#` are treated as comments and ignored.
- Blank lines are ignored.
- Each line must be in `KEY=VALUE` format.
- Values are not quoted — do not surround values with `"` or `'`.
- Real environment variables override file values (useful for CI injection).

---

## Running the Tests

### Build only

```sh
dotnet build CERTInext.IntegrationTests/CERTInext.IntegrationTests.csproj --configuration Release
```

### Run all integration tests

```sh
dotnet test CERTInext.IntegrationTests/CERTInext.IntegrationTests.csproj --configuration Release -v normal
```

### Run a single test class

```sh
dotnet test CERTInext.IntegrationTests/ --filter "FullyQualifiedName~LifecycleTests" -v normal
```

### From the solution root (all tests including unit tests)

```sh
dotnet test certinext-caplugin.sln --verbosity normal
```

---

## Skip Behaviour

Each test calls `IntegrationSkip.IfNotConfigured(fixture)` at the top of the test method.
When `~/.env_certinext` is absent or either `CERTINEXT_API_URL` or `CERTINEXT_ACCESS_KEY`
is empty, every test is reported as **Skipped** rather than Failed.

Some tests additionally skip when the account has no orders yet (e.g. on a fresh sandbox
account).  These tests display a skip reason explaining that the account state does not
satisfy the test's pre-condition.

---

## Test Classes

### `ConnectivityTests`

Verifies basic API reachability and credential validity.

| Test | What it checks |
|------|---------------|
| `Ping_ReturnsSuccess` | Calls `ValidateCredentials`; asserts no exception is thrown |

### `ProductTests`

Verifies product discovery.

| Test | What it checks |
|------|---------------|
| `GetProductDetails_ReturnsProducts` | Calls `GetProductDetails`; asserts the call succeeds without throwing; when products are returned, asserts the expected product code from `CERTINEXT_PRODUCT_CODE` is among them |

Note: some CERTInext accounts return an empty list from `GetProductDetails` even though
orders using those product codes are visible in `GetOrderReport`.  An empty list is
treated as acceptable — only the absence of an exception is mandatory.

### `OrderReportTests`

Exercises the `ListOrdersAsync` path used by `Synchronize`.  Tests skip gracefully
when the account has no orders rather than failing.

| Test | What it checks |
|------|---------------|
| `GetOrderReport_ReturnsOrders` | Fetches page 1; skips when account has no orders; otherwise asserts the list is non-empty |
| `GetOrderReport_AllOrders_HaveRequiredFields` | For each order on page 1: `requestNumber`, `productCode`, and `orderDate` are non-empty; skips when account has no orders |

### `PluginSmokeTests`

End-to-end tests exercising `CERTInextCAPlugin` via the `IAnyCAPlugin` interface with
a live `CERTInextClient` injected through the `(ICERTInextClient, CERTInextConfig)`
test constructor.

| Test | What it checks |
|------|---------------|
| `Ping_ThroughPlugin_Succeeds` | Calls `IAnyCAPlugin.Ping()`; asserts no exception |
| `GetProductIds_ReturnsAtLeastOneProduct` | Calls `IAnyCAPlugin.GetProductIds()`; asserts a non-null list is returned without throwing |
| `Synchronize_ReturnsAtLeastOneRecord` | Runs a full sync; skips when account has no records; otherwise asserts at least one `AnyCAPluginCertificate` is produced |

### `LifecycleTests`

Full end-to-end lifecycle tests that create real orders against the configured CERTInext
account.  These tests do not require any pre-existing account state.

| Test | What it checks |
|------|---------------|
| `Enroll_Synchronize_Revoke_FullLifecycle` | (1) Generates a fresh RSA-2048 CSR; (2) calls `Enroll` and asserts a non-empty `CARequestID` is returned; (3) runs a full sync and asserts the new order appears by `CARequestID`; (4) attempts revocation — skips gracefully if the order is not yet in an issued/approved state |

---

## Expected Outcomes by Account State

### Fresh sandbox account (no prior orders)

| Test class | Expected result |
|-----------|----------------|
| `ConnectivityTests` | Pass — credentials only |
| `ProductTests` | Pass — product list may be empty if `CERTINEXT_GROUP_NUMBER` is not set and the account requires it; test tolerates an empty list |
| `OrderReportTests` | Skip — "account has no orders yet" |
| `PluginSmokeTests.Synchronize_ReturnsAtLeastOneRecord` | Skip — "account has no certificate records yet" |
| `LifecycleTests.Enroll_Synchronize_Revoke_FullLifecycle` | Skip with "Invalid Product Code" if `CERTINEXT_PRODUCT_CODE` is not provisioned for this account; otherwise the enroll and sync steps pass, and the revoke step skips because the DV SSL sandbox order requires domain control verification and RA approval before it reaches an issued/revocable state |

### Account with history (orders previously placed)

| Test class | Expected result |
|-----------|----------------|
| `ConnectivityTests` | Pass |
| `ProductTests` | Pass |
| `OrderReportTests` | Pass |
| `PluginSmokeTests` | Pass |
| `LifecycleTests` | Pass (all three steps) |

---

## Removed Tests

The following test files were present in earlier versions but have been removed because
they relied on pre-existing account state that is not portable across accounts or
sandbox environments:

- **`DraftOrderTests.cs`** — contained five tests that asserted specific `requestNumber`
  values (e.g. `4572531551`, `9149755266`) hardcoded from a different developer account.
  On any other account these request numbers do not exist so all five tests failed.

- **`TrackOrderTests.cs`** — contained one test that located a known draft order by
  `requestNumber` and asserted its `orderNumber` was null (draft/on-hold semantic).
  Same problem: the hardcoded `requestNumber` does not exist on other accounts.

The intent of those tests (verifying draft-order and track-order semantics) is now
covered indirectly by `LifecycleTests`, which creates its own order and verifies the
resulting state without relying on account-specific identifiers.

---

## Authentication

The CERTInext API uses HMAC-SHA256 authentication computed for every request:

```
authKey = SHA256(accessKey + ts + txn)   (lowercase hex)
```

Where:
- `accessKey` is the raw API Access Key from `CERTINEXT_ACCESS_KEY`
- `ts` is the current timestamp in ISO 8601 format
- `txn` is a random numeric transaction ID

The `CERTInextClient` handles this computation automatically.  The raw access key is
never transmitted over the wire — only the derived `authKey` hash is sent.

---

## Fresh Account Setup for Integration Tests

When setting up a brand-new CERTInext sandbox account to run integration tests:

1. **Discover valid product codes** — run `make probe-products` from the repo root.  This places
   `saveAndHold=1` draft orders for all known SSL/TLS product codes and reports which ones your
   account accepts.  Use the first DV SSL code that returns a `requestNumber` as your
   `CERTINEXT_PRODUCT_CODE`.

2. **Set `CERTINEXT_GROUP_NUMBER`** — if `make probe-products` or `GetProductDetails` returns no
   products, find your group number in the CERTInext portal under **Delegation → Groups** and add
   it to `~/.env_certinext`.  The `GetProductDetails` API requires it on some accounts.

3. **Run connectivity tests first** — `make integration-test` or
   `dotnet test CERTInext.IntegrationTests/ -v normal`.  The `ConnectivityTests` class verifies
   credentials.  The `LifecycleTests` class places real orders — it can be run even before any
   orders exist.

4. **Expect the revoke step to skip** — DV SSL orders on the sandbox require domain control
   verification (DCV) and RA approval before they are issued.  The `LifecycleTests` enroll step
   will succeed and sync will find the order, but revoke will skip because the order is in a
   pending state.  This is the expected behavior for a public DV SSL order in sandbox.  To test
   revocation, either use a private PKI product that auto-approves, or log in to the CERTInext
   portal and manually approve the pending order after `LifecycleTests` runs.

5. **Account-specific product codes** — update `CERTINEXT_PRODUCT_CODE` in `~/.env_certinext`
   with the code discovered in step 1.  Do not use `100` (private PKI, not provisioned on
   standard accounts) or codes from documentation examples — they may not be provisioned for your
   account.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| All tests skipped | Missing or empty `~/.env_certinext` | Create the file with `CERTINEXT_API_URL` and `CERTINEXT_ACCESS_KEY` |
| `Ping` fails with 401/403 | Wrong `CERTINEXT_ACCESS_KEY` | Regenerate the key in the CERTInext portal under Integrations → APIs |
| `Ping` fails with timeout or 404 | Wrong `CERTINEXT_API_URL` | Verify the URL matches your account region (see API URL table above) |
| `Enroll` fails with "Invalid Product Code" (EMS-1162) | Wrong `CERTINEXT_PRODUCT_CODE` | Run `make probe-products` to discover the codes provisioned for your account |
| `GetProductDetails` returns empty list | `CERTINEXT_GROUP_NUMBER` not set | Add your group number to `~/.env_certinext`; some accounts require it for `GetProductDetails` to return results |
| `Enroll` fails with "Additional Information cannot be empty" (EMS-918) | Old plugin version missing `additionalInformation.remarks` | Rebuild and redeploy the plugin — the `remarks` field is now populated automatically |
| `Enroll` fails with "Invalid Organization Number" (EMS-1073) | OV/EV product code selected with an unregistered org | Use a DV SSL product code for automated tests, or register and approve your org in CERTInext first |
| Revoke step skips with "not GENERATED" | Sandbox DV SSL order requires domain validation and RA approval | Expected behavior for public DV SSL in sandbox — log in to the CERTInext portal and approve the pending order, then re-run; or use a private PKI product that auto-approves |
| `OrderReportTests` all skip | Fresh account with no orders | Run `LifecycleTests` first to place at least one order |
| `ProductTests` asserts configured product code is not found | `CERTINEXT_PRODUCT_CODE` set to a code not provisioned for the account | Run `make probe-products` and update `CERTINEXT_PRODUCT_CODE` with a valid code |
