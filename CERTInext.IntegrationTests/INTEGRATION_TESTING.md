# CERTInext Integration Tests

This project contains xUnit integration tests that exercise the CERTInext plugin against
the live CERTInext REST API.  All tests skip automatically when credentials are absent,
so the project is safe to include in CI pipelines that do not have API access.

---

## Prerequisites

- .NET 8 or .NET 10 SDK
- Access to a CERTInext account (sandbox or production)
- An API Access Key generated in the CERTInext portal under **Integrations → APIs**

---

## Credential Setup

Create the file `~/.env_certinext` with the following content:

```sh
# CERTInext API credentials
CERTINEXT_API_URL=https://api.certinext.io/emSignHub-API/
CERTINEXT_ACCESS_KEY=your-access-key-here
CERTINEXT_ACCOUNT_NUMBER=your-account-number
CERTINEXT_GROUP_NUMBER=your-group-number
CERTINEXT_ORG_NUMBER=your-org-number
CERTINEXT_PRODUCT_CODE=838
CERTINEXT_REQUESTOR_EMAIL=you@example.com
CERTINEXT_REQUESTOR_NAME=Your Name
```

### Field reference

| Variable | Required | Description |
|----------|----------|-------------|
| `CERTINEXT_API_URL` | Yes | Base URL of the CERTInext API, e.g. `https://api.certinext.io/emSignHub-API/` |
| `CERTINEXT_ACCESS_KEY` | Yes | REST API Access Key from the CERTInext portal (Integrations → APIs) |
| `CERTINEXT_ACCOUNT_NUMBER` | Yes | Your CERTInext account number (numeric string) |
| `CERTINEXT_GROUP_NUMBER` | No | Group number for order filtering |
| `CERTINEXT_ORG_NUMBER` | No | Organization number for order placement |
| `CERTINEXT_PRODUCT_CODE` | No | Default product code (e.g. `838` for DV SSL) |
| `CERTINEXT_REQUESTOR_EMAIL` | No | Email submitted with test orders |
| `CERTINEXT_REQUESTOR_NAME` | No | Name submitted with test orders |

### API URL reference

| Environment | URL |
|-------------|-----|
| Sandbox (US) | `https://sandbox-us-api.certinext.io/emSignHub-API/` |
| Production (US) | `https://us-api.certinext.io/emSignHub-API/` |
| Production (Global/India) | `https://api.certinext.io/emSignHub-API/` |

### Credential file format

The file is parsed line by line:
- Lines starting with `#` are treated as comments and ignored.
- Blank lines are ignored.
- Each line must be in `KEY=VALUE` format.
- Values are not quoted — do not surround values with `"` or `'`.
- Real environment variables override file values (useful for CI injection).

---

## Running the Tests

### Using dotnet CLI

```sh
dotnet test CERTInext.IntegrationTests/ --verbosity normal
```

### Using the Makefile

```sh
make integration-test
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

This makes the test project safe to include in CI pipelines where live credentials are
not available — the tests show up in the results as skipped rather than causing a
pipeline failure.

---

## Test Classes

### `ConnectivityTests`

| Test | What it checks |
|------|---------------|
| `Ping_ReturnsSuccess` | Calls `ValidateCredentials` endpoint; asserts no exception is thrown |

### `ProductTests`

| Test | What it checks |
|------|---------------|
| `GetProductDetails_ReturnsProducts` | Calls `GetProductDetails`; asserts the call succeeds; when products are returned, asserts product code `838` is present |

> Note: some CERTInext accounts return an empty list from `GetProductDetails` even though
> orders using those product codes are visible in `GetOrderReport`.  An empty list is
> treated as acceptable in this test — only the absence of an exception is mandatory.

### `OrderReportTests`

| Test | What it checks |
|------|---------------|
| `GetOrderReport_ReturnsOrders` | Fetches page 1; asserts at least one order is returned |
| `GetOrderReport_AllOrders_HaveRequiredFields` | For each order on page 1: `requestNumber`, `productCode`, and `orderDate` are non-empty |

### `PluginSmokeTests`

End-to-end tests exercising `CERTInextCAPlugin` via the `IAnyCAPlugin` interface with
a live `CERTInextClient` injected through the `(ICERTInextClient, CERTInextConfig)`
test constructor.

| Test | What it checks |
|------|---------------|
| `Ping_ThroughPlugin_Succeeds` | Calls `IAnyCAPlugin.Ping()`; asserts no exception |
| `GetProductIds_ReturnsAtLeastOneProduct` | Calls `IAnyCAPlugin.GetProductIds()`; asserts a non-null list is returned without throwing |
| `Synchronize_ReturnsAtLeastOneRecord` | Runs a full sync; asserts at least one `AnyCAPluginCertificate` record is produced |

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

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| All tests skipped | Missing or empty `~/.env_certinext` | Create the file with required variables |
| `Ping` fails with 401 | Wrong `CERTINEXT_ACCESS_KEY` | Regenerate the key in the CERTInext portal |
| `Ping` fails with timeout | Wrong `CERTINEXT_API_URL` | Verify the URL matches your account region |
| `GetOrderReport` returns 0 orders | Account has no orders | Place a test order first (see `make generate-order` in the project Makefile) |
