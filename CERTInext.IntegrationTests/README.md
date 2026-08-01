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
just probe-products
```

This places `saveAndHold=1` draft orders for all known SSL/TLS product codes and reports
which ones return a `requestNumber` (valid) vs. an error (invalid or not provisioned).

---

## Prerequisites

- .NET 8 or .NET 10 SDK
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
| `CERTINEXT_PRODUCT_CODE` | Yes | Numeric product code for the target account. **This is per-account** — obtain the correct code for your account by calling `GetProductDetails` (or `just probe-products`). Default shown is for sandbox account `9374221333`. |
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

### `SmokeTests`

An older, broader smoke-test class that predates the more focused classes above. Its
`Ping_Succeeds`, `GetProductDetails_ReturnsProducts`, and `ListOrders_ReturnsFirstPage`
tests cover the same ground as `ConnectivityTests`, `ProductTests`, and `OrderReportTests`
respectively (calling `ICERTInextClient` directly rather than going through the plugin),
and `Synchronize_DumpsAllRecords` overlaps with `PluginSmokeTests.Synchronize_ReturnsAtLeastOneRecord`.
It has not been removed because it still carries two scenarios the newer classes don't
cover: `TrackOrder_ReturnsDetails` and the per-order sweep in `GetSingleRecord_ForAllOrders_AllSucceed`.
All tests here are gated by `IntegrationSkip.IfNotConfigured`.

| Test | What it checks |
|------|---------------|
| `Ping_Succeeds` | Calls `ICERTInextClient.PingAsync`; asserts no exception (overlaps `ConnectivityTests.Ping_ReturnsSuccess`) |
| `GetProductDetails_ReturnsProducts` | Calls `ICERTInextClient.GetProductDetailsAsync`; asserts a non-empty product list (overlaps `ProductTests.GetProductDetails_ReturnsProducts`) |
| `ListOrders_ReturnsFirstPage` | Iterates `ICERTInextClient.ListOrdersAsync(pageSize: 10)`, capped at 10 entries; asserts at least one order is returned (overlaps `OrderReportTests.GetOrderReport_ReturnsOrders`) |
| `TrackOrder_ReturnsDetails` | Requires `CERTINEXT_ORDER_ID` env var (skips if unset); calls `ICERTInextClient.TrackOrderAsync`; asserts a non-null `OrderDetails` and logs status/DCV fields |
| `GetSingleRecord_ReturnsRecord` | Requires `CERTINEXT_ORDER_ID` env var (skips if unset); builds a plugin via the `(client, config)` test constructor and calls `GetSingleRecord`; asserts a non-null record |
| `GetSingleRecord_ForAllOrders_AllSucceed` | Lists every order on the account, then calls `GetSingleRecord` for each; asserts every call succeeds (no per-order failures) regardless of certificate status |
| `Synchronize_DumpsAllRecords` | Runs a full `plugin.Synchronize`; asserts the account returns at least one record and logs up to 20 of them (overlaps `PluginSmokeTests.Synchronize_ReturnsAtLeastOneRecord`) |

### `DcvLifecycleTests`

End-to-end tests for the DNS DCV enrollment path, run through `CERTInextCAPlugin`
directly (not the `IAnyCAPlugin` interface). DNS validator selection: when
`CERTINEXT_CF_API_TOKEN` and `CERTINEXT_CF_ZONE_ID` are set, a real `CloudflareDomainValidator`
publishes and cleans up an actual TXT record around the enrollment; otherwise a
`StubDomainValidator` is used and the plugin still runs the full DCV orchestration
path (Stage → propagation wait → VerifyDcv → Cleanup), but CERTInext's own DCV
verification is not guaranteed to succeed. `CERTINEXT_DCV_DOMAIN` overrides the
domain used (default `dcv-test.example.com`). All tests are gated by
`IntegrationSkip.IfNotConfigured`; several are additionally opt-in or require extra
environment variables, noted below.

| Test | What it checks |
|------|---------------|
| `DcvEnroll_CompletesWithoutThrowing` | Enrolls a DV cert with `DcvEnabled=true` against `CERTINEXT_DCV_DOMAIN`; with real Cloudflare DNS asserts the result is `GENERATED` or `EXTERNALVALIDATION`; with the stub validator only asserts a non-null result (VerifyDcv may legitimately fail) |
| `EnrollWithoutDcv_DoesNotInvokeDnsProvider` | Enrolls with `DcvEnabled=false`; asserts the plugin still returns a non-null result via the normal (non-DCV) enrollment flow |
| `EnrollWithDcvOff_OrderAppearsInSync_PluginDidNotInvokeDcv` | Enrolls a fresh random subdomain with `DcvEnabled=false`, then runs `Synchronize`; asserts the order surfaces with `EXTERNALVALIDATION` or `GENERATED` (never `FAILED`) — live verification for GitHub issue #7 that DCV-off does not invoke the DNS provider |
| `EnrollWithDcvOn_OrderIssuedEndToEnd_AndAppearsInSync` | Enrolls a fresh random subdomain with `DcvEnabled=true`, drives DCV via Cloudflare TXT publish/verify, then syncs; asserts the enrolled order reaches `GENERATED` with a parseable cert PEM, and that `GetSingleRecord` returns the same PEM (regression for issue 0001's cert-body-on-sync fix) |
| `EnrollWithDcvOn_IssuesPerKeyAlgorithm` (theory, 10 rows — see `KeyAlgorithms`: RSA-2048/3072/4096/6144/8192, ECDSA-P256/P384/P521, Ed25519, Ed448) | Opt-in via `CERTINEXT_ALGO_MATRIX_DCV=1`, requires Cloudflare DCV credentials. For each algorithm, enrolls a fresh scrup.org DV order, drives DCV to issuance, and asserts the issued cert's public key matches the requested algorithm/size. A CA-side rejection at submission, a `FAILED` order, or an order that doesn't reach `GENERATED` within the polling window is reported as an explicit `Skip` carrying the observed reason rather than a hard failure |
| `GetSingleRecord_DrivesDcvForPendingOrder` | Requires `CERTINEXT_PENDING_ORDER_ID` env var (skips if unset) and Cloudflare DCV credentials (skips if absent). Calls `GetSingleRecord` against a real pending order parked at "Pending System RA"/`dcvStatus=0`; asserts the deferred-DCV retry runs (TXT publish → VerifyDcv → wait → cleanup) and returns `GENERATED` or `EXTERNALVALIDATION` rather than silently no-op'ing |
| `BulkDvEnrollment_AllOrdersIssue_AndPaginationWorks` | Opt-in via `CERTINEXT_RUN_BULK_TEST=1` (default count 101, overridable via `CERTINEXT_BULK_TEST_COUNT`/`CERTINEXT_BULK_TEST_PARALLEL`), requires Cloudflare DCV credentials. Enrolls the configured count of DV orders concurrently, then repeatedly runs `Synchronize` (PageSize=100) until every order reaches `GENERATED` or the pass budget is exhausted; asserts every enrollment succeeds, every order appears in sync, and sync returns >100 records (proves the `ListCertificatesAsync` paginator crosses the page boundary) |
| `CompleteAllPendingDvOrders` | Opt-in via `CERTINEXT_COMPLETE_PENDING=1`, requires Cloudflare DCV credentials. Operational cleanup task — enrolls nothing; repeatedly runs `Synchronize` to drive every existing `EXTERNALVALIDATION` order to `GENERATED`, asserting no order remains pending after the pass budget |
| `FullSync_AllIssuedCerts_CarryParseableCertificateBody` | Runs a full `Synchronize` with `DcvEnabled=false`; asserts the account has at least one `GENERATED` record and every `GENERATED` record carries a parseable certificate PEM body (regression for issue 0001 — the order-report listing carries no body, so the plugin must refetch it) |

### `AlgorithmMatrixTests`

Coverage matrix for the CSR key algorithm/size the plugin submits, since every other
test in the suite hardcodes an RSA-2048 CSR. Covers 10 algorithm tags (see
`KeyAlgorithms.All`): `RSA-2048`, `RSA-3072`, `RSA-4096`, `RSA-6144`, `RSA-8192`,
`ECDSA-P256`, `ECDSA-P384`, `ECDSA-P521`, `Ed25519`, `Ed448`. This class only covers
CSR validity and CA submission acceptance — the end-to-end "does CERTInext actually
*issue* this algorithm" matrix (DCV on, real issuance) lives in
`DcvLifecycleTests.EnrollWithDcvOn_IssuesPerKeyAlgorithm`.

| Test | What it checks |
|------|---------------|
| `Csr_RoundTripsKeyAlgorithm` (theory, all 10 algorithm tags) | Fully offline, no API, always runs (not gated by `IntegrationSkip`). Generates a CSR for each algorithm via BouncyCastle, re-parses it, and asserts the request signature verifies and the public key type/size (RSA modulus bits, EC field size, or Ed25519/Ed448 key type) round-trips correctly |
| `Enroll_AcceptsKeyAlgorithm` (theory, all 10 algorithm tags) | Gated by `IntegrationSkip.IfNotConfigured` and opt-in via `CERTINEXT_ALGO_MATRIX=1` (each run creates a real, non-issued DV order on the sandbox — no DCV is performed, so orders park at `EXTERNALVALIDATION` and are not cleaned up). Submits a real order per algorithm and asserts CERTInext accepts it (returns a `CARequestID`); a CA-side rejection is reported as an explicit `Skip` carrying the classified reason (unsupported key size vs. insufficient credits) rather than a failure |

### `CnameResolverLiveDnsTests`

Live-DNS validation for the production `Dcv.CnameResolver` (issue 0006), exercised
against real public DNS via `DnsClient.NET` rather than a fake single-hop delegate.
Deliberately does **not** go through CERTInext order placement — it only stages
CNAME records in the Cloudflare zone used for DCV tests and resolves them. Neither
test calls `IntegrationSkip.IfNotConfigured` and neither hits the CERTInext API at
all; both only require Cloudflare DNS credentials (`Skip.If(!_fixture.IsCloudflareConfigured, ...)`
— i.e. `CERTINEXT_CF_API_TOKEN`, `CERTINEXT_CF_ZONE_ID`, and `CERTINEXT_DCV_DOMAIN`).
Because this class depends only on live public DNS, its behavior does not vary with
CERTInext account state (fresh sandbox vs. account with history).

| Test | What it checks |
|------|---------------|
| `ResolveTerminalNameAsync_FollowsRealTwoHopCnameChain` | Creates a two-hop CNAME chain (hopA → hopB → hopC, where hopC is never created and is therefore terminal) in the Cloudflare zone, then asserts `CnameResolver.ResolveTerminalNameAsync` walks the real chain to hopC, retrying up to 8 times (3s apart) to absorb DNS propagation delay |
| `ResolveTerminalNameAsync_NoCname_ReturnsInputUnchanged` | Resolves the DCV domain apex (which carries ordinary A/AAAA/TXT records, no CNAME); asserts the resolver returns the input name unchanged (terminal-on-first-hop path against real DNS) |

### `IntegrationTestFixtureTests`

Pure unit tests for the `~/.env_certinext` line parser (`IntegrationTestFixture.ParseEnvValue`),
riding inside the integration test project rather than exercising the CERTInext API.
None of these tests call `IntegrationSkip.IfNotConfigured` and none use `[SkippableFact]`
— they are plain xUnit `[Fact]`/`[Theory]` tests that always run, with no credentials
or account state required.

| Test | What it checks |
|------|---------------|
| `ParseEnvValue_HandlesQuotingAndWhitespace` (theory, 11 rows) | Asserts whitespace trimming and single-pair quote stripping (double or single quotes) for plain, padded, quoted, empty-quoted, mismatched-quote, and blank inputs — regression for GitHub issue #8, where a shell-style quoted value was parsed with the quote characters still included |
| `ParseEnvValue_NullInput_ReturnsEmptyString` | Asserts a `null` input returns `string.Empty` rather than throwing |
| `ParseEnvValue_DoesNotStripEmbeddedQuotes` | Asserts quotes embedded in the middle of a value (not matching outer wrappers) are left untouched |

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
| `SmokeTests` | `TrackOrder_ReturnsDetails` and `GetSingleRecord_ReturnsRecord` skip unless `CERTINEXT_ORDER_ID` is set; `GetSingleRecord_ForAllOrders_AllSucceed` and `Synchronize_DumpsAllRecords` pass trivially against zero orders |
| `DcvLifecycleTests` | Core tests (`DcvEnroll_CompletesWithoutThrowing`, `EnrollWithoutDcv_DoesNotInvokeDnsProvider`, the two `EnrollWithDcvO*_...AppearsInSync` tests) run regardless of account history; the opt-in tests (`EnrollWithDcvOn_IssuesPerKeyAlgorithm`, `BulkDvEnrollment_AllOrdersIssue_AndPaginationWorks`, `CompleteAllPendingDvOrders`) are skipped unless explicitly enabled via their env-var flags; `GetSingleRecord_DrivesDcvForPendingOrder` skips unless `CERTINEXT_PENDING_ORDER_ID` is set |

### Account with history (orders previously placed)

| Test class | Expected result |
|-----------|----------------|
| `ConnectivityTests` | Pass |
| `ProductTests` | Pass |
| `OrderReportTests` | Pass |
| `PluginSmokeTests` | Pass |
| `LifecycleTests` | Pass (all three steps) |
| `SmokeTests` | Pass (all seven tests, given `CERTINEXT_ORDER_ID` is set for the two order-specific tests) |
| `DcvLifecycleTests` | Core tests pass; opt-in tests pass when their env-var flags and Cloudflare DCV credentials are set |

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

1. **Discover valid product codes** — run `just probe-products` from the repo root.  This places
   `saveAndHold=1` draft orders for all known SSL/TLS product codes and reports which ones your
   account accepts.  Use the first DV SSL code that returns a `requestNumber` as your
   `CERTINEXT_PRODUCT_CODE`.

2. **Set `CERTINEXT_GROUP_NUMBER`** — if `just probe-products` or `GetProductDetails` returns no
   products, find your group number in the CERTInext portal under **Delegation → Groups** and add
   it to `~/.env_certinext`.  The `GetProductDetails` API requires it on some accounts.

3. **Run connectivity tests first** — `just integration-test` or
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
| `Enroll` fails with "Invalid Product Code" (EMS-1162) | Wrong `CERTINEXT_PRODUCT_CODE` | Run `just probe-products` to discover the codes provisioned for your account |
| `GetProductDetails` returns empty list | `CERTINEXT_GROUP_NUMBER` not set | Add your group number to `~/.env_certinext`; some accounts require it for `GetProductDetails` to return results |
| `Enroll` fails with "Additional Information cannot be empty" (EMS-918) | Old plugin version missing `additionalInformation.remarks` | Rebuild and redeploy the plugin — the `remarks` field is now populated automatically |
| `Enroll` fails with "Invalid Organization Number" (EMS-1073) | OV/EV product code selected with an unregistered org | Use a DV SSL product code for automated tests, or register and approve your org in CERTInext first |
| Revoke step skips with "not GENERATED" | Sandbox DV SSL order requires domain validation and RA approval | Expected behavior for public DV SSL in sandbox — log in to the CERTInext portal and approve the pending order, then re-run; or use a private PKI product that auto-approves |
| `OrderReportTests` all skip | Fresh account with no orders | Run `LifecycleTests` first to place at least one order |
| `ProductTests` asserts configured product code is not found | `CERTINEXT_PRODUCT_CODE` set to a code not provisioned for the account | Run `just probe-products` and update `CERTINEXT_PRODUCT_CODE` with a valid code |
