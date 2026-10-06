# CERTInext Integration Tests — Test Catalog

This page lists the tests in `CERTInext.IntegrationTests`, what each one checks, and what to expect
for a given account state. For credentials, opt-in flags, and run commands, see
[INTEGRATION_TESTING.md](INTEGRATION_TESTING.md).

Every live test skips (is reported as Skipped, not Failed) when its credentials or opt-in flag are
absent. Tests marked **opt-in** place real orders, publish DNS records, or cancel orders, and run
only when their flag is exported in the shell.

---

## Product Codes Are Per-Account

CERTInext product codes are provisioned per account by eMudhra. The codes your account can order
are set when the account is created and can differ from documentation examples and from other
accounts. Notes that apply when choosing `CERTINEXT_PRODUCT_CODE`:

- `GetProductDetails` returns an empty list on some sandbox accounts unless the request carries
  `groupNumber`. The plugin sends it automatically when `GroupNumber` is configured.
- Private PKI codes (for example `100`, or `149` for the sandbox "emSign Intranet SSL") need a
  separate entitlement. On an account without it, placing an order returns `EMS-1162: Invalid
  Product Code` even when the code appears in the catalog.
- EV SSL needs a registered and approved `organizationNumber`; an unregistered one returns
  `EMS-1073: Invalid Organization Number`.
- The V1 `GenerateOrderSSL` call requires `additionalInformation.remarks`; the plugin always sends it.

To discover the codes your account accepts:

```sh
make probe-products
```

This places `saveAndHold=1` draft orders for the known SSL/TLS product codes and reports which return
a `requestNumber` (valid) and which return an error (invalid or not provisioned).

---

## Test Classes

### V1 — read-only and basic

| Class | Test | What it checks |
|---|---|---|
| `ConnectivityTests` | `Ping_ReturnsSuccess` | `ValidateCredentials` succeeds |
| `ProductTests` | `GetProductDetails_ReturnsProducts` | `GetProductDetails` succeeds; when products come back, the configured product code is among them. An empty list is accepted, because some accounts return one |
| | `ValidateProductInfo_V1_AcceptsConfiguredProductCode` | `CERTInextCAPlugin.ValidateProductInfo` in V1 mode accepts `CERTINEXT_PRODUCT_CODE`; skips if it is unset |
| `OrderReportTests` | `GetOrderReport_ReturnsOrders` | Page 1 of `GetOrderReport` is non-empty; skips when the account has no orders |
| | `GetOrderReport_AllOrders_HaveRequiredFields` | Every order on page 1 has `requestNumber`, `productCode`, and `orderDate`; skips when the account has no orders |
| `PluginSmokeTests` | `Ping_ThroughPlugin_Succeeds` | `IAnyCAPlugin.Ping()` through a live client |
| | `GetProductIds_ReturnsAtLeastOneProduct` | `IAnyCAPlugin.GetProductIds()` returns a non-null list |
| | `Synchronize_ReturnsAtLeastOneRecord` | A full sync produces at least one record; skips when the account has none |
| `SmokeTests` | `Ping_Succeeds`, `GetProductDetails_ReturnsProducts`, `ListOrders_ReturnsFirstPage` | Client-level checks of the same endpoints |
| | `TrackOrder_ReturnsDetails`, `GetSingleRecord_ReturnsRecord` | Look up the order in `CERTINEXT_ORDER_ID`; skip when it is unset |
| | `GetSingleRecord_ForAllOrders_AllSucceed`, `Synchronize_DumpsAllRecords` | Read every order and write the results to the test output |

### V1 — order lifecycle

| Class | Test | What it checks |
|---|---|---|
| `LifecycleTests` | `Enroll_Synchronize_Revoke_FullLifecycle` | Generates an RSA-2048 CSR, enrolls it and asserts a `CARequestID`, runs a full sync and finds the new order, then attempts revocation. Skips gracefully if the order isn't issued yet |
| `AlgorithmMatrixTests` | `Csr_RoundTripsKeyAlgorithm` | Offline: each key algorithm in the matrix generates a CSR whose signature verifies and whose public key parses back to the same type and size |
| | `Enroll_AcceptsKeyAlgorithm` | **Opt-in** (`CERTINEXT_ALGO_MATRIX`). Submits one order per key algorithm and records whether CERTInext accepts it. CERTInext accepts RSA 2048/3072/4096 and ECC P-256/P-384, and rejects larger RSA, ECC P-521, and Ed25519/Ed448 |

### V1 — DNS-01 DCV (need Cloudflare credentials unless noted)

| Class | Test | What it checks |
|---|---|---|
| `DcvLifecycleTests` | `DcvEnroll_CompletesWithoutThrowing` | An enrollment with DCV enabled completes |
| | `EnrollWithoutDcv_DoesNotInvokeDnsProvider` | With DCV disabled, the DNS provider is never called |
| | `EnrollWithDcvOff_OrderAppearsInSync_PluginDidNotInvokeDcv` | An order placed with DCV off still appears in a full sync, and the plugin didn't run DCV |
| | `EnrollWithDcvOn_OrderIssuedEndToEnd_AndAppearsInSync` | Enroll with DCV on, issue the certificate, and find it in a sync |
| | `EnrollWithDcvOn_IssuesPerKeyAlgorithm` | **Opt-in** (`CERTINEXT_ALGO_MATRIX_DCV`). DCV issuance for each key algorithm |
| | `GetSingleRecord_DrivesDcvForPendingOrder` | Needs `CERTINEXT_PENDING_ORDER_ID`. A single-record refresh drives a pending order through DCV |
| | `BulkDvEnrollment_AllOrdersIssue_AndPaginationWorks` | **Opt-in** (`CERTINEXT_RUN_BULK_TEST`). Many concurrent DV enrollments all issue, and sync pagination returns them |
| | `CompleteAllPendingDvOrders` | **Opt-in** (`CERTINEXT_COMPLETE_PENDING`). Repeated full syncs until no DV order remains pending |
| | `FullSync_AllIssuedCerts_CarryParseableCertificateBody` | Every issued record from a full sync carries a parseable certificate |
| `PendingDvDiagnosticsTests` | `PendingDvDiagnostics_DumpDcvState` | Diagnostic. Needs `CERTINEXT_DIAG_ORDER_IDS`. Read-only dump of each listed order's DCV state |

### V2 — API and lifecycle

The V2 tests skip unless the V2 credentials are present (see [INTEGRATION_TESTING.md](INTEGRATION_TESTING.md#skip-behaviour)).

| Class | Test | What it checks |
|---|---|---|
| `V2ApiTests` | `Connectivity_V2_Ping` | `GET /auth/me` succeeds with an OAuth token |
| | `Lifecycle_V2_EnrollTrackRevoke` | Enroll, track, and revoke through the V2 API |
| | `Sync_UsesV2_WithZeroV1Credentials` | Synchronize works with no V1 credentials configured |
| | `GetProductDetails_V2_ReturnsProducts` | The V2 catalog returns products |
| | `ValidateProductInfo_V2_AcceptsConfiguredProductCode`, `ValidateProductInfo_V2_RejectsUnknownProductCode` | Template validation against the V2 catalog |
| | `GetSingleRecord_V2_ReturnsOrderDetails`, `Revoke_V2_IssuedOrder`, `ChainPem_V2_IsAssembled` | Single-record lookup, revocation, and chain assembly for an issued order (`CERTINEXT_V2_ISSUED_ORDER_ID`, or a fresh order) |
| | `DcvFlow_V2_PublishesAndVerifies` | Needs Cloudflare. The V2 DCV flow publishes the TXT record and CERTInext verifies it |
| `V2LifecycleTests` | `Enroll_V2_ReturnsCARequestID`, `Enroll_Synchronize_Revoke_V2_FullLifecycle` | V2 enrollment returns an ID; a full enroll, sync, revoke cycle |
| | `Revoke_V2_ExplicitOrder_Superseded`, `Revoke_V2_IssuedOrder_ReturnsRevoked` | Revocation with an explicit reason, and of an issued order (`CERTINEXT_REVOKE_ORDER_ID`) |
| | `GetSingleRecord_V2_Plugin_ReturnsDetails`, `GetSingleRecord_V2_IssuedOrder_HasParseableCertBody`, `GetSingleRecord_V2_AllSyncedOrders_DoNotThrow` | Single-record lookup through the plugin |
| | `Sync_V2_UsesV2ReportsOrders_ReturnsRecords`, `Sync_V2_WithZeroV1Credentials_Succeeds`, `Sync_V2_SmallPageSize_PaginatesAcrossMultiplePages` | V2 synchronization, with no V1 credentials and across several small pages |
| | `Sync_V2_FullSync_PaginatesEntireHistory` | Set `CERTINEXT_V2_FULL_SYNC_TEST` to run it; can be slow on a shared account |
| `V2DcvLifecycleTests` | `DcvEnroll_V2_CompletesWithoutThrowing`, `EnrollWithoutDcv_V2_DoesNotInvokeDnsProvider`, `GetSingleRecord_V2_DrivesDcvForPendingOrder`, `EnrollWithDcvOn_V2_OrderIssuedEndToEnd_AndAppearsInSync` | The V2 counterparts of the V1 DCV tests (`CERTINEXT_V2_PENDING_ORDER_ID` for the single-record one) |
| | `EnrollWithDcvOn_V2_IssuesPerKeyAlgorithm` | **Opt-in** (`CERTINEXT_V2_ALGO_MATRIX`) |
| | `BulkV2Enrollment_AllOrdersIssue_AndPaginationWorks` | **Opt-in** (`CERTINEXT_V2_RUN_BULK_TEST`) |
| `V2FreshDomainDcvLifecycleTests` | `EnrollWithDcvOn_V2_FreshUnverifiedSubdomain_StagesAndCleansUpTxt`, `EnrollWithDcvOn_V2_WildcardFreshSubdomain_RecordsTxtHostnameAndCleansUp` | **Opt-in** (`CERTINEXT_V2_LIFECYCLE_FRESH_DCV`). DCV against a never-validated subdomain, and against a wildcard on one: the TXT record is staged at the expected hostname and removed afterward |
| `V2FullLifecycleTests` | `Enroll_V2_DvUcc_WithMultipleSans_FullLifecycle`, `Enroll_V2_Ov_FullLifecycle`, `Enroll_V2_OvUcc_WithMultipleSans_FullLifecycle`, `Enroll_V2_Ev_FullLifecycle`, `Enroll_V2_WildcardDv_WildcardOnly_FullLifecycle`, `Enroll_V2_WildcardDv_WildcardPlusApexSan_RecordsActualBehavior`, `EnrollRenewReissue_V2_IssuedDvOrder_RecordsActualBehavior` | **Opt-in** (one `CERTINEXT_V2_LIFECYCLE_*` flag per product, see [INTEGRATION_TESTING.md](INTEGRATION_TESTING.md#opt-in-flags)). Each enrolls, waits, synchronizes, and cleans up its order |
| `PrivatePkiV2LiveTests` | `PrivatePki_V2_EnrollIntranetSsl_ThenRevoke_Live` | **Opt-in** (`CERTINEXT_PRIVATE_PKI_LIVE`). Enrolls a Private PKI Intranet SSL order with DNS and IP SANs, checks the issued SANs, and revokes it. Needs a Private PKI entitlement |
| | `PrivatePki_V2_RecordingProxy_BuildsOffline` | Offline sanity check of the test's recording proxy |
| `V2OrderWindowSweepTests` | `Sweep_ListRecentOrders_ByWindow_DryRun_ThenCancelExplicitIds` | **Opt-in** (`CERTINEXT_V2_OPS_TESTS`). Operations tool: lists V2 orders in a date window and optionally cancels listed IDs |

### Offline tests and utilities

| Class | What it covers |
|---|---|
| `IntegrationTestFixtureTests` | Parsing of `KEY=VALUE` env-file values: quote handling and null input |
| `V1FixtureApiUrlGuardTests` | The V1 fixture rejects a V2 `CERTINEXT_API_URL`; the V2 file loader never promotes V1 keys or opt-in flags into the process environment |
| `KfclabCsrEmitterTests` | Utility, not an API test. With `CERTINEXT_EMIT_CSR_DIR` and `CERTINEXT_EMIT_CSR_SPEC` set, writes CSR files for use by external tooling. Makes no CA calls |

Shared helpers (not tests): `IntegrationTestFixture`, `IntegrationSkip`, `KeyAlgorithms`,
`V2EnvHelper`, `V2DomainStatusHelper`, `V2RawHttpHelpers`, and the DNS validators
`CloudflareDomainValidator`, `RecordingDomainValidator`, and `StubDomainValidator`.

---

## Expected Outcomes by Account State

### Fresh sandbox account (no prior orders)

| Test class | Expected result |
|-----------|----------------|
| `ConnectivityTests` | Pass — credentials only |
| `ProductTests` | Pass — the product list may be empty if `CERTINEXT_GROUP_NUMBER` is unset and the account needs it; the test tolerates an empty list |
| `OrderReportTests` | Skip — "account has no orders yet" |
| `PluginSmokeTests.Synchronize_ReturnsAtLeastOneRecord` | Skip — "account has no certificate records yet" |
| `LifecycleTests.Enroll_Synchronize_Revoke_FullLifecycle` | Skip with "Invalid Product Code" if `CERTINEXT_PRODUCT_CODE` isn't provisioned for the account; otherwise enroll and sync pass, and revoke skips because a sandbox DV order needs domain validation before it is issued |

### Account with history

| Test class | Expected result |
|-----------|----------------|
| `ConnectivityTests`, `ProductTests`, `OrderReportTests`, `PluginSmokeTests` | Pass |
| `LifecycleTests` | Pass for enroll and sync; revoke runs only if the new order is issued |

The DCV tests complete a DV order end to end only when Cloudflare credentials are configured and the
domain in `CERTINEXT_DCV_DOMAIN` is in that zone. Without them, the revoke step of `LifecycleTests`
skips, because DV orders on the sandbox can't be issued without domain validation.

### Fresh account setup

1. **Discover valid product codes** with `make probe-products`. Use the first DV SSL code that
   returns a `requestNumber` as `CERTINEXT_PRODUCT_CODE`.
2. **Set `CERTINEXT_GROUP_NUMBER`** if `make probe-products` or `GetProductDetails` returns no
   products. Find it in the portal under **Delegation → Groups**.
3. **Run `ConnectivityTests` first**, then `LifecycleTests`, which places a real order and can run
   before any orders exist.
4. **Expect the revoke step to skip** without DCV. To exercise revocation, configure Cloudflare so a
   DV order can issue, or use a product that issues without domain validation.
