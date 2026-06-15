# CERTInext CA Plugin — Unit Test Suite Reference

## Overview

The `CERTInext.Tests` project contains unit and contract tests for the CERTInext AnyCA Gateway
REST plugin. No external services are required — all HTTP I/O is handled in-process by WireMock.Net
or replaced by Moq strict mocks.

The project is split into several focused test classes:

| Class | Layer under test | Isolation technique |
|---|---|---|
| `CERTInextClientTests` | `CERTInextClient` HTTP transport | WireMock.Net (real loopback HTTP) |
| `CERTInextClientRequestShapeTests` | `CERTInextClient` request body construction | WireMock.Net |
| `CERTInextCAPluginTests` | `CERTInextCAPlugin` IAnyCAPlugin logic | Moq strict mock of `ICERTInextClient` |
| `CERTInextCAPluginCoverageTests` | Additional plugin logic paths | Moq strict mock |
| `CERTInextCAPluginPublicSurfaceTests` | Binary-compat / no-DCV surface contract | Reflection only |
| `BoundedDcvSyncTests` | DCV sync age/cap filter logic | Pure unit (no I/O) |
| `RateLimitRetryTests` | Rate-limit back-off helpers | Pure unit (no I/O) |
| `ExtractSerialFromPemTests` | PEM serial-number extraction | Pure unit (no I/O) |
| `RedactCredentialsTests` | Log credential-redaction helper | Pure unit (no I/O) |

If a test fails in `CERTInextClientTests` or `CERTInextClientRequestShapeTests`, the bug is in
HTTP transport or request serialisation. If it fails in `CERTInextCAPluginTests` or
`CERTInextCAPluginCoverageTests`, the bug is in plugin logic.

---

## Running the Tests

**Prerequisites:**
- .NET 8 or .NET 10 SDK
- NuGet packages restored (`dotnet restore`)
- No external services required

**Run all tests:**
```bash
dotnet test CERTInext.Tests/
```

**Run a single test class:**
```bash
dotnet test --filter "FullyQualifiedName~CERTInextClientTests"
dotnet test --filter "FullyQualifiedName~CERTInextCAPluginTests"
```

**Run a specific test by name:**
```bash
dotnet test --filter "DisplayName~OAuth2_TokenIsCached"
```

Each `CERTInextClientTests` instance starts a fresh `WireMockServer` in its constructor and
stops it in `Dispose()`, so tests are isolated and can run in parallel without port conflicts.

---

## Authentication model

The real CERTInext API uses HTTP POST for **all** endpoints. There is no Authorization header
for AccessKey mode. Instead, every request body includes a `meta` block containing:

- `authKey` — `SHA256(accessKey + requestTs + requestTxnId)` (lowercase hex)
- `ts` — ISO 8601 timestamp
- `txn` — unique transaction UUID

The raw access key is never transmitted — only the derived hash is sent.

`AuthMode` accepted values:
- `AccessKey` (primary) — HMAC signed body
- `OAuth` (alternative) — bearer token via client credentials flow
- `ApiKey`, `AccessKeyLegacy`, `OAuthLegacy` — legacy aliases accepted for backward compatibility

---

## CERTInextClientTests

The test class implements `IDisposable`. A `WireMockServer` is started on a random available port
in the constructor. All tests build a `CERTInextClient` pointed at `_server.Urls[0]`.

Two helper methods build clients:
- `BuildClient(authMode, apiKey)` — builds an AccessKey-authenticated client
  (defaults: `authMode="AccessKey"`, `apiKey="test-key"`, `accountNumber="12345"`)
- `BuildOAuthClient(tokenUrl)` — builds an OAuth client with `client_id="my-client"`,
  `client_secret="my-secret"`

### PingAsync — POST /ValidateCredentials

| Test | Stub | Assertion |
|------|------|-----------|
| `PingAsync_ReturnsHealthy_WhenServerRespondsOk` | `POST /ValidateCredentials` → 200, success meta | Does not throw; WireMock log contains a request to `/ValidateCredentials` |
| `PingAsync_Throws_When500Returned` | `POST /ValidateCredentials` → 500, server error body | Throws `Exception` with message containing `"health check failed"` |
| `PingAsync_Throws_WhenMetaStatusIsFailure` | `POST /ValidateCredentials` → 200, failure meta (`EMS-001`, `"Invalid credentials"`) | Throws `Exception` with message containing `"credential validation failed"` |

### OAuth2 Token Fetch, Caching, and Injection

| Test | Stub | Assertion |
|------|------|-----------|
| `OAuth2_FetchesToken_BeforeFirstApiCall` | `POST /oauth/token` → token JSON; `POST /ValidateCredentials` → 200 | Log contains both `/oauth/token` and `/ValidateCredentials` |
| `OAuth2_TokenIsCached_SecondCallDoesNotRefetch` | Same stubs | `PingAsync` called twice; `/oauth/token` appears exactly once; `/ValidateCredentials` appears twice |
| `OAuth_InjectsBearerToken_InAuthorizationHeader` | Token endpoint → `fake-bearer-token-abc123`; `/ValidateCredentials` → 200 | WireMock log entry for `/ValidateCredentials` carries `Authorization: Bearer fake-bearer-token-abc123` |
| `OAuth_DoesNotInjectBearerToken_InAccessKeyMode` | `/ValidateCredentials` → 200 | WireMock log entry has no `Authorization` header |

### Retry logic

| Test | Stub | Assertion |
|------|------|-----------|
| `ExecuteWithRetry_MakesThreeAttempts_WhenServerAlwaysReturns500` | `/ValidateCredentials` always → 500 | `PingAsync` throws; WireMock log has exactly 3 requests (3 total attempts, 4xx are not retried) |

### EnrollCertificateAsync — POST /GenerateOrderSSL

| Test | Stub | Assertion |
|------|------|-----------|
| `EnrollCertificateAsync_ReturnsCertificate_WhenServerIssues` | `POST /GenerateOrderSSL` → 200, success meta + `orderDetails.orderNumber="ORD-AAA-111"` | Result not null; `OrderNumber == "ORD-AAA-111"` |
| `EnrollCertificateAsync_ReturnsPending_WhenServerReturnsPendingApproval` | `POST /GenerateOrderSSL` → 200, pending response | Status maps to pending |
| `EnrollCertificateAsync_Throws_WhenGenerateOrderFails` | `POST /GenerateOrderSSL` → 200, failure meta (EMS-918) | Throws `Exception` containing the API error message |
| `EnrollCertificateAsync_Throws_When5xxReturned` | `POST /GenerateOrderSSL` → 500 | Throws `Exception` |
| `EnrollCertificateAsync_Throws_When401Returned` | `POST /GenerateOrderSSL` → 401 | Throws `Exception` |

### GetCertificateAsync — POST /GetCertificate

| Test | Stub | Assertion |
|------|------|-----------|
| `GetCertificateAsync_ReturnsCertificate_WhenFound` | `POST /GetCertificate` → 200, PEM in `certificateDetails.endEntityCertificate` | PEM contains `"BEGIN CERTIFICATE"`; serial `"0A1B2C3D4E5F"` |
| `GetCertificateAsync_ThrowsKeyNotFound_WhenOrderNotFound` | `POST /GetCertificate` → 200, failure meta (EMS-not-found) | Throws `KeyNotFoundException` |

### RevokeCertificateAsync — POST /RevokeOrder

| Test | Stub | Assertion |
|------|------|-----------|
| `RevokeCertificateAsync_Succeeds_When200Returned` | `POST /RevokeOrder` → 200, success meta | Does not throw |
| `RevokeCertificateAsync_Throws_WhenServerReturnsFailure` | `POST /RevokeOrder` → 200, failure meta | Throws `Exception` |

### RenewCertificateAsync — POST /GenerateOrderSSL

CERTInext has no dedicated renewal endpoint. `RenewCertificateAsync` submits a new
`GenerateOrderSSL` order. The test verifies that the correct endpoint and body are used.

| Test | Stub | Assertion |
|------|------|-----------|
| `RenewCertificateAsync_ReturnsNewCertificate_OnSuccess` | `POST /GenerateOrderSSL` → 200, success with new order number | New order number returned |

### ListCertificatesAsync — POST /GetOrderReport (paginated)

`ListCertificatesAsync` is an `IAsyncEnumerable<LegacyGetCertificateResponse>` that paginates
`GetOrderReport`. Pagination stops when the returned page is empty or all pages are fetched.

| Test | Stub | Assertion |
|------|------|-----------|
| `ListCertificatesAsync_ReturnsSinglePage_WhenOnlyOnePage` | `POST /GetOrderReport` → single-page with `ORD-AAA-111` | Enumeration yields exactly 1 item |
| `ListCertificatesAsync_IteratesMultiplePages` | Two pages: page 1 (`ORD-AAA-111`), page 2 (`ORD-BBB-222`) | Enumeration yields 2 items; both order numbers present |
| `ListCertificatesAsync_StopsWhenEmptyPageReturned` | `POST /GetOrderReport` → empty `ordersArray` | Enumeration yields 0 items |
| `ListCertificatesAsync_RespectsIssuedAfterFilter` | Any request with `issuedAfter` parameter → single-page | Enumeration yields 1 item; `issuedAfter` key present in the request log |

### GetProfilesAsync — POST /GetProductDetails

| Test | Stub | Assertion |
|------|------|-----------|
| `GetProfilesAsync_ReturnsProfiles_WhenServerResponds` | `POST /GetProductDetails` → two products in nested category envelope | Result has 2 items; `ProfileIdTls` and `ProfileIdClient` present; all `Active == true` |
| `GetProfilesAsync_ReturnsEmptyList_WhenNoProductsReturned` | `POST /GetProductDetails` → empty `productDetails` array | Result is empty |

### DCV endpoints

| Test | Stub | Assertion |
|------|------|-----------|
| `GetDcvAsync_ReturnsToken_WhenServerRespondsOk` | `POST /GetDcv` → 200, `dcvDetails.token="abc123token"` | Returns token string |
| `GetDcvAsync_Throws_WhenMetaStatusIsFailure` | `POST /GetDcv` → 200, failure meta | Throws `Exception` |
| `GetDcvAsync_Throws_WhenServerReturns401` | `POST /GetDcv` → 401 | Throws `Exception` |
| `VerifyDcvAsync_Succeeds_WhenServerRespondsOk` | `POST /VerifyDcv` → 200, success meta | Does not throw |
| `VerifyDcvAsync_Throws_WhenMetaStatusIsFailure` | `POST /VerifyDcv` → 200, failure meta | Throws `Exception` |
| `VerifyDcvAsync_Throws_WhenServerReturns401` | `POST /VerifyDcv` → 401 | Throws `Exception` |
| `VerifyDcvAsync_Throws_WhenServerReturns500` | `POST /VerifyDcv` → 500 | Throws `Exception` |

---

## CERTInextClientRequestShapeTests

Uses WireMock to verify that the `GenerateOrderSSL` request body includes or omits optional
blocks depending on connector configuration.

| Test | Assertion |
|------|-----------|
| `OrganizationNumber_Set_EmitsPreVettedOrganizationDetails` | Body includes `organizationDetails.preVetting="1"` and the configured `organizationNumber` |
| `OrganizationNumber_Blank_OmitsOrganizationDetailsBlock` | Body omits `organizationDetails` entirely |
| `GroupNumber_Set_EmitsDelegationInformation` | Body includes `delegationInformation.groupNumber` |
| `GroupNumber_Blank_OmitsDelegationInformation` | Body omits `delegationInformation` |
| `TechnicalContact_AllSet_EmitsExplicitValues` | Body includes `technicalPointOfContact` with the configured values |
| `TechnicalContact_AllBlank_FallsBackToRequestorDefaults` | Body includes `technicalPointOfContact` fields derived from `RequestorName`/`RequestorEmail` |
| `SslBodyDefaults_AreEmitted_FromCustomConnectorValues` | Custom connector-level defaults appear in the order body |
| `SslBodyDefaults_AreSafeFallbacks_WhenConfigUntouched` | Default values are emitted without throwing when optional config fields are omitted |
| `ValidityDays_OnRequest_OverridesConnectorDefault` | `ValidityDays` template parameter overrides the connector `SubscriptionValidityYears` |

---

## CERTInextCAPluginTests

The plugin is constructed with `new CERTInextCAPlugin(client)` where `client` is a Moq strict
mock of `ICERTInextClient`. Any call to an unset-up method throws immediately, making unexpected
client calls visible.

Two helpers are used across tests:
- `MakeProductInfo(profileId, extras)` — builds an `EnrollmentProductInfo` with `ProfileId` in
  `ProductParameters`
- `AsyncEnum(items)` — wraps a list as `IAsyncEnumerable<LegacyGetCertificateResponse>`

### Ping

| Test | Mock setup | Assertion |
|------|-----------|-----------|
| `Ping_Succeeds_WhenClientPingAsyncDoesNotThrow` | `PingAsync` returns `Task.CompletedTask` | Does not throw; `PingAsync` called exactly once |
| `Ping_Rethrows_WhenClientPingThrows` | `PingAsync` throws `Exception("Connection refused")` | Throws `Exception` with message matching `"*CERTInext*Connection refused*"` |
| `Ping_SkipsConnectivityTest_WhenConnectorIsDisabled` | Strict mock, no setups; `CERTInextConfig.Enabled = false` | Does not throw; no client method called (verified via `VerifyNoOtherCalls()`) |

### GetProductIds

| Test | Mock setup | Assertion |
|------|-----------|-----------|
| `GetProductIds_ReturnsStaticProductList` | No mock calls expected | Returns 10 items including `DV SSL`, `OV SSL`, `EV SSL`; no client method called |

`GetProductIds()` returns a hardcoded static list — no API call is made. The strict mock's
`VerifyNoOtherCalls()` confirms this.

### Enroll

The `Enroll` method selects a path based on `EnrollmentType`. Both `New` and `Reissue` submit a
new `GenerateOrderSSL` order. `RenewOrReissue` also submits `GenerateOrderSSL` (CERTInext has
no dedicated renewal endpoint) but applies the renewal-window check to determine how Command
tracks the old→new certificate relationship.

| Test | EnrollmentType | Mock setup | Assertion |
|------|---------------|-----------|-----------|
| `Enroll_New_CallsEnrollAsync_AndReturnsIssuedResult` | `New` | `PlaceOrderAsync` returns `ORD-AAA-111` | `CARequestID == "ORD-AAA-111"`; `Status == GENERATED` |
| `Enroll_New_ReturnsPendingStatus_WhenCaReturnsPendingApproval` | `New` | `PlaceOrderAsync` → pending status | `Status == EXTERNALVALIDATION` |
| `Enroll_New_Throws_WhenProfileIdNotSet` | `New` | Strict mock — no setups | Throws before calling the client |
| `Enroll_Reissue_AlsoCallsEnrollAsync` | `Reissue` | `PlaceOrderAsync` returns issued | `Status == GENERATED`; called once |
| `Enroll_Renew_FallsBackToNewEnroll_WhenNoPriorCertSn` | `RenewOrReissue` | `PlaceOrderAsync` returns issued | `CARequestID == "ORD-AAA-111"`; no dedicated renew call |

### GetSingleRecord

| Test | Mock setup | Assertion |
|------|-----------|-----------|
| `GetSingleRecord_ReturnsMappedCertificate_ForIssuedCert` | `TrackOrderAsync("ORD-AAA-111")` returns issued track response; `GetCertificateAsync` returns PEM | `Status == GENERATED`; PEM present; `ProductID == ProfileIdTls` |
| `GetSingleRecord_ReturnsMappedCertificate_ForRevokedCert` | `TrackOrderAsync("ORD-CCC-333")` returns revoked response | `Status == REVOKED`; `RevocationDate` non-null; `RevocationReason == 1` |
| `GetSingleRecord_Rethrows_WhenCertNotFound` | Client throws `KeyNotFoundException` | Rethrows `KeyNotFoundException` |

### Revoke

The plugin checks the current certificate status before calling `RevokeOrder`. CRL reason codes
(integers) are mapped to CERTInext string values.

| Test | Mock setup | Assertion |
|------|-----------|-----------|
| `Revoke_CallsRevokeCertificateAsync_AndReturnsRevokedStatus` | `TrackOrderAsync` returns issued cert; `RevokeOrderAsync` returns `Task.CompletedTask` | Returns `REVOKED`; `RevokeOrderAsync` called once with correct reason string |
| `Revoke_ReturnsAlreadyRevoked_WhenCertAlreadyRevoked` | `TrackOrderAsync` returns revoked cert | Returns `REVOKED`; `RevokeOrderAsync` never called |
| `Revoke_MapsAllCrlReasonCodes` | Per reason code 0–5 and beyond | Verifies mapping: `0→"unspecified"`, `1→"keyCompromise"`, `2→"caCompromise"`, `3→"affiliationChanged"`, `4→"superseded"`, `5→"cessationOfOperation"`, extended codes also covered by `CERTInextCAPluginCoverageTests` |

### Synchronize

`Synchronize` iterates `ListOrdersAsync` and posts mapped `AnyCAPluginCertificate` objects to a
`BlockingCollection`. Full sync passes `null` as `issuedAfter`; delta sync passes `lastSync`.

| Test | Mock setup | Assertion |
|------|-----------|-----------|
| `Synchronize_FullSync_AddsAllCertsToBuffer` | `ListOrdersAsync(null, ...)` returns two issued orders | Buffer contains 2 items; both order numbers present |
| `Synchronize_DeltaSync_PassesLastSyncFilter` | `ListOrdersAsync` captures `issuedAfter` | Captured value equals `lastSync` |
| `Synchronize_FullSync_PassesNullIssuedAfter` | `ListOrdersAsync` captures `issuedAfter` | Even when `lastSync` is non-null, `fullSync:true` forces `issuedAfter=null` |
| `Synchronize_SkipsFailedCertificates` | Returns one issued + one with unknown/failed status | Buffer contains exactly 1 item |
| `Synchronize_HonoursCancellation` | Async enumerable that cancels mid-iteration | Throws `OperationCanceledException` |
| `Synchronize_MapsRevokedCertificates_Correctly` | Returns one revoked record | Buffer item `Status == REVOKED`; `RevocationDate` non-null |
| `Synchronize_CallsCompleteAdding_OnNormalExit` | Returns empty | `buffer.IsAddingCompleted == true` |
| `Synchronize_CallsCompleteAdding_OnCancellation` | Cancels mid-iteration | `buffer.IsAddingCompleted == true` even after `OperationCanceledException` |

**Note on `CompleteAdding`:** `Synchronize` calls `blockingBuffer.CompleteAdding()` in a `finally`
block. Tests must not call `buffer.CompleteAdding()` themselves — doing so after the plugin has
already called it throws `InvalidOperationException`.

---

## CERTInextCAPluginPublicSurfaceTests

Reflection-based contract tests that verify the no-DCV build does not expose any public types,
fields, methods, or constructors that reference `IDomainValidatorFactory` or other IAnyCAPlugin
3.3-only types. These tests ensure the default build loads cleanly on AnyCA Gateway 25.5.x hosts.

| Test | What it checks |
|------|---------------|
| `NoPublicConstructor_ReferencesV3Point3OnlyTypes` | No public constructor has a parameter typed as a 3.3-only interface |
| `NoInstanceField_DeclaredTypeReferencesV3Point3OnlyTypes` | No public or private instance field is typed as a 3.3-only type |
| `NoNestedType_ImplementsV3Point3OnlyInterface` | No nested type implements a 3.3-only interface |
| `NoPublicMethod_SignatureReferencesV3Point3OnlyTypes` | No public method has a parameter or return type referencing 3.3-only types |
| `ParameterlessConstructor_IsPublic` | The plugin has a public parameterless constructor (required by the gateway host for reflection-based instantiation) |
| `SetDomainValidatorFactory_AcceptsObject_NotIDomainValidatorFactory` | The DCV injection method accepts `object`, not the 3.3-only `IDomainValidatorFactory`, so the method signature loads on 3.2 hosts |
| `SetDomainValidatorFactory_NullArgument_LeavesDcvDisabled` | Passing `null` does not enable DCV |
| `SetDomainValidatorFactory_NonFactoryArgument_IsIgnored` | Passing a non-factory object does not enable DCV |

---

## BoundedDcvSyncTests

Pure unit tests for the age-window and per-pass cap logic in `TryRunDcvDuringSyncAsync`. No
network I/O. Verifies that:
- Orders within the configured age window are attempted
- Orders older than the window are skipped (to avoid retrying abandoned orders indefinitely)
- Orders at the exact age boundary are attempted
- Orders with unknown dates are attempted (not starved)
- Age window of 0 disables the filter
- The per-pass cap skips orders once the cap is reached
- Cap of 0 disables the cap
- Age skip takes precedence over the cap check

---

## RateLimitRetryTests

Pure unit tests for the `IsRateLimitSurface` and `ComputeRateLimitBackoffSeconds` helpers:
- `IsRateLimitSurface` recognises the documented CERTInext rate-limit error phrase and rejects
  unrelated strings
- `ComputeRateLimitBackoffSeconds` produces a result within the expected jittered range for each
  attempt number
- Attempt values below 1 are clamped to 1

---

## MockCertificateData

`MockCertificateData` is a static internal class shared across test suites. It provides realistic
fake CERTInext API response objects and JSON payloads.

The real CERTInext API uses HTTP POST for all endpoints and wraps every response in a `meta`
block with `status: "1"` (success) or `status: "0"` (failure).

### Constants

| Constant | Value | Used for |
|----------|-------|---------|
| `FakePemCertificate` | PEM block starting with `-----BEGIN CERTIFICATE-----` | Certificate body in all responses |
| `FakeCsrPem` | PEM block starting with `-----BEGIN CERTIFICATE REQUEST-----` | CSR body in enroll requests |
| `OrderNumber1` | `"ORD-AAA-111"` | Primary order number (also aliased as `CertId1`) |
| `OrderNumber2` | `"ORD-BBB-222"` | Second order number (also aliased as `CertId2`) |
| `OrderNumber3` | `"ORD-CCC-333"` | Revoked order number (also aliased as `CertId3`) |
| `ProfileIdTls` | `"tls-server"` | TLS server product code placeholder |
| `ProfileIdClient` | `"client-auth"` | Client auth product code placeholder |

`CertId1/2/3` are backward-compatibility aliases for `OrderNumber1/2/3`.

### JSON helpers (WireMock stubs)

| Method | Endpoint | Notes |
|--------|----------|-------|
| `ValidateCredentialsSuccessJson()` | `POST /ValidateCredentials` | Success meta only |
| `ValidateCredentialsFailureJson(code, msg)` | `POST /ValidateCredentials` | Failure meta |
| `GenerateOrderSuccessJson(orderNumber)` | `POST /GenerateOrderSSL` | Includes `orderDetails.orderNumber` |
| `TrackOrderIssuedJson(orderNumber)` | `POST /TrackOrder` | `certificateStatusId="9"` (GENERATED) |
| `TrackOrderPendingJson(orderNumber)` | `POST /TrackOrder` | `certificateStatusId="1"` (SetupPending) |
| `TrackOrderRevokedJson(orderNumber)` | `POST /TrackOrder` | `certificateStatusId="22"`, revocation details present |
| `GetCertificateSuccessJson()` | `POST /GetCertificate` | PEM in `certificateDetails.endEntityCertificate`; serial `"0A1B2C3D4E5F"` |
| `RevokeSuccessJson()` | `POST /RevokeOrder` | Success meta only |
| `OrderReportSinglePageJson()` | `POST /GetOrderReport` | One entry, `ORD-AAA-111` |
| `OrderReportPageJson(orderNumbers, total, pages, current)` | `POST /GetOrderReport` | Multi-entry paginated response |
| `OrderReportEmptyJson()` | `POST /GetOrderReport` | Empty `ordersArray`, `noOfPages=0` |
| `GetProductDetailsJson()` | `POST /GetProductDetails` | Nested category envelope with two products |
| `GetProductDetailsEmptyJson()` | `POST /GetProductDetails` | Empty `productDetails` array |
| `ApiFailureJson(code, msg)` | Any endpoint | Generic `meta.status="0"` failure |
| `GetDcvSuccessJson(token)` | `POST /GetDcv` | `dcvDetails.token` |
| `GetDcvFailureJson(code, msg)` | `POST /GetDcv` | Failure meta |
| `VerifyDcvSuccessJson()` | `POST /VerifyDcv` | Success meta only |
| `VerifyDcvFailureJson(code, msg)` | `POST /VerifyDcv` | Failure meta |
| `OAuth2TokenJson(expiresIn)` | OAuth token endpoint | `access_token="fake-bearer-token-abc123"` |
| `ServerErrorJson()` | Any | Generic 500 error body (not meta-wrapped) |
| `UnauthorizedJson()` | Any | Generic 401 error body (not meta-wrapped) |

### Object helpers (Moq setups)

| Method | Returns |
|--------|---------|
| `ActiveProfiles()` | Two `ProfileInfo` objects, both `Active=true`: `ProfileIdTls` and `ProfileIdClient` |
| `MixedProfiles()` | Three `ProfileInfo` objects: `ProfileIdTls` (active), `"legacy-profile"` (inactive), `ProfileIdClient` (active) |
| `IssuedEnrollResponse(id)` | `EnrollCertificateResponse` with `Status="issued"`, PEM, `SerialNumber="0A1B2C3D4E5F"` |
| `PendingEnrollResponse(id)` | `EnrollCertificateResponse` with `Status="pending_approval"`, `Certificate=null` |
| `IssuedCertRecord(id)` | `LegacyGetCertificateResponse` with `Status="issued"`, PEM, `ProfileId=ProfileIdTls` |
| `PendingCertRecord(id)` | `LegacyGetCertificateResponse` with `Status="pending_approval"`, no certificate — maps to `EXTERNALVALIDATION` |
| `RevokedCertRecord(id)` | `LegacyGetCertificateResponse` with `Status="revoked"`, `RevokedAt`, `RevocationReason="keyCompromise"` |
| `DcvPendingTrackResponse(orderNumber, domain)` | `TrackOrderResponse` with one DNS-TXT entry at `dcvStatus="0"` (pending) |
| `DcvVerifiedTrackResponse(orderNumber, domain)` | `TrackOrderResponse` with DNS-TXT entry at `dcvStatus="1"` (validated) |
| `AlreadyIssuedTrackResponse(orderNumber)` | `TrackOrderResponse` with `certificateStatusId="9"` (GENERATED) — DCV should be skipped |
| `DcvTokenResponse(token)` | `GetDcvResponse` with `DcvDetails.Token` set |

---

## Adding New Tests

### Which suite to add to

- **`CERTInextClientTests`** — when testing HTTP-level behaviour: a new endpoint, error status
  code, authentication header detail, body serialisation, or query parameter.
- **`CERTInextClientRequestShapeTests`** — when verifying that the request body includes or omits
  specific JSON blocks based on connector configuration.
- **`CERTInextCAPluginTests` / `CERTInextCAPluginCoverageTests`** — when testing plugin logic: a
  new enrollment type, validation rule, status mapping, or response to specific client return values.

### Adding a new WireMock stub

1. Register a stub in the test body:
   ```csharp
   _server
       .Given(Request.Create().WithPath("/YourEndpoint").UsingPost())
       .RespondWith(Response.Create()
           .WithStatusCode(200)
           .WithHeader("Content-Type", "application/json")
           .WithBody(MockCertificateData.YourResponseJson()));
   ```
2. Add a `YourResponseJson(...)` JSON helper to `MockCertificateData` if the shape is reused.
3. Verify request details by inspecting `_server.LogEntries` after the call.
