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
| `CERTInextClientCoverageTests` | `CERTInextClient` auth-failure branches & OAuth2 edge cases | WireMock.Net |
| `CERTInextCAPluginTests` | `CERTInextCAPlugin` IAnyCAPlugin logic | Moq strict mock of `ICERTInextClient` |
| `CERTInextCAPluginCoverageTests` | Additional plugin logic paths | Moq strict mock |
| `CERTInextCAPluginDcvTests` | DCV staging/verification/cleanup orchestration in `CERTInextCAPlugin` | Moq strict mock + `FakeDomainValidator` |
| `CERTInextCAPluginEnrollmentWaitTests` | Post-enroll synchronous polling/wait logic in `CERTInextCAPlugin` | Moq strict mock of `ICERTInextClient` |
| `CERTInextCAPluginPublicSurfaceTests` | Binary-compat / no-DCV surface contract | Reflection only |
| `BoundedDcvSyncTests` | DCV sync age/cap filter logic | Pure unit (no I/O) |
| `RateLimitRetryTests` | Rate-limit back-off helpers | Pure unit (no I/O) |
| `CnameResolverTests` | `CnameResolver` CNAME chain resolution (DCV delegation) | Pure unit (no I/O) |
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
| `EnrollCertificateAsync_DoesNotRetryOrderSubmit_OnTransient500` | `POST /GenerateOrderSSL` → persistent 500 | Throws `Exception` containing `"did not return a usable response"`; exactly 1 request logged — a non-idempotent order submit must not be retried (avoids EMS-947 duplicate/orphan) |
| `EnrollCertificateAsync_SurfacesDuplicateGuidance_OnEms947` | `POST /GenerateOrderSSL` → 200, failure meta `EMS-947` ("Duplicate requestTxn") | Throws `Exception` containing `"duplicate order transaction"` — classified as a benign duplicate, not a generic hard failure |

### SubmitCsrAsync — POST /SubmitCSR

| Test | Stub | Assertion |
|------|------|-----------|
| `SubmitCsrAsync_DoesNotRetry_OnTransient500` | `POST /SubmitCSR` → persistent 500 | Throws `Exception` containing `"did not return a usable response"`; exactly 1 request logged — a non-idempotent CSR submit must not be retried |

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
| `ValidityYears_OnRequest_OverridesConnectorDefaultAndValidityDays` | `ValidityYears=3` on the request wins over both `ValidityDays=730` and the connector's `SubscriptionValidityYears="1"` default — body's `subscriptionDetails.validity == "3"` |
| `ValidityYears_Unset_FallsBackToValidityDaysThenConnectorDefault` | With `ValidityYears` unset on the request, the connector's `SubscriptionValidityYears="2"` default is used — body's `subscriptionDetails.validity == "2"` |

---

## CERTInextClientCoverageTests

WireMock tests for auth-failure branches and OAuth2 error conditions in `CERTInextClient` that
aren't exercised by `CERTInextClientTests`. Uses the same `BuildClient`/`BuildOAuthClient` helper
pattern against a fresh per-test `WireMockServer`.

| Test | Stub | Assertion |
|------|------|-----------|
| `PingAsync_Throws_On401` | `POST /ValidateCredentials` → 401, generic unauthorized body | Throws `Exception` containing `"health check failed"` |
| `PingAsync_Throws_On403` | `POST /ValidateCredentials` → 403, generic forbidden body | Throws `Exception` containing `"health check failed"` |
| `GetCertificateAsync_Throws_On401` | `POST /TrackOrder` → 401 | Throws `Exception` containing `"Authentication failure"` |
| `RevokeCertificateAsync_Throws_On401` | `POST /RevokeOrder` → 401 | Throws `Exception` containing `"authentication failure"` |
| `RenewCertificateAsync_Throws_On401` | `POST /TrackOrder` → 401 (prior-order lookup during renewal) | Throws `Exception` containing `"Authentication failure"` |
| `ListCertificatesAsync_Throws_On401` | `POST /GetOrderReport` → 401 | Enumerating the async stream throws `Exception` containing `"Authentication failure"` |
| `GetProfilesAsync_Throws_On401` | `POST /GetProductDetails` → 401 | Throws `Exception` containing `"Authentication failure"` |
| `EnrollCertificateAsync_Throws_OnEmptyResponseBody` | `POST /GenerateOrderSSL` → 200 with an empty body | Throws `Exception` containing `"empty body"` |
| `RevokeCertificateAsync_ThrowsWithSafeMessage_WhenBodyIsPlainText` | `POST /RevokeOrder` → 500, plain-text body | Throws `Exception` whose message names the `"revoke"` operation but never echoes the raw response body |
| `OAuth2_Throws_WhenTokenEndpointReturns500` | OAuth token endpoint → 500 | `PingAsync` throws `Exception` containing `"OAuth2 token"` |
| `OAuth2_Throws_WhenTokenResponseLacksAccessToken` | OAuth token endpoint → 200 with a body lacking `access_token` | `PingAsync` throws `Exception` containing `"access_token"` |

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

### ValidateCAConnectionInfo

| Test | Mock setup | Assertion |
|------|-----------|-----------|
| `ValidateCAConnectionInfo_Throws_WhenApiUrlMissing` | Connection info dict omits `ApiUrl` | Throws `AnyCAValidationException` containing `"ApiUrl"` and `"required"` |
| `ValidateCAConnectionInfo_Throws_WhenApiUrlIsNotUri` | `ApiUrl = "not-a-url"` | Throws `AnyCAValidationException` containing `"valid absolute URI"` |
| `ValidateCAConnectionInfo_Throws_WhenApiKeyMissingForApiKeyMode` | `AuthMode = "ApiKey"`, no `ApiKey` | Throws `AnyCAValidationException` containing `"ApiKey"` and `"required"` |
| `ValidateCAConnectionInfo_Throws_WhenAuthModeIsBasicOrOtherUnsupported` | `AuthMode = "Basic"` (unsupported by the real API) | Throws `AnyCAValidationException` containing `"AuthMode"` and `"must be one of"` |
| `ValidateCAConnectionInfo_Throws_WhenOAuthFieldsMissing` | `AuthMode = "OAuth"`, missing `OAuthTokenUrl`/`OAuthClientId`/`OAuthClientSecret` | Throws `AnyCAValidationException` containing `"OAuthTokenUrl"` and `"required"` |
| `ValidateCAConnectionInfo_Throws_WhenAuthModeIsInvalid` | `AuthMode = "CertificateBased"` (unrecognized value) | Throws `AnyCAValidationException` containing `"AuthMode"` and `"must be one of"` |
| `ValidateCAConnectionInfo_SkipsValidation_WhenDisabled` | `Enabled = false`, everything else missing | Does not throw; strict mock's `VerifyNoOtherCalls()` confirms no client calls |

### ValidateProductInfo

| Test | Mock setup | Assertion |
|------|-----------|-----------|
| `ValidateProductInfo_Throws_WhenProfileIdMissing` | `ProductID = ""`, empty `ProductParameters` | Throws `AnyCAValidationException` containing `"ProfileId"` and `"required"` |

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
| `Synchronize_IssuedCertMissingBody_RefetchesFullCertificate` | Listing entry is issued but carries no PEM (`Certificate == null`); `GetCertificateAsync` returns the full record | Buffer item carries the refetched PEM body; `GetCertificateAsync` called once (regression for issue 0001) |
| `Synchronize_IssuedCertWithBody_DoesNotRefetch` | Listing entry already carries a PEM body | Buffer item keeps that PEM; `GetCertificateAsync` never called (strict mock has no setup for it) |
| `Synchronize_RevokedCertMissingBody_RefetchesWithRevocationMetadata` | Listing entry is revoked with no body/`RevokedAt`; `GetCertificateAsync` returns body + revocation detail | Buffer item is REVOKED with the PEM body and a non-null `RevocationDate` after the refetch |
| `Synchronize_CallsCompleteAdding_OnNormalExit` | Returns empty | `buffer.IsAddingCompleted == true` |
| `Synchronize_CallsCompleteAdding_OnCancellation` | Cancels mid-iteration | `buffer.IsAddingCompleted == true` even after `OperationCanceledException` |

**Note on `CompleteAdding`:** `Synchronize` calls `blockingBuffer.CompleteAdding()` in a `finally`
block. Tests must not call `buffer.CompleteAdding()` themselves — doing so after the plugin has
already called it throws `InvalidOperationException`.

### RenewOrReissue

Three semantic cases for the `RenewOrReissue` renewal-window check (complementing the
`CERTInextCAPluginCoverageTests` Group A edge cases): whether a prior certificate's expiry falls
inside, outside, or already past the configured `RenewalWindowDays`.

| Test | Mock setup | Assertion |
|------|-----------|-----------|
| `RenewOrReissue_UsesRenewApi_WhenCertExpiresWithinWindow` | Prior cert expires in 30 days, `RenewalWindowDays = 90` | Calls `RenewCertificateAsync` once for the prior order; GENERATED |
| `RenewOrReissue_UsesNewEnroll_WhenCertExpiresOutsideWindow` | Prior cert expires in 120 days, `RenewalWindowDays = 90` | Calls `EnrollCertificateAsync` (new order) once; `RenewCertificateAsync` never called |
| `RenewOrReissue_UsesNewEnroll_WhenCertAlreadyExpired` | Prior cert expired 5 days ago, `RenewalWindowDays = 90` | Falls back to new enroll (graceful degradation for an already-expired cert); `RenewCertificateAsync` never called |

---

## CERTInextCAPluginCoverageTests

Additional Moq-based coverage for `CERTInextCAPlugin` logic not exercised by
`CERTInextCAPluginTests` — organized (per the source file's own comments) into Group A
(`RenewOrReissueAsync`/`BuildEnrollmentResult` edge cases), Group B (status-mapping variants via
`Synchronize`/`Revoke`), and Group C (annotations, `Initialize`, SAN builder, revocation-reason
codes). WireMock auth-failure branch tests live in `CERTInextClientCoverageTests` instead.

### Group A — RenewOrReissueAsync + BuildEnrollmentResult edge cases

| Test | Mock setup | Assertion |
|------|-----------|-----------|
| `RenewOrReissue_FallsBackToNew_WhenGetRequestIDThrows` | `GetRequestIDBySerialNumber` throws; `EnrollCertificateAsync` returns issued | Falls back to new enroll (GENERATED); `EnrollCertificateAsync` called once, `RenewCertificateAsync` never |
| `RenewOrReissue_FallsBackToNew_WhenGetRequestIDReturnsEmpty` | `GetRequestIDBySerialNumber` returns `""` | Falls back to new enroll (GENERATED) |
| `RenewOrReissue_FallsBackToNew_WhenExpiryIsNull` | `GetExpirationDateByRequestId` returns `null` | Falls back to new enroll; `RenewCertificateAsync` never called |
| `RenewOrReissue_CallsRenewApi_WhenCertWithinRenewalWindow` | Expiry 30 days out, window 90 days | Calls `RenewCertificateAsync` once; `EnrollCertificateAsync` never called |
| `RenewOrReissue_FallsBackToNew_WhenCertOutsideRenewalWindow` | Expiry already 200 days in the past, window 90 days | Falls back to new enroll — an already-expired cert doesn't satisfy `expiry > now` |
| `Enroll_Renew_FallsBackToNew_WhenNoPriorCertSnInParams` | `EnrollmentType.Renew`, no `PriorCertSN` parameter | Falls back to new enroll (GENERATED) |
| `BuildEnrollmentResult_ReturnsFailed_WhenCaReturnsFailedStatus` | `EnrollCertificateAsync` returns `Status = "failed"` | Result `Status == FAILED`; `CARequestID` preserved |
| `BuildEnrollmentResult_ReturnsFailed_WhenCaReturnsUnknownStatus` | `EnrollCertificateAsync` returns `Status = "queued"` (unmapped) | Result `Status == FAILED` via the `StatusMapper` default |
| `Revoke_Throws_WhenCertIsInNonRevocableState` | `GetCertificateAsync` returns `Status = "pending_approval"` | Throws `Exception` containing `"cannot be revoked"` |
| `GetSingleRecord_Rethrows_WhenGenericExceptionOccurs` | `GetCertificateAsync` throws `Exception("Timeout")` | Rethrows `Exception` containing `"Timeout"` |
| `Synchronize_SkipsExpiredCerts_WhenIgnoreExpiredIsTrue` | `IgnoreExpired = true`; one expired + one valid cert | Buffer contains only the valid cert |

### Group B — status-mapping variants via Synchronize + Revoke

| Test | Mock setup | Assertion |
|------|-----------|-----------|
| `Synchronize_MapsActiveCert_AsGenerated` | One "active" + one "expired" cert (`IgnoreExpired = false`) | Both map to GENERATED |
| `Synchronize_SkipsCancelledAndRejectedCerts` | "cancelled" + "rejected" + one valid cert | Buffer contains only the valid cert (cancelled/rejected → FAILED → skipped) |
| `Revoke_MapsExtendedCrlReasonCodes` (`Theory`: codes 6, 8, 9, 10) | Reason codes 6/8/9/10 | Map to `certificateHold`/`removeFromCRL`/`privilegeWithdrawn`/`aACompromise` respectively |
| `Synchronize_SkipsCertWithTotallyUnknownStatus` | Cert with `Status = "totally-unknown-status"` | Buffer is empty (unknown status → FAILED → skipped) |

### Group C — annotations, Initialize, SAN builder, revocation-reason codes

| Test | Mock setup | Assertion |
|------|-----------|-----------|
| `GetCAConnectorAnnotations_ContainsAllExpectedKeys` | Plugin built directly, no setups | All expected connector annotation keys are present (`ApiUrl`, `AuthMode`, `OAuthTokenUrl`, etc.) |
| `GetTemplateParameterAnnotations_ContainsAllExpectedKeys` | No setups | All expected template parameter keys are present, including the P2-B additions `DomainName`/`SignerName`/`SignerPlace`/`SignerIp` |
| `Initialize_Succeeds_WithValidApiKeyConfig` | `IAnyCAPluginConfigProvider` mock returns a valid ApiKey config | `Initialize` does not throw |
| `Enroll_PassesAllEnrollmentParamsToRequest` | Product params include `ValidityDays`, `AutoApprove`, `RequesterName`, `RequesterEmail`, `KeyType` | Captured `EnrollCertificateRequest` carries all of them through |
| `Enroll_WithInvalidValidityDays_FallsBackToNull` | `ValidityDays = "not-a-number"` | Captured request's `ValidityDays` is `null` (falls back to profile default) |
| `Enroll_PassesValidityYearsToRequest` | `ValidityYears = "3"` | Captured request's `ValidityYears == 3` |
| `Enroll_WithInvalidValidityYears_FallsBackToNull` | `ValidityYears = "not-a-number"` | Captured request's `ValidityYears` is `null` |
| `Enroll_WithNullSanValueArray_StillCallsEnroll` | SAN dict has a key (`ip`) with a `null` value array | Does not throw; `EnrollCertificateAsync` still called once, GENERATED |
| `Enroll_WithUnknownSanType_PassesThroughRawType` | SAN dict has an unrecognized key `oid` | Captured request's `Sans` contains an entry with `Type == "oid"` passed through as-is |
| `GetSingleRecord_MapsRevocationReasonStringToCorrectCode` (`Theory` ×10) | `RevocationReason` string values (`unspecified`…`aACompromise`) | Each string maps to its correct CRL numeric code (0, 1, 2, 3, 4, 5, 6, 8, 9, 10) |

---

## CERTInextCAPluginDcvTests

Unit tests for the DCV orchestration path inside `CERTInextCAPlugin.Enroll` /
`PerformDcvIfNeededAsync` / `WaitForDcvVerificationAsync` / `WaitForIssuanceAsync`. All external
dependencies (CERTInext client, DNS validator) are stubbed, so no network calls are made, and
propagation delay is set to 0 so tests run fast.

Helpers: `DcvConfig(enabled, propagationDelaySeconds, timeoutMinutes, dcvWaitForChallengeSeconds,
dcvWaitForIssuanceSeconds)` builds a `CERTInextConfig` with the general `EnrollmentWaitSeconds`
poll defaulted to 0 (so it doesn't interfere with these DCV-focused tests unless a test opts back
in); `BuildPlugin(client, factory, config)`; `HappyPathMocks(...)` wires the full
Enroll → TrackOrder(pending) → GetDcv → VerifyDcv → GetCertificate happy path; `Enroll(plugin)`
drives a single enrollment for a fixed CSR/subject/SAN.

| Test | Mock setup | Assertion |
|------|-----------|-----------|
| `Dcv_HappyPath_StagesVerifiesAndCleansUp` | Full happy-path mocks; `dcvWaitForIssuanceSeconds = 10` | GENERATED with PEM; TXT record staged at the expected hostname and cleaned up; `VerifyDcvAsync`/`GetCertificateAsync` each called once |
| `Dcv_HappyPath_UsesCustomTxtTemplate` | Happy-path mocks with a custom `DcvTxtRecordTemplate` | TXT record staged and cleaned up at the hostname built from the custom template |
| `Dcv_Skipped_WhenOrderAlreadyIssued` | `EnrollCertificateAsync` returns issued; `TrackOrderAsync` returns an already-issued track response | GENERATED straight from the enroll response; no staging; `GetDcvAsync` never called |
| `Dcv_Skipped_WhenNoDomainVerificationBlock` | `TrackOrderAsync` returns a track response with `DomainVerification = null` | No TXT staged; `GetDcvAsync` never called |
| `Dcv_EnrollmentWaitStillRuns_WhenDcvShortCircuitsWithoutAnIssuanceWait` | DCV challenge slot never appears (`DomainVerification = null`); catalog lookup fails; `EnrollmentWaitSeconds = 10` | The general enrollment-wait poll still runs and returns GENERATED — DCV short-circuiting must not suppress it |
| `Dcv_RecoversPem_WhenPostDcvIssuanceWaitEndsWithGeneratedButNoBody` | Post-DCV `GetCertificateAsync` first returns issued-without-body, then issued-with-body; `EnrollmentWaitSeconds = 10` | GENERATED with PEM after 2 `GetCertificateAsync` calls — the general enrollment-wait poll recovers the PEM the post-DCV wait left bodyless |
| `Dcv_EnrollmentWaitStillRuns_WhenDcvCompletesButIssuanceWaitBudgetIsZero` | DCV already validated (`dcvDone = true`) but `DcvWaitForIssuanceSeconds = 0`; `EnrollmentWaitSeconds = 10` | GENERATED — the general enrollment-wait poll still fires even though the DCV-specific issuance wait short-circuited to a no-op |
| `Dcv_AlreadyInFlight_DuplicateCallDefersWithoutPolling` | Two concurrent `Enroll()` calls for the same order; first holds the `_dcvInFlight` reservation via a gated `TrackOrderAsync` | The duplicate call returns EXTERNALVALIDATION immediately without polling; only the original caller polls `GetCertificateAsync` (once) |
| `Dcv_SkipsStaging_AndDoesNotIssuancePoll_WhenAllDomainsAlreadyValidated_AndIssuanceBudgetZero` | `DomainVerification.Status = "1"` (validated); default `DcvWaitForIssuanceSeconds = 0` | No TXT staged; `GetDcvAsync`/`GetCertificateAsync` never called — order is left for sync to pick up |
| `Dcv_RunsIssuanceWait_WhenDcvAlreadyValidated_AndIssuanceBudgetPositive` | DCV already validated; `dcvWaitForIssuanceSeconds = 10`; `GetCertificateAsync` sequence pending→issued | GENERATED after polling at least twice; no TXT staging or `GetDcvAsync` call needed |
| `Dcv_Skipped_WhenDcvEnabledFalse` | `DcvEnabled = false` | No TXT staged; `TrackOrderAsync` never called |
| `Dcv_NoFactoryInjected_StillReturnsCAsPendingResult_WhenNoGuidanceAvailable` | Plugin built with `domainValidatorFactory: null`, `DcvEnabled = true`; `TrackOrderAsync` returns no `DomainVerification` data | Does not throw; returns the CA's pending status unchanged with empty `EnrollmentContext` |
| `SetDomainValidatorFactory_AfterConstruction_WiresFactoryForSubsequentEnroll` | Plugin constructed with a `null` factory, then `SetDomainValidatorFactory(...)` called before `Enroll` | Subsequent `Enroll()` drives DCV end-to-end (GENERATED, TXT staged) via the injected factory |
| `SetDomainValidatorFactory_SecondCall_OverridesFirst` | `SetDomainValidatorFactory` called twice with different factories | Only the second factory's validator receives TXT staging traffic; the first is never called |
| `Dcv_Skipped_WhenOrderStatusIdIsTerminal_EvenIfDcvValidated` (`Theory`: `OrderStatusId` 4/5) | `DomainVerification.Status = "1"` (validated) but `OrderStatusId` is Cancelled(4)/Rejected(5); `dcvWaitForIssuanceSeconds = 10` | `GetCertificateAsync` never called and no TXT staged — cancelled/rejected orders don't enter the issuance wait even with cached-validated DCV state |
| `SyncDcvRetry_DoesSingleShotTrackOrder_WhenChallengeNotReady` | `dcvWaitForChallengeSeconds = 60` exercised via `GetSingleRecord` (the sync path); `DomainVerification = null` | Completes in well under 10s and makes exactly one `TrackOrderAsync` call — sync's DCV retry is single-shot, not a full poll of the configured challenge budget |
| `Dcv_Throws_WhenNoProviderForDomain` | Factory returns a `null` validator | Throws `InvalidOperationException` containing `"No DNS provider plugin is configured"` |
| `Dcv_Throws_WhenStageValidationFails` | `FakeDomainValidator.StageSucceeds = false` | Throws `InvalidOperationException` containing `"Failed to stage DNS validation"` and the validator's error; `VerifyDcvAsync` never called |
| `Dcv_CleanupAlwaysCalled_EvenWhenVerifyDcvThrows` | `VerifyDcvAsync` throws | Exception propagates but `Cleanup` is still invoked for the staged hostname |
| `Dcv_Throws_WhenGetDcvReturnsNoToken` | `GetDcvAsync` returns a response with `Token = null` | Throws `InvalidOperationException` containing `"GetDcv returned no token"` |
| `Dcv_Defers_When_GetDcv_ReturnsEms956` | `GetDcvAsync` throws an exception whose message contains `"EMS-956"` | Does not throw; returns a non-null pending result; nothing staged/cleaned up; `VerifyDcvAsync` never called |
| `Dcv_Defers_When_GetDcv_ReturnsInvalidRequestMessage_WithoutEms956Code` | `GetDcvAsync` throws `"Invalid Request for this API"` (no EMS-956 code) | Does not throw; nothing staged — tolerance matches the human-readable phrase too, not only the code |
| `Dcv_Rethrows_When_GetDcv_FailsWithUnrelatedError` | `GetDcvAsync` throws `"HTTP 500: Internal Server Error"` | Rethrows — the EMS-956 tolerance is narrow and doesn't swallow unrelated failures |
| `Dcv_WaitsForChallenge_WhenDomainVerificationAppearsLate` | `TrackOrderAsync` sequence: null→pending→verified; `dcvWaitForChallengeSeconds = 10`, `dcvWaitForIssuanceSeconds = 10` | GENERATED and TXT staged — the plugin polled until the challenge slot appeared instead of skipping |
| `Dcv_GivesUpWaitingForChallenge_AfterBudgetExpires` | `DomainVerification` stays `null` forever; `dcvWaitForChallengeSeconds = 5` | Does not throw; polls `TrackOrderAsync` at least twice within the budget then gives up (deferred to sync) |
| `Dcv_WaitsForIssuance_AfterDcvVerifies` | Post-DCV `GetCertificateAsync` sequence: pending→issued; `dcvWaitForIssuanceSeconds = 10` | GENERATED (the polled issued status), with at least 2 `GetCertificateAsync` calls |
| `Dcv_NoFactoryWired_SurfacesManualTxtGuidanceInEnrollmentResult` | No factory at all (`(IDomainValidatorFactory)null`); `GetDcvAsync` returns a token | EXTERNALVALIDATION; `EnrollmentContext` contains the expected TXT hostname → token, and `StatusMessage` mentions both; `VerifyDcvAsync` never called |
| `Dcv_NoFactoryWired_WhenGuidanceLookupFails_FallsBackToPlainPendingMessage` | No factory; `TrackOrderAsync` throws | `EnrollmentContext` is empty; `StatusMessage` falls back to the plain `"pending approval"` message |
| `Dcv_NoFactoryWired_ButDcvDisabled_DoesNotAttemptGuidanceLookup` | No factory; `DcvEnabled = false` | `EnrollmentContext` is empty; `TrackOrderAsync` never called |
| `Dcv_CnameDelegationEnabled_RoutesToTerminalNameValidator` | `DcvFollowCnameDelegation = true`; a `CnameResolver` chain routes the challenge hostname to a terminal name keyed in a `KeyedDomainValidatorFactory` | GENERATED; the factory is queried with the terminal name (not the raw domain) and TXT is staged/cleaned up there |
| `Dcv_CnameDelegationDisabled_UsesRawDomainUnchanged` | `DcvFollowCnameDelegation` left at its default (`false`) | Behavior identical to the pre-CNAME-delegation happy path — TXT staged at the raw domain's hostname |
| `Dcv_CnameDelegationEnabled_LoopDetected_ThrowsCleanly` | `DcvFollowCnameDelegation = true`; CNAME chain cycles back to the challenge hostname | Throws `InvalidOperationException` containing `"loop"`; nothing staged/verified before the loop is detected |

---

## CERTInextCAPluginEnrollmentWaitTests

Unit tests for the synchronous enrollment-wait poll (`TryEnrollmentWaitForCertificateAsync`) that
runs at the end of every enrollment path on both build flavors: DV products poll `GetCertificate`
and return GENERATED + PEM when CERTInext issues within the budget; OV/EV products defer
immediately (async by CA design, per CERTInext support); exhaustion or any failure soft-falls
back to the pending result without throwing. Compiles on both the DCV (3.3.0) and no-DCV (3.2.0)
flavors.

Helpers: `EnrollmentWaitConfig(totalSeconds = 50)` builds a `CERTInextConfig` with the fixed
5-second poll interval in mind (default budget ⇒ 10 max polls); `SslCatalog()` returns DV/OV/EV
`ProductDetail`s keyed by product code (`842`/`846`/`850`); `ProductInfo(productName,
productCode)`; `Enroll(plugin, productInfo, type)`.

| Test | Mock setup | Assertion |
|------|-----------|-----------|
| `EnrollmentWait_DvProduct_PendingThenIssued_ReturnsGeneratedWithPem` | DV product; `GetCertificateAsync` sequence pending→issued | GENERATED with PEM; polled exactly twice, stopping as soon as issued |
| `EnrollmentWait_DvProduct_IssuedOnFirstPoll_ReturnsGenerated` | DV product; `GetCertificateAsync` returns issued immediately | GENERATED; polled exactly once |
| `EnrollmentWait_OvProduct_ReturnsPendingImmediately_WithoutPolling` | OV product | EXTERNALVALIDATION immediately with a status message mentioning "asynchronously"/"synchronization"; `GetCertificateAsync` never called |
| `EnrollmentWait_EvProduct_ReturnsPendingImmediately_WithoutPolling` | EV product | Same as OV — EXTERNALVALIDATION, no poll |
| `EnrollmentWait_OvByTemplateName_Defers_WhenCatalogUnavailable` | Product catalog fetch throws; template name carries the OV wildcard token | EXTERNALVALIDATION; no poll — the name-based classifier fallback still prevents a futile poll |
| `EnrollmentWait_ProductCatalog_IsCachedAcrossEnrollments` | 3 successive OV enrollments | `GetProductDetailsAsync` called exactly once — catalog is cached, not refetched per enrollment |
| `EnrollmentWait_UnknownProduct_PollsOptimistically` | Catalog fetch fails; product name/code unrecognized | GENERATED; polls once — unknown products are polled optimistically rather than silently deferred |
| `EnrollmentWait_SoftFallsBackToPending_WhenBudgetExhausted` | DV product; `GetCertificateAsync` always returns pending; 10s budget (5s interval ⇒ 2 polls) | EXTERNALVALIDATION with a "later synchronization" message; polled exactly twice (off-by-one guard) |
| `EnrollmentWait_SurvivesTransientFailure_AndReturnsIssuedOnRetry` | `GetCertificateAsync` throws once then returns issued | GENERATED; a transient failure consumes one attempt, not the whole budget |
| `EnrollmentWait_Disabled_WhenRetriesNegative` | `EnrollmentWaitSeconds = -1` | EXTERNALVALIDATION; neither the catalog nor `GetCertificateAsync` are called — "-1 to disable" convention honored |
| `EnrollmentWait_SoftFallsBackToPending_WhenGetCertificateThrows` | `GetCertificateAsync` always throws; 10s budget | EXTERNALVALIDATION with the order's `CARequestID` preserved — a failing poll never fails the enrollment |
| `EnrollmentWait_ReturnsFailed_WhenOrderReachesTerminalFailure` | `GetCertificateAsync` returns `Status = "failed"` | Returns FAILED (not left pending); message doesn't claim the cert was issued |
| `EnrollmentWait_Disabled_WhenRetriesZero` | `EnrollmentWaitSeconds = 0` | EXTERNALVALIDATION; catalog and `GetCertificateAsync` never called |
| `EnrollmentWait_Skipped_WhenEnrollReturnsIssuedWithPem` | `EnrollCertificateAsync` returns issued+PEM directly | GENERATED; `GetCertificateAsync` never called — an already-complete result needs no wait |
| `EnrollmentWait_FetchesPem_WhenEnrollReturnsIssuedWithoutPem` | Enroll response issued but `Certificate = null`; `GetCertificateAsync` returns the PEM | GENERATED with PEM recovered via the wait poll |
| `EnrollmentWait_KeepsPolling_WhenGeneratedWithoutBody_ThenRecoversPem` | `GetCertificateAsync` sequence: issued-no-body → issued-with-body | GENERATED with PEM after 2 polls — a bodyless GENERATED mid-poll is not treated as terminal |
| `EnrollmentWait_SoftFallsBackToPending_WhenGeneratedBodyNeverArrives` | `GetCertificateAsync` always returns issued-without-body; 15s budget | EXTERNALVALIDATION with no certificate — never surfaces a bodyless GENERATED as success |
| `EnrollmentWait_SoftFallsBackToPending_WhenEnrollIssuedWithoutPem_AndBodyNeverArrives` | Enroll response issued-without-PEM; every poll also bodyless; 15s budget | EXTERNALVALIDATION with no certificate — same invariant enforced from an issued-without-PEM entry state |
| `EnrollmentWait_Disabled_DowngradesIssuedWithoutPem_ToPending` | `EnrollmentWaitSeconds = 0`; enroll response issued-without-PEM | EXTERNALVALIDATION with no certificate even though the wait never polls — the no-bodyless-GENERATED rule still applies |
| `EnrollmentWait_DegradesIssuedWithoutPem_ToPending_WhenOrderNumberEmpty` | Enroll response issued-without-PEM and empty order `Id` | EXTERNALVALIDATION with no certificate; `GetCertificateAsync` never called (nothing to poll with) |
| `EnrollmentWait_CatalogFailure_IsBackedOff_NotRetriedPerEnrollment` | Catalog fetch always throws; 3 successive DV enrollments | `GetProductDetailsAsync` called exactly once — a failing catalog fetch is backed off, not retried every enrollment |
| `EnrollmentWait_RenewPath_PendingThenIssued_ReturnsGenerated` | Renewal via `RenewCertificateAsync`; `GetCertificateAsync` sequence pending→issued for the new order number | GENERATED with PEM; the wait polls the NEW order number returned by the renewal |
| `EnrollmentWait_RenewPath_RunsEvenWhenDcvEnabled` | Renewal path with `DcvEnabled = true` | GENERATED — DcvEnabled must not suppress the renew-path enrollment wait (no in-call DCV runs on renewals) |
| `EnrollmentWait_FetchesPem_ForIssuedOrder_EvenWhenDcvEnabled` | Enroll response issued-without-PEM; `DcvEnabled = true` | GENERATED with PEM recovered — the PEM-recovery fetch runs regardless of DCV configuration |
| `EnrollmentWait_RenewPath_ClassifiesTheProductCodeActuallyOrdered` | Renewal response's `ProfileId` reports the connector's `DefaultProductCode` (OV) even though the template says DV | EXTERNALVALIDATION; `GetCertificateAsync` never called — the OV/EV gate classifies the code actually ordered, not the template's |

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

## CnameResolverTests

Pure unit tests for `CnameResolver`'s hop-walking algorithm (depth cap + loop detection), used by
the DCV CNAME-delegation feature (issue 0006). Exercised via the internal delegate-injection
constructor against a fake in-memory CNAME chain map, so no real DNS queries are made.

| Test | What it checks |
|------|---------------|
| `ResolveTerminalNameAsync_NoCname_ReturnsSameName` | A name with no CNAME entry resolves to itself |
| `ResolveTerminalNameAsync_SingleHop_ReturnsTarget` | A single CNAME hop resolves to its target |
| `ResolveTerminalNameAsync_MultiHopChain_FollowsToTerminalName` | A 3-hop chain is followed to its terminal (non-CNAME) name |
| `ResolveTerminalNameAsync_TrailingDotAndCase_AreNormalized` | A resolved target with a trailing root dot and mixed case has the dot stripped (case preserved) for use as a lookup key |
| `ResolveTerminalNameAsync_DirectLoop_ThrowsCleanly` | A 2-node cycle (`a→b→a`) throws `InvalidOperationException` containing `"loop detected"` |
| `ResolveTerminalNameAsync_SelfLoop_ThrowsCleanly` | A name that points to itself throws `InvalidOperationException` containing `"loop detected"` |
| `ResolveTerminalNameAsync_ChainWithinDepthCap_Succeeds` | A 9-hop chain (under the `MaxCnameDepth = 10` cap) resolves successfully to the terminal name |
| `ResolveTerminalNameAsync_ChainExceedingDepthCap_ThrowsCleanly` | An 11-hop non-looping chain (over the depth cap) throws `InvalidOperationException` containing `"maximum depth"` rather than hanging |

---

## ExtractSerialFromPemTests

Regression tests for the private `CERTInextCAPlugin.ExtractSerialFromPem` helper (invoked via
reflection), which feeds the audit-log `SerialNumber` field. These pin the serial-formatting
invariants established after the BouncyCastle crypto migration (replacing
`X509Certificate2.SerialNumber`) — particularly the leading-zero-byte case where the old BCL
behavior and a naive `BigInteger.ToString(16)` diverge. Certificates are generated in-test with
BouncyCastle only, per the project's crypto policy.

| Test | What it checks |
|------|---------------|
| `ExtractSerialFromPem_PreservesLeadingZeroByte` | A serial with a leading-zero nibble in its first byte (`0x0A123456`) round-trips as `"0A123456"` (8 nibbles), not `"A123456"` (a dropped leading zero that would mis-correlate against Command's stored serial) |
| `ExtractSerialFromPem_NormalSerial_UppercaseHexNoLeadingZero` | A mid-range serial renders as plain uppercase hex with no separators |
| `ExtractSerialFromPem_LongSerial_AllBytesPreservedUppercase` | A 20-byte serial (the CA/B Forum maximum) preserves every byte as uppercase hex with no loss |
| `ExtractSerialFromPem_GarbageInput_ReturnsParseError` | Non-PEM input returns `"(parse-error)"` instead of throwing — the audit-log path must never throw |
| `ExtractSerialFromPem_EmptyBody_ReturnsEmptyPem` | A PEM header/footer with no body between them returns `"(empty-pem)"` |

---

## RedactCredentialsTests

Pins the credential-scrubbing pass that `CERTInextClient.RedactCredentials` runs on every
response/request body before it's logged or truncated. The CERTInext request `meta` block
includes an `authKey` SHA-256 digest that is itself a replayable credential under SOX (anyone with
one valid `(ts, txn, authKey)` triple can replay until the timestamp window expires); these tests
pin that the scrubber catches both the documented-as-sent field (`authKey`) and adjacent
credential field names that could end up on the wire via a future code path (`client_secret`,
`accessKey`, `password`).

| Test | What it checks |
|------|---------------|
| `RedactCredentials_ScrubsJsonCredentialFields` (`Theory` ×4) | JSON bodies with `authKey`, `client_secret`, `apiKey`, and `accessKey`/`password` fields each have the credential value replaced with `***REDACTED***` while sibling fields are left untouched |
| `RedactCredentials_ScrubsFormUrlEncodedCredentialFields` (`Theory` ×2) | Form-urlencoded bodies (`client_secret=...`, `authKey=...`) have the credential value redacted; other key/value pairs pass through untouched |
| `RedactCredentials_ScrubsAuthorizationHeaderLines` | An `Authorization: Bearer ...` header line is replaced with `Authorization: ***REDACTED***`; other header lines (`Host`, `Content-Type`) pass through unchanged |
| `RedactCredentials_PreservesNonCredentialFields` | A body containing only non-credential fields (`ts`, `txn`, `errorMessage`) is returned unchanged |
| `RedactCredentials_HandlesNullAndEmpty` (`Theory`: `null`, `""`) | `null`/empty input is returned as-is without throwing |
| `RedactCredentials_CaseInsensitiveFieldNameMatch` | Mixed-case field names (`AuthKey`, `APIKEY`) are still redacted; documents the known gap that CamelCase `ClientSecret` is NOT currently matched — only the snake_case `client_secret` form CERTInext's OAuth endpoint actually uses |

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
