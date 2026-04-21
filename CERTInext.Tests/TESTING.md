# CERTInext CA Plugin — Test Suite Reference

## Overview

There are two test classes in this project, each targeting a different layer of the plugin:

**`CERTInextClientTests`** tests the HTTP client (`CERTInextClient`) in isolation. It uses [WireMock.Net](https://github.com/WireMock-Net/WireMock.Net) to start a real in-process HTTP server on a random port, then directs the client at that server. RestSharp makes actual HTTP calls, so JSON serialization, request routing, header construction, OAuth2 token fetching, and pagination logic are all exercised end-to-end against real network I/O (loopback only).

**`CERTInextCAPluginTests`** tests the `CERTInextCAPlugin` class — the Keyfactor `IAnyCAPlugin` implementation. It replaces `ICERTInextClient` with a [Moq](https://github.com/moq/moq4) strict mock so no network calls are made. The focus is on plugin-level logic: argument validation, status mapping, enrollment type routing, revocation reason translation, and synchronization behavior.

The split keeps concerns separate. If a test fails in `CERTInextClientTests`, the bug is in HTTP transport or serialization. If it fails in `CERTInextCAPluginTests`, the bug is in plugin logic.

---

## Running the Tests

**Prerequisites:**
- .NET SDK 6.0 or later
- NuGet packages restored (`dotnet restore`)
- No external services required — WireMock runs in-process

**Run all tests:**
```bash
dotnet test
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

Each `CERTInextClientTests` instance starts a fresh `WireMockServer` in its constructor and stops it in `Dispose()`, so tests are isolated and can run in parallel without port conflicts.

---

## CERTInextClientTests

The test class implements `IDisposable`. A `WireMockServer` is started on a random available port in the constructor. All tests build a `CERTInextClient` pointed at `_server.Urls[0]`.

Two helper methods build clients:
- `BuildClient(authMode, apiKey)` — builds an ApiKey-authenticated client (default: `authMode="ApiKey"`, `apiKey="test-key"`)
- `BuildOAuthClient(tokenUrl)` — builds an OAuth2 client with `client_id="my-client"` and `client_secret="my-secret"`

### PingAsync

| Test | Stub | Assertion |
|------|------|-----------|
| `PingAsync_ReturnsHealthy_WhenServerRespondsOk` | `GET /api/v1/health` → 200, `{"status":"ok","version":"2.1.0"}` | Does not throw; WireMock log contains a request to `/api/v1/health` |
| `PingAsync_Throws_When500Returned` | `GET /api/v1/health` → 500, server error body | Throws an `Exception` with message containing `"health check failed"` |

### API Key Authentication

| Test | Stub | Assertion |
|------|------|-----------|
| `PingAsync_SendsApiKeyHeader_WhenAuthModeIsApiKey` | `GET /api/v1/health` matched only when header `X-API-Key: super-secret-key` is present → 200 | WireMock records exactly one matched request, confirming the header was sent with the correct value |

This test verifies the header matching at the WireMock level: if the client sends the wrong header name or value, WireMock finds no matching stub and the request fails.

### OAuth2 Token Fetch and Caching

| Test | Stub | Assertion |
|------|------|-----------|
| `OAuth2_FetchesToken_BeforeFirstApiCall` | `POST /oauth/token` → 200, token JSON with `expires_in=3600`; `GET /api/v1/health` → 200 | Log entries contain both `/oauth/token` and `/api/v1/health`, confirming token acquisition precedes the API call |
| `OAuth2_TokenIsCached_SecondCallDoesNotRefetch` | Same as above | `PingAsync` called twice; `/oauth/token` appears exactly once in log, `/api/v1/health` appears twice |

### EnrollCertificateAsync

| Test | Stub | Assertion |
|------|------|-----------|
| `EnrollCertificateAsync_ReturnsCertificate_WhenServerIssues` | `POST /api/v1/certificates` → 200, enroll response with `status="issued"`, cert PEM, `id=CertId1` | Result is not null; `Id == CertId1`; `Status == "issued"`; `Certificate` contains `"BEGIN CERTIFICATE"` |
| `EnrollCertificateAsync_ReturnsPending_WhenServerReturnsPendingApproval` | `POST /api/v1/certificates` → 200, `{"status":"pending_approval","certificate":null,...}` | `Status == "pending_approval"`; `Certificate` is null |
| `EnrollCertificateAsync_Throws_When4xxReturned` | `POST /api/v1/certificates` → 400, `{"error":"BAD_REQUEST","message":"Invalid CSR."}` | Throws `Exception` with message containing `"Invalid CSR"` |
| `EnrollCertificateAsync_Throws_When5xxReturned` | `POST /api/v1/certificates` → 500, server error body | Throws `Exception` (any type) |
| `EnrollCertificateAsync_Throws_When401Returned` | `POST /api/v1/certificates` → 401, unauthorized body | Throws `Exception` (any type) |

### GetCertificateAsync

| Test | Stub | Assertion |
|------|------|-----------|
| `GetCertificateAsync_ReturnsCertificate_WhenFound` | `GET /api/v1/certificates/{CertId1}` → 200, full certificate JSON | Result is not null; `Id == CertId1`; `Status == "issued"`; `Certificate` contains `"BEGIN CERTIFICATE"` |
| `GetCertificateAsync_ThrowsKeyNotFound_When404Returned` | `GET /api/v1/certificates/nonexistent-id` → 404, not-found error body | Throws `KeyNotFoundException` |

### RevokeCertificateAsync

| Test | Stub | Assertion |
|------|------|-----------|
| `RevokeCertificateAsync_Succeeds_When200Returned` | `POST /api/v1/certificates/{CertId1}/revoke` → 200, `{"success":true,...}` | Does not throw |
| `RevokeCertificateAsync_Throws_When4xxReturned` | `POST /api/v1/certificates/{CertId1}/revoke` → 409, `{"error":"ALREADY_REVOKED",...}` | Throws `Exception` with message containing `"revoke certificate"` |

### RenewCertificateAsync

| Test | Stub | Assertion |
|------|------|-----------|
| `RenewCertificateAsync_ReturnsNewCertificate_OnSuccess` | `POST /api/v1/certificates/{CertId1}/renew` → 200, renew response with `id="cert-renewed-001"` | `Id == "cert-renewed-001"`; `Status == "issued"`; `Certificate` contains `"BEGIN CERTIFICATE"` |

### ListCertificatesAsync

`ListCertificatesAsync` is an `IAsyncEnumerable<GetCertificateResponse>` that pages through results using a `page` query parameter, stopping when the returned page is empty or the last page has been fetched.

| Test | Stub | Assertion |
|------|------|-----------|
| `ListCertificatesAsync_ReturnsSinglePage_WhenOnlyOnePage` | `GET /api/v1/certificates?page=1` → 200, single-page list with one cert (`CertId1`) | Enumeration yields exactly 1 item with `Id == CertId1` |
| `ListCertificatesAsync_IteratesMultiplePages` | `GET /api/v1/certificates?page=1` → page 1 of 2 (`CertId1`); `GET /api/v1/certificates?page=2` → page 2 of 2 (`CertId2`) | Enumeration yields 2 items; both `CertId1` and `CertId2` are present |
| `ListCertificatesAsync_StopsWhenEmptyPageReturned` | `GET /api/v1/certificates?page=1` → 200, `{"data":[],"pagination":{"total":0,...}}` | Enumeration yields 0 items |
| `ListCertificatesAsync_RespectsIssuedAfterFilter` | Any `GET /api/v1/certificates` request that includes an `issuedAfter` query parameter → 200, single-page list | Enumeration yields 1 item; WireMock log entry for the first request has an `issuedAfter` key in its query string |

### GetProfilesAsync

| Test | Stub | Assertion |
|------|------|-----------|
| `GetProfilesAsync_ReturnsProfiles_WhenServerResponds` | `GET /api/v1/profiles` → 200, two-profile JSON (`ProfileIdTls`, `ProfileIdClient`, both active) | Result has 2 items; both profile IDs present; all have `Active == true` |
| `GetProfilesAsync_ReturnsEmptyList_WhenDataIsEmpty` | `GET /api/v1/profiles` → 200, `{"data":[]}` | Result is empty |

---

## CERTInextCAPluginTests

The plugin is constructed by passing an `ICERTInextClient` mock directly: `new CERTInextCAPlugin(client)`. Moq is configured with `MockBehavior.Strict`, so any call to a method that has no setup will throw, making unexpected client calls immediately visible.

Two local helpers are used across tests:
- `MakeProductInfo(profileId, extras)` — builds an `EnrollmentProductInfo` with `ProductID` and a `ProductParameters` dictionary containing `"ProfileId"`
- `AsyncEnum(items)` — wraps a `List<GetCertificateResponse>` as an `IAsyncEnumerable<GetCertificateResponse>` for use in `ListCertificatesAsync` mock setups

### Ping

| Test | Mock setup | Assertion |
|------|-----------|-----------|
| `Ping_Succeeds_WhenClientPingAsyncDoesNotThrow` | `PingAsync` returns `Task.CompletedTask` | Does not throw; `PingAsync` called exactly once |
| `Ping_Rethrows_WhenClientPingThrows` | `PingAsync` throws `Exception("Connection refused")` | Throws `Exception` with message matching `"*CERTInext*Connection refused*"` — verifies the plugin wraps the error with context |

### GetProductIds

| Test | Mock setup | Assertion |
|------|-----------|-----------|
| `GetProductIds_ReturnsActiveProfileIds` | `GetProfilesAsync` returns `ActiveProfiles()` (two active profiles) | Returns 2 IDs: `ProfileIdTls` and `ProfileIdClient` |
| `GetProductIds_FiltersOutInactiveProfiles` | `GetProfilesAsync` returns `MixedProfiles()` (two active, one inactive `"legacy-profile"`) | Returns 2 IDs; `"legacy-profile"` is not present |
| `GetProductIds_ReturnsEmptyList_WhenClientThrows` | `GetProfilesAsync` throws `Exception("Unavailable")` | Returns an empty list rather than propagating the exception |

### ValidateCAConnectionInfo

The plugin validates the connection info dictionary before any API calls are made.

| Test | Input | Assertion |
|------|-------|-----------|
| `ValidateCAConnectionInfo_Throws_WhenApiUrlMissing` | `AuthMode="ApiKey"`, `ApiKey` set, no `ApiUrl` | Throws `AnyCAValidationException` with message matching `"*ApiUrl*required*"` |
| `ValidateCAConnectionInfo_Throws_WhenApiUrlIsNotUri` | `ApiUrl="not-a-url"` | Throws `AnyCAValidationException` with message matching `"*valid absolute URI*"` |
| `ValidateCAConnectionInfo_Throws_WhenApiKeyMissingForApiKeyMode` | `ApiUrl` set, `AuthMode="ApiKey"`, no `ApiKey` | Throws `AnyCAValidationException` with message matching `"*ApiKey*required*"` |
| `ValidateCAConnectionInfo_Throws_WhenBasicCredentialsMissing` | `ApiUrl` set, `AuthMode="Basic"`, no `Username` or `Password` | Throws `AnyCAValidationException` with message matching `"*Username*required*"` |
| `ValidateCAConnectionInfo_Throws_WhenOAuth2FieldsMissing` | `ApiUrl` set, `AuthMode="OAuth2"`, no token URL, client ID, or secret | Throws `AnyCAValidationException` with message matching `"*OAuth2TokenUrl*required*"` |
| `ValidateCAConnectionInfo_Throws_WhenAuthModeIsInvalid` | `ApiUrl` set, `AuthMode="CertificateBased"` | Throws `AnyCAValidationException` with message matching `"*AuthMode*must be one of*"` |
| `ValidateCAConnectionInfo_SkipsValidation_WhenDisabled` | `Enabled=false`, nothing else set | Does not throw; no calls made to the mock client |

### ValidateProductInfo

| Test | Input | Assertion |
|------|-------|-----------|
| `ValidateProductInfo_Throws_WhenProfileIdMissing` | `ProductID = string.Empty`, valid connection info | Throws `AnyCAValidationException` with message matching `"*ProfileId*required*"` |

### Enroll

The `Enroll` method accepts an `EnrollmentType` parameter. `New` and `Reissue` both route to `EnrollCertificateAsync`. `RenewOrReissue` routes to `RenewCertificateAsync` when `PriorCertSN` is present in `ProductParameters`, and falls back to `EnrollCertificateAsync` when it is not.

| Test | EnrollmentType | Mock setup | Assertion |
|------|---------------|-----------|-----------|
| `Enroll_New_CallsEnrollAsync_AndReturnsIssuedResult` | `New` | `EnrollCertificateAsync` (matching `ProfileId == ProfileIdTls`) returns `IssuedEnrollResponse()` | `CARequestID == CertId1`; `Status == EndEntityStatus.GENERATED`; `Certificate` contains `"BEGIN CERTIFICATE"`; client called once |
| `Enroll_New_ReturnsPendingStatus_WhenCaReturnsPendingApproval` | `New` | `EnrollCertificateAsync` returns `PendingEnrollResponse()` | `Status == EndEntityStatus.EXTERNALVALIDATION` |
| `Enroll_New_Throws_WhenProfileIdNotSet` | `New` | No setup (strict mock — any unexpected call throws) | Throws `Exception` with message matching `"*ProfileId*required*"` before calling the client |
| `Enroll_Reissue_AlsoCallsEnrollAsync` | `Reissue` | `EnrollCertificateAsync` returns `IssuedEnrollResponse()` | `Status == EndEntityStatus.GENERATED`; `EnrollCertificateAsync` called once |
| `Enroll_Renew_FallsBackToNewEnroll_WhenNoPriorCertSn` | `RenewOrReissue` | `EnrollCertificateAsync` returns `IssuedEnrollResponse()` | `CARequestID == CertId1`; `EnrollCertificateAsync` called once; `RenewCertificateAsync` never called |

### GetSingleRecord

| Test | Mock setup | Assertion |
|------|-----------|-----------|
| `GetSingleRecord_ReturnsMappedCertificate_ForIssuedCert` | `GetCertificateAsync(CertId1)` returns `IssuedCertRecord()` | `CARequestID == CertId1`; `Status == EndEntityStatus.GENERATED`; `Certificate` contains `"BEGIN CERTIFICATE"`; `ProductID == ProfileIdTls` |
| `GetSingleRecord_ReturnsMappedCertificate_ForRevokedCert` | `GetCertificateAsync(CertId3)` returns `RevokedCertRecord()` | `Status == EndEntityStatus.REVOKED`; `RevocationDate` is not null; `RevocationReason == 1` (keyCompromise) |
| `GetSingleRecord_Rethrows_WhenCertNotFound` | `GetCertificateAsync("no-such-id")` throws `KeyNotFoundException` | Rethrows `KeyNotFoundException` |

### Revoke

The plugin looks up the certificate first to check whether it is already revoked, then calls `RevokeCertificateAsync` only if it is not. CRL reason codes (integers) are mapped to string values expected by the CERTInext API.

| Test | Mock setup | Assertion |
|------|-----------|-----------|
| `Revoke_CallsRevokeCertificateAsync_AndReturnsRevokedStatus` | `GetCertificateAsync(CertId1)` returns issued cert; `RevokeCertificateAsync(CertId1, ...)` returns `Task.CompletedTask` | Returns `EndEntityStatus.REVOKED`; `RevokeCertificateAsync` called once with `Reason == "keyCompromise"` (CRL code 1) |
| `Revoke_ReturnsAlreadyRevoked_WhenCertAlreadyRevoked` | `GetCertificateAsync(CertId3)` returns revoked cert | Returns `EndEntityStatus.REVOKED`; `RevokeCertificateAsync` never called |
| `Revoke_MapsAllCrlReasonCodes` | For each reason code 0–5: `GetCertificateAsync` returns issued cert; `RevokeCertificateAsync` matched only when `Reason` equals the expected string | Verifies the complete mapping: `0→"unspecified"`, `1→"keyCompromise"`, `2→"caCompromise"`, `3→"affiliationChanged"`, `4→"superseded"`, `5→"cessationOfOperation"` |

### Synchronize

`Synchronize` iterates `ListCertificatesAsync` and adds mapped `AnyCAPluginCertificate` objects to a `BlockingCollection<AnyCAPluginCertificate>`. A full sync passes `null` as `issuedAfter`; a delta sync passes the `lastSync` timestamp. Certificates with a status that cannot be mapped (e.g., `"failed"`) are skipped.

| Test | Mock setup | Assertion |
|------|-----------|-----------|
| `Synchronize_FullSync_AddsAllCertsToBuffer` | `ListCertificatesAsync(null, ...)` returns two issued certs (`CertId1`, `CertId2`) | Buffer contains 2 items; both IDs present |
| `Synchronize_DeltaSync_PassesLastSyncFilter` | `ListCertificatesAsync` captures the `issuedAfter` argument and returns one cert | Captured `issuedAfter` equals the `lastSync` value passed to `Synchronize` |
| `Synchronize_FullSync_PassesNullIssuedAfter` | `ListCertificatesAsync` captures `issuedAfter` and returns empty | Even when `lastSync` is non-null, `fullSync: true` causes `issuedAfter` to be passed as `null` |
| `Synchronize_SkipsFailedCertificates` | `ListCertificatesAsync` returns one issued cert and one cert with `status="failed"` and `Certificate=null` | Buffer contains exactly 1 item (`CertId1`); the failed cert is dropped |
| `Synchronize_HonoursCancellation` | Custom async enumerable that yields one cert, cancels the `CancellationTokenSource`, then calls `ct.ThrowIfCancellationRequested()` before yielding a second | Throws `OperationCanceledException` |
| `Synchronize_MapsRevokedCertificates_Correctly` | `ListCertificatesAsync` returns one revoked cert (`CertId3`) | Buffer contains 1 item; `Status == EndEntityStatus.REVOKED`; `RevocationDate` is not null |

---

## MockCertificateData

`MockCertificateData` is a static internal class shared by both test suites. It provides two types of output:

- **Object helpers** — return typed API response objects for use in Moq setups
- **JSON helpers** — return raw JSON strings for use in WireMock stubs

### Constants

| Constant | Value | Used for |
|----------|-------|---------|
| `FakePemCertificate` | PEM block starting with `-----BEGIN CERTIFICATE-----` | Certificate body in all responses |
| `FakeCsrPem` | PEM block starting with `-----BEGIN CERTIFICATE REQUEST-----` | CSR body in enroll and renew requests |
| `CertId1` | `"cert-aaa-111"` | Default issued certificate ID |
| `CertId2` | `"cert-bbb-222"` | Second certificate ID (pagination, delta sync) |
| `CertId3` | `"cert-ccc-333"` | Default revoked certificate ID |
| `ProfileIdTls` | `"tls-server"` | TLS server profile |
| `ProfileIdClient` | `"client-auth"` | Client authentication profile |

### Object helpers (Moq)

| Method | Returns |
|--------|---------|
| `ActiveProfiles()` | Two `ProfileInfo` objects, both `Active=true`: `ProfileIdTls` and `ProfileIdClient` |
| `MixedProfiles()` | Three `ProfileInfo` objects: `ProfileIdTls` (active), `"legacy-profile"` (inactive), `ProfileIdClient` (active) |
| `IssuedEnrollResponse(id)` | `EnrollCertificateResponse` with `Status="issued"`, `FakePemCertificate`, `SerialNumber="0A1B2C3D4E5F"` |
| `PendingEnrollResponse(id)` | `EnrollCertificateResponse` with `Status="pending_approval"`, `Certificate=null` |
| `IssuedCertRecord(id)` | `GetCertificateResponse` with `Status="issued"`, `FakePemCertificate`, `ProfileId=ProfileIdTls`, issued 2024-06-01, expires 2025-06-01 |
| `RevokedCertRecord(id)` | `GetCertificateResponse` with `Status="revoked"`, `RevokedAt=2024-03-15`, `RevocationReason="keyCompromise"` |

### JSON helpers (WireMock)

| Method | Returns |
|--------|---------|
| `EnrollResponseJson(id, status)` | Enroll response JSON with `status="issued"` and `FakePemCertificate` escaped for JSON |
| `PendingEnrollResponseJson(id)` | Enroll response JSON with `status="pending_approval"` and `certificate:null` |
| `GetCertificateJson(id, status)` | Single certificate JSON including SANs, subject, CSR, and revocation fields |
| `RevokedCertificateJson(id)` | Certificate JSON with `status="revoked"` and revocation fields populated |
| `SinglePageListJson(id)` | Paginated list JSON: one cert on page 1 of 1 |
| `TwoPageListJson(page)` | Paginated list JSON: call with `page=1` or `page=2` to get the respective page of a two-page result set |
| `RevokeSuccessJson()` | `{"success":true,"message":"Certificate revoked successfully."}` |
| `RenewResponseJson(newId)` | Renew response JSON with a new certificate ID |
| `HealthOkJson()` | `{"status":"ok","version":"2.1.0"}` |
| `OAuth2TokenJson(expiresIn)` | OAuth2 token response with `access_token="fake-bearer-token-abc123"` |
| `ProfilesJson(profiles)` | Profiles list JSON; defaults to `ActiveProfiles()` if no argument passed |
| `NotFoundErrorJson(id)` | 404 error body with the given ID in the message |
| `ServerErrorJson()` | Generic 500 error body |
| `UnauthorizedJson()` | 401 error body |

`EscapeForJson` is a private helper used internally to embed `FakePemCertificate` and `FakeCsrPem` (which contain newlines and no special JSON escaping) inside JSON string values.

---

## Adding New Tests

### Which suite to add to

- **Add to `CERTInextClientTests`** when testing HTTP-level behavior: a new endpoint, a new error status code, authentication header details, query parameter serialization, or any behavior where the actual request sent over the wire matters.
- **Add to `CERTInextCAPluginTests`** when testing plugin logic: a new enrollment type, a new validation rule, a new status mapping, or how the plugin responds to specific client return values or exceptions.

### Adding a new WireMock stub

1. Register a stub in the test body using the existing pattern:
   ```csharp
   _server
       .Given(Request.Create().WithPath("/api/v1/your-endpoint").UsingGet())
       .RespondWith(Response.Create()
           .WithStatusCode(200)
           .WithHeader("Content-Type", "application/json")
           .WithBody(@"{""yourField"":""yourValue""}"));
   ```
2. If the response shape is reused across tests, add a JSON helper to `MockCertificateData` following the same `string YourResponseJson(...)` convention.
3. If you need a typed object for a Moq setup that mirrors the new JSON, add a corresponding object helper (e.g., `YourResponse()`) that returns a populated API response object.
4. Verify request details (headers, query parameters, body) by inspecting `_server.LogEntries` after the call, following the pattern in `PingAsync_SendsApiKeyHeader_WhenAuthModeIsApiKey` and `ListCertificatesAsync_RespectsIssuedAfterFilter`.
