# CERTInext AnyCA REST Gateway Plugin

An AnyCA REST Gateway plugin that enables Keyfactor Command to manage the full certificate lifecycle
(enroll, renew, revoke, and synchronize) through the
[CERTInext](https://emudhra.com/en-us/certinext/) platform by eMudhra.

## Overview

The plugin implements the `IAnyCAPlugin` interface and translates Keyfactor Command certificate
operations into CERTInext REST API calls.  It supports three authentication modes, paginated
synchronization, all standard revocation reason codes, and both renewal-via-API and
reissue-as-new enrollment flows.

## Requirements

| Component | Version |
|-----------|---------|
| Keyfactor AnyCA REST Gateway | 24.2.0+ |
| .NET Runtime | 6.0 |
| CERTInext | Any version with REST API access |

## Installation

1. Build the project in Release configuration:

   ```
   dotnet publish CERTInext/CERTInext.csproj -c Release
   ```

2. Copy the contents of `CERTInext/bin/Release/net8.0/` to the AnyCA Gateway's
   `extensions/CERTInext/` directory.

3. Ensure `manifest.json` is in the same directory as `CERTInextCAPlugin.dll`.

4. Restart the AnyCA Gateway service.

## CA Connector Configuration

Configure the following fields in the Keyfactor Command console when adding a new CA connector:

| Field | Required | Description |
|-------|----------|-------------|
| `ApiUrl` | Yes | Base URL of the CERTInext REST API (e.g. `https://us.certinext.io`) |
| `AuthMode` | Yes | Authentication mode: `ApiKey`, `Basic`, or `OAuth2` |
| `ApiKey` | When `AuthMode=ApiKey` | API key issued by CERTInext |
| `Username` | When `AuthMode=Basic` | Basic auth username |
| `Password` | When `AuthMode=Basic` | Basic auth password |
| `OAuth2TokenUrl` | When `AuthMode=OAuth2` | Token endpoint (e.g. `https://us.certinext.io/oauth/token`) |
| `OAuth2ClientId` | When `AuthMode=OAuth2` | OAuth2 client ID |
| `OAuth2ClientSecret` | When `AuthMode=OAuth2` | OAuth2 client secret |
| `IgnoreExpired` | No | If `true`, skip expired certs during sync (default: `false`) |
| `PageSize` | No | Records per sync page; max 500 (default: `100`) |
| `Enabled` | No | Set to `false` to disable the connector without deleting it (default: `true`) |

## Certificate Template Configuration

Configure the following enrollment parameters on each Keyfactor certificate template:

| Parameter | Required | Description |
|-----------|----------|-------------|
| `ProfileId` | Yes | CERTInext certificate profile ID (matches a profile in the CERTInext portal) |
| `ValidityDays` | No | Validity period in days; uses profile default if omitted |
| `AutoApprove` | No | Attempt auto-approval for `pending_approval` certs (default: `false`) |
| `RequesterName` | No | Default requester name when none is in the subject |
| `RequesterEmail` | No | Default requester email when none is in the subject |
| `RenewalWindowDays` | No | Days before expiry to use the renew API vs. reissuing new (default: `90`) |
| `KeyType` | No | Key algorithm hint e.g. `RSA2048`, `EC256`; uses profile default if omitted |

## Authentication Modes

### API Key (recommended for most deployments)

```json
{
  "AuthMode": "ApiKey",
  "ApiKey": "<your-api-key>"
}
```

The plugin sends the key as an `X-API-Key` header on every request.

### HTTP Basic

```json
{
  "AuthMode": "Basic",
  "Username": "<username>",
  "Password": "<password>"
}
```

### OAuth2 Client Credentials

```json
{
  "AuthMode": "OAuth2",
  "OAuth2TokenUrl": "https://us.certinext.io/oauth/token",
  "OAuth2ClientId": "<client-id>",
  "OAuth2ClientSecret": "<client-secret>"
}
```

Tokens are cached in memory and refreshed automatically 60 seconds before expiry.

## Enrollment Flows

### New Certificate

A fresh PKCS#10 CSR is forwarded to CERTInext via `POST /api/v1/certificates`.  The response
is either `issued` (certificate immediately returned) or `pending_approval` (certificate will
be returned during the next synchronization once approved in the portal).

### Renewal

When Keyfactor Command triggers a `RenewOrReissue`:

1. The plugin resolves the prior certificate's CARequestID from the `PriorCertSN` parameter.
2. If the certificate is within the `RenewalWindowDays` window, it calls
   `POST /api/v1/certificates/{id}/renew` on the existing certificate ID.
3. If outside the window, a fresh enrollment is submitted instead.

### Reissue

Treated as a new enrollment.

## Synchronization

The plugin pages through `GET /api/v1/certificates` with an optional `issuedAfter` filter for
delta syncs.  For each certificate it:

1. Maps the CERTInext status to a Keyfactor `RequestDisposition`.
2. Skips certificates in terminal failure states (rejected, cancelled, failed).
3. Optionally skips expired certificates when `IgnoreExpired=true`.
4. Adds each remaining certificate to the blocking buffer for Command to process.

Full sync (`fullSync=true` in the gateway configuration) fetches all certificates regardless
of issuance date.

## Status Mapping

| CERTInext Status | Keyfactor RequestDisposition |
|-----------------|------------------------------|
| `active`, `issued` | ISSUED |
| `pending`, `pending_approval`, `processing` | PENDING |
| `revoked` | REVOKED |
| `expired` | ISSUED (retained in inventory) |
| `rejected`, `failed`, `cancelled` | FAILED (skipped during sync) |

## Building and Testing

```bash
# Build
dotnet build

# Run unit tests (if test project is added)
dotnet test

# Produce release artifacts
dotnet publish CERTInext/CERTInext.csproj -c Release
```

## License

Copyright 2024 Keyfactor.  Licensed under the Apache License, Version 2.0.
See [LICENSE](LICENSE) for details.
