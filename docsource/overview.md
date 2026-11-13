## Overview

The CERTInext AnyCA Gateway REST plugin extends the certificate lifecycle capabilities of the CERTInext platform (by eMudhra) to Keyfactor Command via the Keyfactor AnyCA Gateway REST. Related documents:

- [configuration.md](configuration.md): installation and configuration details.
- [architecture.md](architecture.md): design notes.
- [migration-v1-to-v2.md](migration-v1-to-v2.md): moving a connector to the V2 API.
- [development.md](development.md): local development.

## CERTInext CA Certificates

Before the gateway can register a CA backed by this plugin, the Keyfactor Command server (and the AnyCA Gateway REST host) must trust the CERTInext issuing CA chain. Download the root and any intermediate CA certificates from the CERTInext portal for the environment you are targeting:

| Environment | Portal Sign-in URL |
|---|---|
| Sandbox | https://sandbox-us.certinext.io/ |
| Production — India (Global) | https://in.certinext.io/ |
| Production — US | https://us.certinext.io/ |

To import the chain:

1. Sign in to the CERTInext portal for your environment.
2. Open the certificate-authority / chain download page.
3. Export each CA in the chain as PEM or DER.
4. On the gateway host, import the root CA into the **Trusted Root Certification Authorities** store.
5. Import any subordinate CAs into the **Intermediate Certification Authorities** store.

See [configuration.md](configuration.md#gateway-registration) for the full Gateway Registration walkthrough.

> Note: eMudhra is withdrawing from public TLS, and the emSign roots are being phased out by browser root programs (Chrome and Firefox after November 16, 2026; Apple on November 30, 2026). CERTInext public TLS certificates will be issued under a different CA, so the steps above need repeating with the new chain. See [Change of issuing CA](configuration.md#change-of-issuing-ca-emudhra-exit-from-public-tls).

## Troubleshooting

| Symptom | Section |
|---|---|
| V1 enrollments fail with `Inactive Account User.` | [`"Inactive Account User."` from `GenerateOrderSSL`](#inactive-account-user-returned-from-generateorderssl-v1) |
| Enrollment returns pending (`Status=90`, `EXTERNALVALIDATION`) | [Enrollment returns immediately with `Status=90`](#enrollment-returns-immediately-with-status90-externalvalidation) |
| `EMS-956 "Invalid Request for this API"` from `GetDcv` | [`EMS-956` from `GetDcv`](#ems-956-invalid-request-for-this-api-from-getdcv-v1) |
| HTTP 500 and a `TypeLoadException` in the gateway log | [Plugin fails to load](#plugin-fails-to-load-with-could-not-load-type-keyfactoranygatewayextensionsidomainvalidatorfactory) |
| Connector fails to start with an `https` error | [`ApiUrl` must use https](#connector-fails-to-start-apiurl--must-use-https) |
| Enrollment fails with `invalid custom extension or certificate policy OIDs` | [Enrollment fails with `invalid custom extension or certificate policy OIDs`](#enrollment-fails-with-invalid-custom-extension-or-certificate-policy-oids) |

### `"Inactive Account User."` returned from `GenerateOrderSSL` (V1)

**Symptom**

V1 enrollments fail with the gateway exception:

```
CERTInext order failed: Inactive Account User.. See gateway logs for details.
```

The same access key / account works before and after the failing window — a `Ping` (`ValidateCredentials`) call seconds earlier returns success, and the next individual enrollment after a brief pause also succeeds.

**Root cause**

- **Cause:** the CERTInext sandbox at `https://sandbox-us-api.certinext.io/emSignHub-API` applies a **burst rate limit** on order placement.
- **Generic error:** the rejection uses the string `"Inactive Account User."`, the same string the API uses for genuinely inactive accounts.
- **No distinguishing field:** the response has no `errorCode`, `Retry-After` header, or structured field that tells the two conditions apart.
- **Trigger:** roughly **16 or more enrollments submitted within 10 seconds** on the US sandbox.
- **Below the threshold:** lower submission velocity runs cleanly.

**Confirmation steps**

1. Run a single `Ping` against the same `ApiUrl` / `ApiKey`. If it succeeds, the account is active; the failure was almost certainly a rate-limit hit.
2. Check the gateway warning log for the API-failure line the plugin writes just before it throws. It includes the full raw response body, so any distinguishing code or message CERTInext returns appears there.
3. Wait 30–60 seconds, then retry the failed enrollment. A successful retry confirms it was a rate limit.

**Mitigation**

- **Automatic retry**: when order placement returns this error, the plugin retries it with exponential backoff and jitter (up to 5 attempts) before surfacing the failure, so brief bursts resolve without operator action.
- **Reduce submission velocity**: throttle order placements to roughly one per 1–2 seconds. The plugin has no built-in client-side throttle; pacing must come from the caller (for example Keyfactor Command's enrollment scheduling, or a workflow that places certificates in batches).
- **High-volume migrations**: split the workload into batches of about 10 orders separated by a short pause, rather than submitting everything at once.

### Enrollment returns immediately with `Status=90 (EXTERNALVALIDATION)`

**Symptom**

Enrollment completes but the certificate is not yet issued — Command shows the request as pending. A later `Synchronize` picks it up.

**Root cause**

This is the expected result in any of these cases:

- **OV or EV order:** CERTInext issues these after organization verification (minutes to hours), longer than the enrollment call waits.
- **DCV enabled but unable to run:** no DNS provider plugin is deployed on the gateway, or none resolves the order's domain. The plugin logs why. The order completes only after the domain is validated some other way.
- **`Enroll()` budget elapsed:** the plugin's bounded wait ended before CERTInext finished issuing. The budget is:
    - `PickupRetries` × `PickupDelay` for the certificate pickup poll, capped at 75 s in total (inside Command's roughly 100 s enrollment-call timeout);
    - on V1, `DcvWaitForChallengeSeconds` + `DcvWaitForIssuanceSeconds` (default 60 s each) around DCV. When DCV engages for an order, these waits replace the pickup wait; they do not stack.
- **Issued but certificate not generated yet (V2):** CERTInext reports the order `issued` while Download Certificate still answers 422 `EMS-1165`. Normal generation takes about 20 s; the pickup poll waits for it, logging at Debug level and writing one Information summary. If the budget runs out the next sync imports the certificate.
- **DCV could not validate every domain:** for example an IP or email SAN with no DNS provider. V1 still validates the other domains but returns pending without waiting for issuance.
- **V1 renewal still pending DNS-01 validation:** with DCV enabled, a renewal waiting on DNS-01 validation returns pending at once instead of holding a worker for the pickup wait; the next sync completes the validation.

**Mitigation**

The next gateway sync cycle picks the certificate up and moves it to issued. Sync-driven DCV is bounded per pass by `DcvSyncMaxOrderAgeHours` and `DcvSyncMaxPerPass`, so a large backlog of old pending orders doesn't slow each pass. See [configuration.md](configuration.md) for the knobs that tune the `Enroll()` wait.

### `EMS-956 "Invalid Request for this API"` from `GetDcv` (V1)

**Symptom**

The plugin's DCV machinery starts but the first `GetDcv` call returns this error. The plugin defers DCV to the next sync cycle (a single log line, no exception).

**Root cause**

CERTInext exposes the `domainVerification` slot in `TrackOrder` **before** the `GetDcv` endpoint accepts calls for that order. The plugin recognizes this condition and treats it as "DCV not ready yet, retry on the next sync".

**Mitigation**

No action needed. The order is picked up on a subsequent sync cycle once CERTInext's gate clears; the wait can range from seconds to several hours.

### Plugin fails to load with `Could not load type 'Keyfactor.AnyGateway.Extensions.IDomainValidatorFactory'`

**Symptom**

The gateway returns HTTP 500 on CA registration or first enrollment (the response body is only a generic `ErrorCode`), and the gateway log shows a `TypeLoadException` for `Keyfactor.AnyGateway.Extensions.IDomainValidatorFactory`.

**Root cause**

The gateway's bundled `Keyfactor.AnyGateway.IAnyCAPlugin` assembly is older than 3.3, which does not define `IDomainValidatorFactory`. This plugin requires AnyCA Gateway REST 26.2.0 or later.

**Mitigation**

Upgrade the AnyCA Gateway REST to 26.2.0 or later.

### Connector fails to start: `'ApiUrl' ... must use https`

**Symptom**

After upgrading, a connector fails initialization with an error naming `ApiUrl` and `https`.

**Root cause**

The API key (V1) or OAuth client secret (V2) is sent to `ApiUrl` on every request, so the plugin rejects `http` URLs on save and at startup. A loopback host (`localhost`, `127.0.0.1`, `::1`) is the only exception, for local test servers.

**Mitigation**

Change the connector's `ApiUrl` to an `https` URL.

### Enrollment fails with `invalid custom extension or certificate policy OIDs`

**Symptom**

Command reports this error for an enrollment:

```
An error occurred while performing the operation. This may be due to invalid custom extension or certificate policy OIDs. Please see CA logs for more information.
```

The certificate request may be valid, and CERTInext may already have issued the certificate.

**Root cause**

This is a known timing issue. If the scheduled gateway sync runs while an enrollment is still finishing, the sync can create the record for that request first. The enrollment's own save then fails, because a record for the same request already exists. That record may or may not include the certificate yet. The error message does not describe this, so it looks like a problem with the request. The problem is more likely when the sync runs more often.

The plugin reduces the race: a sync skips pending and issued orders created in the last `SyncRecentOrderGraceSeconds` (default 120, plus a 5-second margin) and imports them on the next pass. That makes the error less likely, not impossible. An enrollment that takes longer than about two minutes to finish saving, or a connector with `SyncRecentOrderGraceSeconds` set to `0`, can still hit it.

**What to do before you retry**

1. Check whether CERTInext has already issued a certificate for the request.
2. In Command, search for the certificate by subject name. It may already be there, or it may appear after a later sync.
3. Check the gateway log for a "duplicate key" error. If you find one, this issue is the likely cause.

Retrying can place a second order with CERTInext, which may be billed again. Check first.

**Versions**

Seen with the CERTInext plugin on AnyCA REST Gateway 25.5, before the hold-back existed. Other versions have not been tested.
