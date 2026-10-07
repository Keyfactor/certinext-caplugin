## Overview

The CERTInext AnyCA Gateway REST plugin extends the certificate lifecycle capabilities of the CERTInext platform (by eMudhra) to Keyfactor Command via the Keyfactor AnyCA Gateway REST. See [configuration.md](configuration.md) for full installation and configuration details, [architecture.md](architecture.md) for design notes, [migration-v1-to-v2.md](migration-v1-to-v2.md) for moving a connector to the V2 API, and [development.md](development.md) for local development.

## CERTInext CA Certificates

Before the gateway can register a CA backed by this plugin, the Keyfactor Command server (and the AnyCA Gateway REST host) must trust the CERTInext issuing CA chain. Download the root and any intermediate CA certificates from the CERTInext portal for the environment you are targeting:

| Environment | Portal Sign-in URL |
|---|---|
| Sandbox | https://sandbox-us.certinext.io/ |
| Production — India (Global) | https://in.certinext.io/ |
| Production — US | https://us.certinext.io/ |

After signing in, navigate to the certificate-authority / chain download page in the portal, export each CA in the chain as PEM or DER, and import them into the appropriate Windows certificate stores on the gateway host (Trusted Root for the root CA, Intermediate Certification Authorities for any subordinates). See [configuration.md](configuration.md#gateway-registration) and the [README](../README.md#configuration) for the full Gateway Registration walkthrough.

## Troubleshooting

### `"Inactive Account User."` returned from `GenerateOrderSSL` (V1)

**Symptom**

V1 enrollments fail with the gateway exception:

```
CERTInext order failed: Inactive Account User.. See gateway logs for details.
```

The same access key / account works before and after the failing window — a `Ping` (`ValidateCredentials`) call seconds earlier returns success, and the next individual enrollment after a brief pause also succeeds.

**Root cause**

The CERTInext sandbox at `https://sandbox-us-api.certinext.io/emSignHub-API` applies a **burst rate limit** on order placement and reports the rejection with the **generic** error string `"Inactive Account User."` — the same string the API uses for genuinely inactive accounts. The response carries no distinguishing `errorCode`, `Retry-After` header, or structured field that tells the two conditions apart.

The limit applies at roughly **16 or more enrollments submitted within 10 seconds** on the US sandbox. Submission velocity well below that runs cleanly.

**Confirmation steps**

1. Run a single `Ping` against the same `ApiUrl` / `AccessKey`. If it succeeds, the account is active; the failure was almost certainly a rate-limit hit.
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

This is the expected result when:

1. The order is OV or EV. CERTInext issues these after organization verification (minutes to hours), longer than the enrollment call waits.
2. DCV is enabled but cannot run: no DNS provider plugin is deployed on the gateway, or none resolves the order's domain. The plugin logs why, and the order completes only after the domain is validated some other way.
3. The plugin's bounded `Enroll()` budget elapsed before CERTInext finished issuing: `PickupRetries` × `PickupDelay` for the certificate pickup poll, and on V1 `DcvWaitForChallengeSeconds` + `DcvWaitForIssuanceSeconds` (default 60s each) around DCV.

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

The gateway returns HTTP 500 on CA registration or first enrollment with the body `{"ErrorCode":"0x80131509"}`, and the gateway log shows a `TypeLoadException` for `Keyfactor.AnyGateway.Extensions.IDomainValidatorFactory`.

**Root cause**

The gateway's bundled `Keyfactor.AnyGateway.IAnyCAPlugin` assembly is older than 3.3, which does not define `IDomainValidatorFactory`. This plugin requires AnyCA Gateway REST 26.2.0 or later.

**Mitigation**

Upgrade the AnyCA Gateway REST to 26.2.0 or later.

### Connector fails to start: `'ApiUrl' ... must use https`

**Symptom**

After upgrading, a connector fails initialization with an error naming `ApiUrl` (or `OAuthTokenUrl`) and `https`.

**Root cause**

The API key (V1) or OAuth client secret (V1 OAuth and V2) is sent to these URLs on every request, so the plugin rejects `http` URLs on save and at startup. A loopback host (`localhost`, `127.0.0.1`, `::1`) is the only exception, for local test servers.

**Mitigation**

Change the connector's `ApiUrl` (and, for V1 OAuth, `OAuthTokenUrl`) to an `https` URL.

### V2: `Multiple CERTInext catalog products match ProductID ...`

**Symptom**

A V2 template that sets only `ProductId` fails to save, or an enrollment against it fails, listing several product codes.

**Root cause**

The live V2 catalog carries more than one product at the same assurance level (for example two DV SSL products with different billing terms), and the plugin won't guess between them.

**Mitigation**

Set `ProductCode` on the template to one of the listed codes, or set the connector's `DefaultProductCode` to one of them. See [V2 Product Code Resolution](configuration.md#v2-product-code-resolution).
