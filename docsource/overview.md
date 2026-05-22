## Overview

The CERTInext AnyCA Gateway REST plugin extends the certificate lifecycle capabilities of the CERTInext platform (by eMudhra) to Keyfactor Command via the Keyfactor AnyCA Gateway REST. See [configuration.md](configuration.md) for full installation and configuration details, [architecture.md](architecture.md) for design notes, and [development.md](development.md) for local development.

## Troubleshooting

### `"Inactive Account User."` returned from `GenerateOrderSSL`

**Symptom**

Enrollments fail with the gateway exception:

```
CERTInext order failed: Inactive Account User.. See gateway logs for details.
```

The same access key / account works perfectly fine before and after the failing window — a `Ping` (`ValidateCredentials`) call seconds earlier returns success, and the next individual enrollment after a brief pause also succeeds.

**Root cause**

The CERTInext sandbox at `https://sandbox-us-api.certinext.io/emSignHub-API` applies a **burst rate limit** on order placement and surfaces rate‑limit rejection through the **generic** error string `"Inactive Account User."` — the same string the API uses for genuinely inactive accounts. There is currently no distinguishing `errorCode`, `Retry-After` header, or structured field to tell the two conditions apart from the meta block alone.

Empirically the limit kicks in at roughly **16+ enrollments submitted within 10 seconds** on the US sandbox. Sustained submission velocity well below that runs cleanly.

**Confirmation steps**

1. Run a single `Ping` against the same `ApiUrl` / `AccessKey`. If it succeeds, the account is active; the prior failure was almost certainly a rate-limit hit.
2. Check the gateway warning log for the `LogApiFailure` line emitted just before the throw (see issue [#8](../../issues/8) and the `LogApiFailure` helper in `CERTInextClient.cs`). The full raw response body is included there — if CERTInext ever surfaces a distinguishing code or message for rate-limit (as opposed to account-state), it will appear in that line.
3. Wait 30–60 seconds, then retry the failed enrollment(s). A successful retry confirms it was rate-limit.

**Mitigation**

- **Reduce submission velocity**: throttle order placements to roughly one per 1–2 seconds. The plugin does not yet have a built-in client-side throttle; pacing must come from the caller (e.g. Keyfactor Command's enrollment scheduling, or a workflow that places certs in batches).
- **For high-volume migration scenarios**: split the workload into batches of ~10 orders separated by a short pause, rather than firing everything at once.
- **No client-side automatic retry on this error**: a defensive retry inside `PlaceOrderAsync` would paper over the misleading error string and burn the operator's order quota on retries. We document the gotcha instead.

### Enrollment returns immediately with `Status=90 (EXTERNALVALIDATION)`

**Symptom**

Enrollment completes successfully but the cert is not yet issued — Command shows the request in pending status. A subsequent `Synchronize` picks it up.

**Root cause**

This is the expected return shape on two paths:

1. The plugin was loaded on an older gateway host (pre-IAnyCAPlugin v3.3) that does not inject `IDomainValidatorFactory`. DCV cannot run, so any product that requires DNS validation completes only after CERTInext-side validation finishes.
2. The plugin's bounded `Enroll()` budget (`DcvWaitForChallengeSeconds` + `DcvWaitForIssuanceSeconds`, defaults 60s each) elapsed before CERTInext finished asynchronous issuance.

**Mitigation**

The next gateway sync cycle will pick the cert up and transition it to `GENERATED`. The plugin's sync-driven DCV retry is single-shot per record, so even with hundreds of pending orders the sync completes in seconds, not minutes — see [configuration.md](configuration.md) for the `DcvWaitForChallengeSeconds`/`DcvWaitForIssuanceSeconds` knobs if you want to tune the Enroll-time budget.

### `EMS-956 "Invalid Request for this API"` from `GetDcv`

**Symptom**

The plugin's DCV machinery starts but the first `GetDcv` call returns this error. Plugin gracefully defers DCV to the next sync cycle (single warning log line, no exception thrown).

**Root cause**

CERTInext exposes the `domainVerification` slot in `TrackOrder` **before** the `GetDcv` endpoint will accept calls for that order — there's an internal gating window. The plugin's `IsDcvNotYetReady` predicate explicitly recognizes this and treats it as "DCV not ready yet, retry on the next sync".

**Mitigation**

No action needed. Plugin's sync-driven DCV retry handles this transparently — the order will be picked up on a subsequent sync cycle once the CA-side gate clears (observed window: seconds to a few hours, environment-dependent).

### Plugin fails to load with `Could not load type 'Keyfactor.AnyGateway.Extensions.IDomainValidatorFactory'`

**Symptom**

Gateway returns HTTP 500 on CA registration or first enrollment with the body `{"ErrorCode":"0x80131509"}`. Pod logs show `TypeLoadException` for `Keyfactor.AnyGateway.Extensions.IDomainValidatorFactory`.

**Root cause**

Older gateway image whose bundled `Keyfactor.AnyGateway.IAnyCAPlugin` assembly is v3.2 or earlier (the `IDomainValidatorFactory` interface is v3.3+). This was fully addressed by the issue [#7](../../issues/7) fix in v1.0 — both the constructor-signature surface AND the field-type surface are now safe to load on v3.2 hosts.

**Mitigation**

Upgrade to the v1.0 release or later. If you are on a build before that fix, the headline error means the plugin DLL was built against the v3.3 prerelease but is being loaded against a v3.2 host with no DCV path — older builds need to be rebuilt against the post-fix `main`.
