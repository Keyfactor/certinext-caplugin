## Overview

The CERTInext AnyCA Gateway REST plugin extends the certificate lifecycle capabilities of the CERTInext platform (by eMudhra) to Keyfactor Command via the Keyfactor AnyCA Gateway REST. The plugin represents a fully featured AnyCA REST plugin with the following capabilities:

* CA Synchronization:
    * Download all certificates issued through the CERTInext CA, either as a full inventory or incrementally since the last sync.
    * Expired certificates can optionally be excluded from synchronization using the `IgnoreExpired` configuration flag (V2 only; the V1 API does not currently apply it).
* Certificate Enrollment for profiles configured in CERTInext:
    * New certificate enrollment (new keys and certificate).
    * Certificate renewal — on the V1 API, submits a new `GenerateOrderSSL` order when the prior certificate is within the configured renewal window (CERTInext has no dedicated renewal endpoint; the renewal-window check governs how Command tracks old→new, not which API is called). On the V2 API every renewal places a new order.
    * Certificate reissuance (new keys with the same or updated subject/SANs) when outside the renewal window or no prior certificate is found.
    * Synchronous certificate pickup — a fast-issuing order (DV, or already-approved) can return the certificate in the same enrollment call instead of always waiting for the next sync, via `PickupRetries`/`PickupDelay`.
    * DNS-01 domain control validation (DCV) — the plugin publishes the validation TXT record through a DNS provider plugin deployed on the gateway and asks CERTInext to verify it, during enrollment and during synchronization (`DcvEnabled`, on by default).
* Certificate Revocation:
    * Request revocation of a previously issued certificate using RFC 5280 reason codes, mapped to the reasons CERTInext accepts (see [Revocation Reason Codes](#revocation-reason-codes)).
* Supported authentication modes for calls to the CERTInext API:
    * V1 API (default): AccessKey — SHA-256 signed requests.
    * V2 API: OAuth2 `client_credentials` bearer token.
* Two CERTInext API generations, selected per connector with `UseV2Api`: the V1 API (default) and the order-centric V2 REST API, which adds Private PKI products. See [V2 API](#v2-api) and [Migrating from V1 to V2](#migrating-from-v1-to-v2).

## Requirements

* Keyfactor Command 25.5 or later
* AnyCA Gateway REST framework version 26.2.0 or later
* A DNS provider plugin deployed on the AnyCA Gateway if the connector validates domains with DNS-01 DCV (the default; see `DcvEnabled`)
* A CERTInext account with API access enabled and at least one certificate product configured
* Network connectivity from the AnyCA Gateway host to the CERTInext API endpoint for your region (see table below)
* The AnyCA Gateway host must trust the TLS certificate presented by the CERTInext API endpoint

### Compatibility and Authentication Matrix

The connector runs in one of two modes, chosen with `UseV2Api`. The mode decides the `ApiUrl` shape, how the plugin authenticates, and which credential fields are used.

| | V1 (default) | V2 (`UseV2Api` = `true`) |
|---|---|---|
| AnyCA Gateway REST / `IAnyCAPlugin` | 26.2.0 or later / 3.3.0 | 26.2.0 or later / 3.3.0 |
| Authentication | AccessKey (SHA-256 signed request body) | OAuth2 `client_credentials` bearer token |
| `ApiUrl` shape | `https://<host>/emSignHub-API/` | Bare host, for example `https://us-api.certinext.io` |
| Token URL | None | Derived: `{ApiUrl}/oauth/token` |
| `AccountNumber` | Required | Ignored |
| `ApiKey` | Required | Ignored |
| `AuthMode` | Optional; leave as `AccessKey` (legacy field) | Ignored |
| `OAuthClientId` / `OAuthClientSecret` | Not used (legacy only) | Required |
| `OAuthTokenUrl` | Not used (legacy only) | Ignored |
| `SignerPlace` | Set it; sent on every order | Required at save |
| Products | SSL/TLS (DV, OV, EV) | SSL/TLS (DV, OV, EV) and Private PKI |
| DCV | On by default; needs a DNS provider plugin | On by default; needs a DNS provider plugin |

### CERTInext Environments

CERTInext operates three separate environments. Use the sandbox environment for initial integration testing. Switch to a production environment only after all functionality has been verified.

| Environment | Portal Sign-in URL | V1 API Base URL | V2 API Base URL |
|---|---|---|---|
| Sandbox | https://sandbox-us.certinext.io/ | `https://sandbox-us-api.certinext.io/emSignHub-API/` | `https://sandbox-us-api.certinext.io` |
| Production — India (Global) | https://in.certinext.io/ | `https://api.certinext.io/emSignHub-API/` | `https://api.certinext.io` |
| Production — US | https://us.certinext.io/ | `https://us-api.certinext.io/emSignHub-API/` | `https://us-api.certinext.io` |

> Note: Product codes differ between sandbox and production. Always confirm product codes from the GetProductDetails API call against the environment you are targeting before going live.

## CERTInext API Setup

The credentials you create in the CERTInext portal depend on the API generation the connector uses.

| Mode | API | Where credentials go | Fields required |
|---|---|---|---|
| AccessKey | V1 (default) | `authKey` in the `meta` block of every request body. There is no `Authorization` header. | `AccountNumber`, `ApiKey` |
| OAuth2 client credentials | V2 (`UseV2Api` = `true`) | `Authorization: Bearer` header. The token comes from `{ApiUrl}/oauth/token`. | `OAuthClientId`, `OAuthClientSecret`, `SignerPlace` |

> Note: V1 OAuth is not supported. The live V1 API ignores a bearer token and answers HTTP 401 (`clientAccessKey is not active`) whether or not one is sent. The `AuthMode` and `OAuthTokenUrl` fields remain only so connectors saved with them keep loading. Leave `AuthMode` as `AccessKey`.

### AccessKey (SHA-256 signed requests) — V1

The V1 API signs every request. Each call includes a computed `authKey` field in the `meta` block of the request body. The access key itself is never transmitted — only the derived hash is sent.

The `authKey` is a plain SHA-256 digest (not an HMAC), computed as:

```
authKey = SHA256(accessKey + ts + txn)
```

Where `ts` is the ISO 8601 timestamp of the request and `txn` is the unique transaction ID generated per request; both are sent in the same `meta` block. The gateway performs this computation automatically on every outbound API call.

**Steps to generate an Access Key:**

1. Log in to the CERTInext portal for your environment (e.g. https://in.certinext.io).
2. Navigate to **Integrations → APIs**.
3. Click **+ Create API Credentials** at the top right of the page.
4. In the dialog, fill in the following fields:
    - **API Type**: Select `REST`.
    - **Description**: Enter a descriptive label, such as `keyfactor-gateway`.
    - **User**: Select the CERTInext user account this credential will be associated with.
    - **Auth Type**: Select `Access Key`.
5. Click **Generate**.
6. In the confirmation dialog, copy the displayed Access Key immediately. This is the only time the key is shown in plaintext.
7. Confirm that the new credential row appears in the APIs list with status **Active** before proceeding.

Enter the copied value in the `ApiKey` field of the CA connector configuration. The field is masked in the Keyfactor Command UI and stored in Command's encrypted gateway configuration.

### OAuth2 client credentials — V2

The V2 API authenticates with an OAuth2 `client_credentials` bearer token. Create the credential with **Auth Type** `OAuth` and enter the client ID and secret in `OAuthClientId` and `OAuthClientSecret`. See [V2 OAuth2 Setup](#v2-oauth2-setup) for the steps.

> Note: Credentials are stored in Keyfactor Command's encrypted gateway configuration and are never written to disk by the plugin.

## Gateway Registration

Before enrolling certificates, the Keyfactor Command server must trust the CERTInext issuing CA chain.

1. Log in to the CERTInext portal and download the root CA certificate and any intermediate CA certificates in the chain as PEM or DER files.
2. On the Keyfactor Command server, import those certificates into the appropriate Windows certificate store — **Trusted Root Certification Authorities** for the root CA and **Intermediate Certification Authorities** for any subordinate CAs.
3. In the Keyfactor Command Management Portal, navigate to **CA Connectors** and add a new CA using the **CERTInext AnyCA REST Gateway Plugin**.
4. Complete the CA connector configuration fields described in the next section, then save and test the connection. The gateway performs a live connectivity test during validation: the V1 `ValidateCredentials` endpoint, or `GET /api/certinext/v2/auth/me` when `UseV2Api` is `true`.

### Change of issuing CA (eMudhra exit from public TLS)

eMudhra, CERTInext's parent company, is withdrawing from the public SSL/TLS certificate business, and browser root programs are phasing out the emSign roots that CERTInext public TLS certificates have chained to. Public TLS certificates ordered through CERTInext will be issued under a different CA. Which CA depends on your service: InCommon members are moving to [SSL.com](https://incommon.org/about/news/incommon-certificate-service-update), and eMudhra offers [Sectigo](https://emudhra.com/en/post/certificate-security-incident) certificates to its customers. Confirm the new chain for your account with CERTInext.

Dates published by eMudhra for the emSign G1 root (check the [eMudhra statement](https://emudhra.com/en/post/certificate-security-incident) for changes):

| Root program | Effect |
|---|---|
| Chrome, Mozilla Firefox | Certificates logged after November 16, 2026 are not trusted. Certificates issued before then stay trusted until they expire. |
| Apple | The root is removed on November 30, 2026. Every certificate issued under it stops being trusted on Apple platforms, including existing ones. |
| Microsoft | No date announced. |

The plugin does not need to change. It stores only the issued certificate and never reads or checks the issuer. Repeat the trust and registration steps above with the new chain:

1. Get the new root and intermediate certificates for your account from CERTInext.
2. Import them on the Keyfactor Command server and the AnyCA Gateway REST host, and on any orchestrator or client that builds or validates certificate chains. Use **Trusted Root Certification Authorities** for the root and **Intermediate Certification Authorities** for subordinates.
3. Replace the CA certificate in this CA's **Gateway Registration** with the new issuing chain.
4. Replace certificates that chain to the emSign G1 root before November 30, 2026 if Apple clients rely on them. Keep the emSign certificates in your trust stores until you have replaced every certificate issued under them.

Also confirm with CERTInext whether your account's product codes change. If they do, update the `ProductCode` mapping on each template.

## CA Configuration

The following fields are presented in the Keyfactor Command Management Portal when creating or editing the CERTInext CA connector. The **Applies to** column shows which API generation uses the field: **V1**, **V2**, or **Both**.

### Save-Time Validation

When the connector is saved (and `Enabled` is `true`), the plugin checks only the fields below. Every other field marked **Required** in the tables is needed by CERTInext for a successful order, but the connector saves without it — enrollment then fails, or the order is parked pending, until it is set.

| Mode | Fields checked at save |
|---|---|
| All | `ApiUrl` must be present and use `https` (`http` is allowed only for a loopback host: `localhost`, `127.0.0.1`, `::1`). |
| V1 AccessKey | `AccountNumber`, `ApiKey` |
| V2 | `OAuthClientId`, `OAuthClientSecret`, `SignerPlace` |

### Connection

| Field | Applies to | Required | Description |
|---|---|---|---|
| `ApiUrl` | Both | Required | CERTInext API base URL. The shape depends on `UseV2Api`; see [ApiUrl by mode](#apiurl-by-mode). |
| `UseV2Api` | Both | Optional | Route all operations through the V2 REST API. Requires `OAuthClientId`, `OAuthClientSecret`, and `SignerPlace`. Default: `false`. |
| `AccountNumber` | V1 | Required | CERTInext account number (numeric string), sent in the `meta` block of every request. Example: `1234567890`. |
| `ApiKey` | V1 | Required | Access Key from **Integrations → APIs**. Masked in the UI. |
| `AuthMode` | V1 | Optional | Legacy. Default: `AccessKey`. Leave as is; V1 does not honor OAuth. Ignored on V2. |
| `OAuthClientId` | V2 | Required | OAuth client ID. The key must be generated in OAuth mode. |
| `OAuthClientSecret` | V2 | Required | OAuth client secret. Masked in the UI. |
| `OAuthTokenUrl` | V1 (legacy) | Optional | Legacy / unsupported: V1 does not honor OAuth tokens. Ignored on V2, which derives `{ApiUrl}/oauth/token`. |
| `Enabled` | Both | Optional | Set to `false` to create the connector record before credentials exist; skips validation and the live connectivity test. Default: `true`. |

#### ApiUrl by Mode

| Mode | Value | Examples |
|---|---|---|
| V1 (default) | Host plus the `/emSignHub-API/` path | Sandbox: `https://sandbox-us-api.certinext.io/emSignHub-API/`<br>Production US: `https://us-api.certinext.io/emSignHub-API/`<br>Production India: `https://api.certinext.io/emSignHub-API/` |
| V2 (`UseV2Api` = `true`) | Bare host, no path suffix | `https://sandbox-us-api.certinext.io` |

- The two APIs are hosted differently, so change `ApiUrl` whenever you toggle `UseV2Api`.
- A trailing slash is accepted in either mode.
- The URL must use `https`: the API key (V1) or OAuth client secret (V2) is sent to it on every request. `http` is rejected except for a loopback host, for local test servers only.

### Requestor and Signer

| Field | Applies to | Required | Description |
|---|---|---|---|
| `RequestorName` | Both | Required | Default name of the person or service submitting orders. Example: `PKI Automation`. |
| `RequestorEmail` | Both | Required | Default requestor email. Use a monitored inbox registered in your CERTInext account. |
| `RequestorIsdCode` | Both | Optional | Dialing code for the requestor phone, digits only, no `+`. Default: `1`. |
| `RequestorMobileNumber` | Both | Optional | Requestor mobile number, digits only, no country code. |
| `RequestorDesignation` | Both | Optional | Job title of the requestor. Sent as `requestorInformation.requestorDesignation` (V1) and `requestor.designation` (V2). Omitted when blank. |
| `TechnicalContactName`<br>`TechnicalContactEmail`<br>`TechnicalContactIsdCode`<br>`TechnicalContactMobileNumber` | Both | Optional | Technical point of contact on every SSL order. Each defaults to the matching `Requestor*` field. On V1 the name is sent as `pocFirstName` and `pocLastName`, split on the first whitespace (a single word goes in both). If no name or no email resolves, V1 omits the whole block and logs a warning, because CERTInext requires both inside it. |
| `SignerPlace` | Both | Required | City of the person accepting the subscriber agreement. Required at save on V2; a template `SignerPlace` overrides it on both. On V1, if neither is set, the plugin sends `Gateway` and logs a warning. Example: `Austin`. |
| `SignerIp` | V1 | Required on V1 | Public IP of the host accepting the subscriber agreement. Not sent on V2, whose agreement block has no IP field. See the bullets below. Example: `203.0.113.10`. |

- **`SignerIp` blank:** on V1, when neither a template `SignerIp` nor this field is set, the plugin sends `127.0.0.1` and logs a warning, which misstates the audit record CERTInext keeps. Set it to the gateway host's outbound IP. A V1 value that is not an IP address is still sent unchanged, with a warning. On V2 the setting is ignored: the V2 agreement block has no signer IP field (the CA records the signer's IP itself), so it is never sent and never warned about.
- **Signer values per order:** the agreement signer is the template `SignerName`, `SignerPlace`, and `SignerIp` parameters first, then the connector's `RequestorName`, `SignerPlace`, and `SignerIp`, then the placeholders `Keyfactor Gateway`, `Gateway`, and `127.0.0.1` (each placeholder logs a warning on V1). `SignerIp` is V1 only. Blank values fall through. This applies to new orders and renewals on both V1 and Vt.
- **Where to find values:** the account number is under your name or avatar → **Account Settings** or **My Profile**. Use a monitored team inbox for `RequestorEmail`.

### Order Defaults

| Field | Applies to | Required | Description |
|---|---|---|---|
| `GroupNumber` | Both | Optional | CERTInext group (delegation) number, from **Delegation → Groups**. Routes orders to the right group. See the bullets below. |
| `OrganizationNumber` | Both | Optional | Pre-vetted organization number, from **Organizations → Pre-vetted Organizations**. Required for OV/EV on V2: enrollment fails before any CA call if blank. |
| `DefaultProductCode` | Both | Optional | Numeric product code fallback. See [DefaultProductCode](#defaultproductcode). |
| `AccountingModel` | V1 | Optional | Billing model: `2` = credit-based (most accounts), `1` = cash. Default: `2`. |
| `EmailNotifications` | Both | Optional | Lifecycle emails to the requestor. See [EmailNotifications values](#emailnotifications-values). Default: `0`. |
| `SubscriptionValidityYears` | Both | Optional | Default validity in years: `1`, `2`, or `3`. Used when the template sets no `ValidityYears` (and, on V1, no `ValidityDays`); a template term overrides it. Default: `1`. |
| `SubscriptionAutoRenew` | Both | Optional | `0` = CERTInext does not auto-renew (recommended; Command drives renewal), `1` = enabled. Default: `0`. |
| `SubscriptionRenewCriteriaDays` | Both | Optional | Days before expiry at which CERTInext auto-renews. Honored only when `SubscriptionAutoRenew` is `1`. Default: `30`. |
| `AutoSecureWww` | Both | Optional | `1` adds the `www.` variant of the primary domain as an extra SAN, which must also pass domain validation. Sent as `orderDetails.autoSecureWWW` on every V1 SSL order (new and renewal). Default: `0`. |
| `SubmitNonDnsSans` | V1 | Optional | `true` submits non-DNS SANs (IP, email, URI) to CERTInext, which cannot validate them, so the order will not issue until they are removed. `false` submits DNS names only. Default: `true`. |

- **`GroupNumber`:** it is sent in `productDetails.groupNumber` on `GetProductDetails` and in `orderDetails.groupNumber` on every V1 SSL order (new and renewal). When blank, CERTInext uses the account's default group. On V2 it is sent as `groupNumber` on order create and as a query parameter on the catalog and orders-report calls. Some sandbox accounts return an empty product list unless it is set.
- **`GroupNumber` is not `AccountNumber`:** `AccountNumber` is your top-level account identifier. Each CERTInext group (cost center or department) has its own `groupNumber`, which is separate from any organization number on the Organizations page.
- **`OrganizationNumber`:** when set, V1 orders carry `organizationDetails.preVetting="1"` and this number, so CERTInext skips its manual vetting queue. Without it, orders can sit in `Pending System RA` for tens of hours. V2 DV orders never send an organization block.
- **Non-DNS SANs on V2:** `SubmitNonDnsSans` is not consulted. See [Migrating from V1 to V2](#step-2--update-the-ca-connector).

#### DefaultProductCode

Calling `GetProductDetails` against your account lists the codes available to you (see [Product Codes](#product-codes)).

| Mode | When it applies |
|---|---|
| V1 | Renewals only, and only when the template supplies no `ProductCode`/`ProfileId`. CERTInext's `TrackOrder` does not return the prior order's product code. No effect on new enrollments. |
| V2 | Not used. V2 orders send `X-Product-Code` only for an explicit template `ProductCode`; otherwise CERTInext resolves the product. |

- If neither the template nor this field supplies a code on a V1 renewal, the renewal goes out with an empty product code.

#### EmailNotifications Values

| Value | V1 | V2 |
|---|---|---|
| `1` | Full notification set (sent as `1`) | Sent as `all` |
| `0` | Silent (sent as `0`) | Silent: sent as `consent-only`, the quietest value the V2 spec allows (its enum is `consent-only` or `all`) |
| Blank | Silent (sent as `0`) | Omitted, so the CA default (`all`, not silent) applies |
| Anything else | Sent unchanged, not validated | Enrollment fails before any CA call |

### Synchronization and Pickup

| Field | Applies to | Required | Description |
|---|---|---|---|
| `IgnoreExpired` | V2 | Optional | Skip expired certificates during sync. The V1 API does not currently apply it. Default: `false`. |
| `PageSize` | Both | Optional | Orders fetched per page during sync. Must be 1 or higher; reduce it if sync requests time out. Default: `100`. Maximum: `500` on V1, `100` on V2. |
| `V2SyncLookbackHours` | V2 | Optional | Extra hours subtracted from the last-sync time on incremental sync, so a slow order is not missed. Default: `72`. |
| `SyncRecentOrderGraceSeconds` | Both | Optional | A sync (full or incremental) skips pending or issued orders created less than this many seconds ago (plus a 5-second clock margin); the next incremental sync imports them. This keeps a sync that runs during an in-flight enrollment from causing that enrollment to fail with a duplicate key. `0` disables it. Default: `120`. |
| `PickupRetries` | Both | Optional | Times `Enroll` polls CERTInext for the certificate after a successful order. `0` disables the wait. Default: `5`. |
| `PickupDelay` | Both | Optional | Seconds between pickup polls. Default: `10`. |

- **`IgnoreExpired` on V1:** the V1 sync maps no certificate expiry date, so the filter never matches and expired certificates are still imported. The V2 sync applies it.
- **`PageSize` limits:** values above the maximum are clamped. On V2, a value of 0 or less falls back to 100. On V1, a value below 1 is not corrected, so keep it at 1 or higher.
- **`PickupRetries` and `PickupDelay`:** OV/EV orders validate asynchronously (minutes to hours) and typically exhaust the wait regardless of these values. Pickup applies to V1 and V2.

#### Pickup Limits

| Setting | Minimum | Maximum | Default | Out-of-range behavior |
|---|---|---|---|---|
| `PickupRetries` | 0 (disabled) | 30 | 5 | Negative becomes 0; above 30 becomes 30 |
| `PickupDelay` (seconds) | 1 | 60 | 10 | Zero or negative becomes 10; above 60 becomes 60 |
| Total wait | — | 75 s | ~55 s | The retry count is reduced to fit the cap |

> **Pickup timing detail:** after a successful order placement, the plugin waits a fixed 5-second initial delay before the first poll, then polls CERTInext every `PickupDelay` seconds up to `PickupRetries` times. Each poll calls `GetCertificate` to check whether the certificate has been issued. The total time budget is **5 s + (`PickupRetries` × `PickupDelay`) + about 1 s API round trip per poll**. With the defaults this is 5 + (5 × 10) = **~55 s plus round trips**.
>
> **Tuning for faster pickup:** if CERTInext typically issues certificates within a few seconds of order placement (as is typical for DV and auto-approved orders), lower `PickupDelay` and raise `PickupRetries` to compensate. This polls more often without changing the total budget. Command's own enrollment call into the gateway is bounded at about 100 s, and order submission and each poll's round trip also use that budget, so keep the total well under the 75 s ceiling.
>
> | Configuration | PickupRetries | PickupDelay | Total budget | Poll cadence |
> |---------------|:---:|:---:|---|---|
> | Default | `5` | `10` | ~55 s | Every 10 s |
> | Faster polling | `10` | `5` | ~55 s | Every 5 s |
> | Aggressive | `30` | `2` | ~65 s | Every 2 s |
> | Minimal wait | `0` | — | 0 s | No polling; defers to sync |
>
> The 5-second initial delay is not configurable, and the 75-second ceiling applies regardless of configuration. It sits inside Command's roughly 100-second enrollment-call timeout, which leaves headroom for order submission and per-poll round trips. When the DCV flow ran for the order inside the same `Enroll` call, the pickup poll is skipped, because the DCV flow already waited for issuance.

### Domain Control Validation (DCV)

DCV needs a DNS provider plugin (for example `azure-azuredns-dnsplugin`) deployed on the gateway. Without one, orders that need validation stay pending and the plugin logs why.

| Field | Applies to | Required | Description |
|---|---|---|---|
| `DcvEnabled` | Both | Optional | Perform DNS-based DCV during enrollment and synchronization. Set to `false` to validate domains another way. Default: `true`. |
| `DcvTxtRecordTemplate` | Both | Optional | TXT record hostname format; `{0}` is the domain being validated. Default: `_emsign-validation.{0}`. |
| `DcvPropagationDelaySeconds` | Both | Optional | Seconds to wait after publishing the TXT record before asking CERTInext to verify. Default: `30`. |
| `DcvTimeoutMinutes` | Both | Optional | Maximum minutes for the whole DCV flow before the order is left pending. Default: `10`. |
| `DcvWaitForChallengeSeconds` | V1 | Optional | How long `Enroll()` waits for CERTInext to expose the DCV challenge. `0` disables the wait. Default: `60`. |
| `DcvWaitForIssuanceSeconds` | V1 | Optional | How long `Enroll()` waits for issuance after DCV verifies. `0` disables the wait. Default: `60`. |
| `DcvSyncMaxOrderAgeHours` | Both | Optional | During sync, only pending DV orders younger than this are driven through DCV. `0` disables the filter. Default: `24`. |
| `DcvSyncMaxPerPass` | Both | Optional | Maximum pending DV orders driven through DCV per sync pass. `0` disables the cap. Default: `50`. |

- **Environment variables:** `DcvTimeoutMinutes`, `DcvWaitForChallengeSeconds`, and `DcvWaitForIssuanceSeconds` can also be set with `CERTINEXT_DCV_TIMEOUT_MINUTES`, `CERTINEXT_DCV_WAIT_FOR_CHALLENGE_SECONDS`, and `CERTINEXT_DCV_WAIT_FOR_ISSUANCE_SECONDS`. The environment variable wins when both are set.
- **Propagation delay:** on V1, DCV driven during synchronization uses its own fixed 3-second delay. V2 uses `DcvPropagationDelaySeconds` everywhere.
- **Sync limits:** `DcvSyncMaxOrderAgeHours` and `DcvSyncMaxPerPass` keep a large backlog of old or abandoned pending orders from slowing every sync pass.

### Diagnostics

| Field | Applies to | Required | Description |
|---|---|---|---|
| `LogSensitiveRequestData` | Both | Optional | Temporary diagnostic switch. When `true`, requestor personal data and full CA request/response payloads are written to the gateway logs. Default: `false`. |

- **Use it briefly:** turn it on only while verifying a new deployment (to confirm exactly what was sent to the CA), then turn it off.
- **When `false`:** personal-data fields are redacted. Emails are masked but keep their domain (for example `j***@example.com`), and the enrollment log line omits the requester name.
- **Email SANs:** `rfc822Name` values in log lines are masked the same way. DNS, IP, and URI SANs are always logged in full.
- **Credentials:** API keys, OAuth secrets, and tokens are always redacted, whatever this setting is.

## Certificate Template Creation Step

A Keyfactor Command certificate template maps an enrollment request to a specific CERTInext product. Create one template per CERTInext product that you want to make available to requesters.

The AnyCA Gateway REST portal also needs one certificate profile per product before Command templates can be created against it. Create the profiles by hand in the gateway portal, or with the helper script this repository ships (`make register-profiles`; set `DRY_RUN=1` to preview). See [scripts/register/README.md](https://github.com/Keyfactor/certinext-caplugin/blob/main/scripts/register/README.md) for authentication and options.

In the Keyfactor Command Management Portal, navigate to **Certificate Templates** and create a new template associated with the CERTInext CA connector. The following enrollment parameters are available:

| Parameter | Required / Optional | Type | Description | Example / Default |
|---|---|---|---|---|
| `ProductCode` | Optional | String | Overrides the numeric CERTInext product code. Get the right code from `GetProductDetails` for your account. On V2 it is an override sent as `X-Product-Code`; leave it blank and CERTInext resolves the product. | DV SSL: `842` (sandbox) or `838` (production) |
| `ProfileId` | Deprecated | String | Legacy alias for `ProductCode`. Accepted for backward compatibility — if `ProductCode` is not set, `ProfileId` is used in its place. New templates should use `ProductCode`. | `838` |
| `ValidityYears` | Optional | Number | Subscription term in years: `1`, `2`, or `3`. Default: `1`. CERTInext certificates are issued within a subscription term at up to 390 days per certificate, with free renewals within the term. | `1` |
| `ValidityDays` | Optional | Number | V1 only; ignored on V2. Requested validity in days, converted to whole subscription years and rounded up (365 days = 1 year), because the order API takes years. Default: `365`. See the note below the table. | `365` |
| `AutoApprove` | Optional | Boolean | **Currently has no effect** — reserved for future use. The plugin does not call any approval endpoint against CERTInext regardless of this setting. | `false` |
| `RequesterName` | Optional | String | Overrides the connector `RequestorName` for this template when non-blank. Never derived from the certificate subject. | `Keyfactor Automation` |
| `RequesterEmail` | Optional | String | Overrides the connector `RequestorEmail` for this template when non-blank. Never derived from the certificate subject. | `pki-admin@example.com` |
| `RenewalWindowDays` | Optional | Number | V1 only. Number of days before certificate expiration within which a renewal is attempted instead of a reissue. V2 places a new order for every renewal and reissue. Default: `90`. | `90` |
| `KeyType` | Optional | String | Informational. The CSR decides the key algorithm. CERTInext accepts only RSA 2048/3072/4096 and ECC P-256/P-384. | `RSA2048`, `RSA3072`, `RSA4096`, `EC256`, `EC384` |
| `DomainName` | Optional | String | V2 only: primary domain name for SSL/TLS orders (for Private PKI, the primary hostname). If omitted, the plugin uses the CSR subject `CN`. V1 always uses the CSR subject `CN`. | `example.com` |
| `SignerName` | Optional | String | Per-template override for the subscriber agreement signer name. When omitted, defaults to the connector-level `RequestorName` (V2: the requestor name). If no name resolves, V1 sends `Keyfactor Gateway` and logs a warning. | `Jane Smith` |
| `SignerPlace` | Optional | String | Per-template override for the subscriber agreement signer location. When omitted, defaults to the connector-level `SignerPlace`. If neither is set, V1 sends `Gateway` and logs a warning. | `Austin` |
| `SignerIp` | Optional (V1 only) | String | Per-template override for the subscriber agreement signer IP address. Ignored on V2. When omitted, defaults to the connector-level `SignerIp`. If neither is set, V1 sends `127.0.0.1` and logs a warning; a V1 value that is not an IP address is sent unchanged, with a warning. | `203.0.113.10` |

- **Subscription term (V1):** the order's term is the larger of `ValidityYears` and `ValidityDays` rounded up to whole years (365 days = 1 year). Each field counts only when it is set, and a field left at its default (1 year) never overrides the other, so a template saved with only `ValidityDays` keeps its term. Because the larger value wins, a stale larger `ValidityDays` cannot be shortened with `ValidityYears` alone; set `ValidityDays` back to `365`. V2 uses only `ValidityYears`.
- **Key types:** larger RSA, ECC P-521, and the Ed25519/Ed448 curves are rejected by the CA (`Invalid key size`).

When `ProductCode` is omitted:

- **V1:** the plugin uses the built-in default code for the selected product name (see [Product Codes](#product-codes)).
- **V2:** no code is sent and CERTInext resolves the product itself (see [V2 Product Code Resolution](#v2-product-code-resolution)). Set `ProductCode` to override that choice.
- **Sandbox or non-standard codes (V1):** set `ProductCode` explicitly.

The V2-only template parameters `ProductFamily` and `ProductVariant` are described under [V2 Certificate Template Fields](#v2-certificate-template-fields).

## Product Codes

CERTInext uses numeric product codes to identify certificate types. **Product codes are provisioned per account by eMudhra** — the codes available to your account are determined when your account is set up. The codes in the tables below are example values for the sandbox and production environments; your account may have different codes.

To retrieve the exact codes available to your account, call the `GetProductDetails` endpoint:
- If you have a `GroupNumber` configured, include it in the request `productDetails` block — some accounts require this to return a non-empty list.
- Use the `make get-product-details-group` Makefile target to retrieve products from the sandbox with `groupNumber` included.

> Note: Product codes differ between the sandbox and production environments. Always verify the correct code before switching environments.

> Note: Product codes are per-account. If you receive "Invalid Product Code" (EMS-1162) when placing an order, your account does not have that product provisioned. Contact your eMudhra account representative to request provisioning of the product codes you need.

### SSL/TLS

The product codes in this table are for:
- the US sandbox environment (`sandbox-us-api.certinext.io`)
- the Production India environment (`api.certinext.io`)

**Your account may still have different codes.** Always call `GetProductDetails` against your target environment before going live.

| Product | Sandbox Code | Production Code | CERTInext-side requirements (beyond `domainName`, `csr`, `requestorInformation`, `subscriptionDetails`, `agreementDetails`) |
|---|---|---|---|
| DV (Domain Validated) | `842` | `838` | None. `domainName` is derived from the CSR CN if omitted on the template. |
| DV Wildcard | `843` | `839` | CSR CN must use wildcard format (e.g. `*.example.com`). `domainName` in the order must also use the wildcard format. |
| DV UCC (Multi-domain) | `844` | `840` | `certificateInformation.additionalDomains` — array of additional SAN values beyond the primary `domainName`. |
| DV Wildcard UCC (Multi-domain Wildcard) | `845` | `841` | Combines wildcard and multi-domain requirements. CSR CN and `domainName` must use wildcard format; `certificateInformation.additionalDomains` required. |
| OV (Organization Validated) | `846` | `842` | `organizationDetails.organizationNumber` (your CERTInext org ID); `certificateInformation.locality`, `postalCode`, and full organization address fields (`streetAddress`, `city`, `state`, `country`). |
| OV Wildcard | `847` | `843` | Same as OV. CSR CN and `domainName` must use wildcard format. |
| OV UCC (Multi-domain) | `848` | `844` | Same as OV plus `certificateInformation.additionalDomains`. |
| OV Wildcard UCC (Multi-domain Wildcard) | `849` | `845` | Combines OV, wildcard, and multi-domain requirements. Same as OV plus wildcard CN/domainName and `certificateInformation.additionalDomains`. |
| EV (Extended Validation) | `850` | `846` | All OV fields plus: `contractSignerInfo` object (`name`, `email`, `isdCode`, `mobileNumber`, `designation`, `employeeID`); `certificateApproverInfo` object (same fields); `certificateInformation.companyRegistrationNumber`; `streetAddress2` must be non-empty. |
| EV UCC (Multi-domain EV) | `851` | `847` | Same as EV plus `certificateInformation.additionalDomains`. |

> Note: The plugin supplies `domainName` and `additionalDomains` (from the CSR and its SANs), but none of the organization, address, or EV fields in the table. For OV and EV it sends only `organizationDetails.preVetting` and `organizationNumber` (V1), so these products need a pre-vetted organization: set `OrganizationNumber` on the connector.

> Note: SSL/TLS codes are offset by 4 between the US sandbox and Production India in the tables above — treat that as a coincidence, not a guarantee. eMudhra controls the per-account mapping and may use different numeric codes for any new account. Always confirm via `GetProductDetails`.

> Note: The CERTInext portal may display additional short-validity products (e.g. **DV SSL Certificate 1 Month**, **DV SSL Certificate Wildcard 1 Month**) that do not appear in the `GetProductDetails` API response and have no published product code. These products are not accessible via the API and are therefore **not supported by this plugin**. Contact eMudhra to determine whether API ordering is available for these products on your account.

### Private PKI

| Product | Sandbox Code | Production Code | Availability |
|---|---|---|---|
| emSign Intranet SSL 1 year | `149` | `100` | Requires special provisioning by eMudhra. Not orderable on standard accounts. |
| IGTF Host 1 year | n/a | `104` | Requires special provisioning by eMudhra. Not orderable on standard accounts. |

> Note: Private PKI products need a separate entitlement. On an account without it, placing an order returns EMS-1162 (product not provisioned). Contact eMudhra to have these products enabled. Whether the sandbox code `149` ("Sandbox emSign Intranet SSL 1 Year", `productTypeID` `39`) is available depends on the account. Check your own account's catalog.

### S/MIME and Document Signing

**Not supported by this plugin.** `GetProductIds` advertises SSL/TLS products only, and V2 `ProductFamily=signature` enrollment fails before any order is placed. The codes below are listed for reference only, because they can appear in your account's `GetProductDetails` response.

CERTInext uses the same numeric codes for these products on the US sandbox and Production India in the snapshots we have. **Treat that as an example, not a contract** — eMudhra assigns codes per account.

| Product | Sandbox / Production Code | Notes |
|---|---|---|
| S/MIME | `894` | Not supported. Needs a separate S/MIME entitlement. |
| Document Signer | `819`–`827` | Not supported. Needs a document signing entitlement. |

CERTInext's published references don't agree on which Document Signer code maps to which product. The V2 API spec lists:

| Code | Product (per V2 API spec) |
|---|---|
| `819` / `820` / `821` | Natural Person, 1 / 2 / 3 year |
| `822` / `823` / `824` | Legal Person, 1 / 2 / 3 year |
| `825` / `826` / `827` | Legal Entity, 1 / 2 / 3 year |


## Mechanics

### Authentication

Every CERTInext API call is an HTTP request with a JSON body. How it authenticates depends on the API generation:

| Mode | Where credentials go | Fields required |
|---|---|---|
| V1 AccessKey | `authKey` in the `meta` block of the POST body. No `Authorization` header. | `AccountNumber`, `ApiKey` |
| V2 OAuth2 | `Authorization: Bearer` header. Tokens are cached; see [V2 Token Caching](#v2-token-caching). | `OAuthClientId`, `OAuthClientSecret`, `SignerPlace` |

For V1, `authKey = SHA256(accessKey + ts + txn)`, where `ts` is the ISO 8601 request timestamp and `txn` is a random numeric transaction ID generated per request. It is a plain SHA-256 digest, not an HMAC. The `meta` block also carries the version and account number. The raw access key is never transmitted, and the computation happens automatically on every outbound call.

V1 OAuth (`AuthMode` = `OAuth`) is legacy and unsupported: the live V1 API ignores bearer tokens.

### HTTP Timeout and Retries

Every CERTInext API call (enroll, sync, revoke) uses a fixed 120-second request timeout, on both
V1 and V2. The V2 OAuth token request is the exception: it uses the HTTP client's default timeout. The
120 seconds is hardcoded and is not exposed as a connector setting or environment variable — it cannot be
changed without modifying the plugin. If a call doesn't return within 120 seconds, the plugin aborts it
and the operation fails.

- **Order placement and CSR submission are never auto-retried after a timeout or server error**,
  because CERTInext may have already created the order. If the CA did create it, the next
  synchronization imports it. Do not resubmit immediately; check the CERTInext
  portal first.
- **Other V1 calls** (status checks, downloads, revoke, reports) are retried up to 3 attempts on a
  5xx response or network failure. 4xx responses are not retried.
- **V1 rate limit:** when order placement returns CERTInext's rate-limit response (the generic
  `Inactive Account User.` error), the plugin retries it up to 5 attempts with exponential backoff
  and jitter. See the rate-limit entry in [overview.md](overview.md#troubleshooting).
- **V2 calls are never auto-retried.** The only repeated V2 call is the one-time revoke-reason
  fallback described under [V2 Revocation Reason Handling](#v2-revocation-reason-handling).

### Enrollment Decision Logic

**V1.** When the gateway calls `Enroll`, the plugin selects a path from the enrollment type and the age of the prior certificate:

1. **New or Reissue** (`EnrollmentType.New` / `Reissue`) — a new `GenerateOrderSSL` request is submitted.
2. **Renew or RenewOrReissue** — Command supplies the prior certificate's serial number (`PriorCertSN`). The plugin resolves the prior order from the Command database, then:
    - no serial number, or no prior order found (including a failed lookup): a new order is submitted as for a new enrollment;
    - the prior certificate's expiry is in the future and within `RenewalWindowDays` (default 90 days): a renewal order is submitted — CERTInext has no dedicated renewal endpoint, so this is also a new `GenerateOrderSSL` order; the prior order is looked up first and its details fill in anything the request doesn't supply;
    - the prior certificate is outside the window, or already expired: a new order is submitted.

The prior order is never revoked automatically. The `RenewalWindowDays` template parameter sets the renewal/reissue boundary per certificate template.

**V2.** All enrollment types (New, Reissue, Renew, RenewOrReissue) place a new V2 order; there is no renewal-window logic. See [V2 Order Lifecycle](#v2-order-lifecycle).

### Required Order Fields

The V1 `GenerateOrderSSL` API requires an `additionalInformation.remarks` field in every order request body. The gateway populates this field automatically with the text `"Issued via Keyfactor Command AnyCA REST Gateway."`. If you encounter error `EMS-918: Additional Information cannot be empty`, verify that the gateway version is current and that the field is being sent.

### Order Lifecycle and Pending Approval

CERTInext orders pass through several internal status stages before a certificate is issued. The plugin maps the V1 `certificateStatusId` values to Keyfactor statuses as follows:

| Keyfactor result | CERTInext status IDs | Behavior |
|---|---|---|
| Issued | `7`, `9`, `12`, `15`, `20`, `23` | Certificate returned immediately. Status `12` (expired) stays in inventory as issued rather than failing. |
| Pending | `1`, `2`, `4`, `6`, `16`, `17`, `24` | Enrollment returns pending. `Enroll()` first polls briefly (see `PickupRetries`/`PickupDelay`). |
| Revoked | `22` | Certificate marked revoked. |
| Failed | `3`, `5`, `8`, `13`, `14`, `18`, `19`, `21`, or any unrecognized ID | Enrollment returns a failed result. |

Orders that are still pending when `Enroll()` returns are picked up by a later synchronization.

### Synchronization

On V1, synchronization uses the `GetOrderReport` endpoint with paginated results (controlled by `PageSize`, default 100, max 500). Each page is fetched sequentially until all orders are retrieved; a full sync requests every order, and an incremental sync requests orders placed since the last sync date. The plugin maps each order's status to a Keyfactor certificate status and returns the result set to the gateway framework, which reconciles it against the Command inventory.

- The order report carries no certificate body, so the plugin refetches the certificate for issued and revoked orders.
- Rejected and cancelled orders are skipped.
- Pending orders are emitted as pending. When DCV is enabled and a DNS provider plugin is available, recently placed pending orders are first driven through DNS-01 validation, bounded by `DcvSyncMaxOrderAgeHours` and `DcvSyncMaxPerPass`.
- If more than 25% of the records processed so far have failed (after at least 50 records), the sync aborts and is retried on the next cycle.

Expired certificates are included in the V1 sync. `IgnoreExpired` has no effect on V1 today because the V1 sync never populates a certificate expiry date; it is applied on V2 only.

On V2, synchronization reads `/reports/orders` instead — see [V2 Order Lifecycle](#v2-order-lifecycle).

### Product Code Resolution

On V1, the numeric CERTInext product code is resolved in this order (V2 follows [V2 Product Code Resolution](#v2-product-code-resolution)):

1. `ProductCode` template parameter (explicit override — use for sandbox or non-standard codes).
2. `ProfileId` template parameter (deprecated alias, accepted for backward compatibility).
3. Default production code looked up from the selected product name (e.g. **DV SSL** → `838`).

If none of these yield a code, enrollment fails with a validation error.

## V2 API

The plugin includes an opt-in CERTInext V2 REST API code path that uses OAuth2 `client_credentials` authentication and an order-centric resource model. V2 is disabled by default; V1 remains the active path unless `UseV2Api` is explicitly set to `true`. When enabled, V2 is fully self-contained: Ping, Enroll, GetSingleRecord, Revoke, and Synchronize all route through the V2 API, and V1 credentials (`ApiKey`, `AccountNumber`, `AuthMode`) are not required. Known limitations are listed under [Known Gaps](#known-gaps).

### V2 CA Connector Fields

V2 mode reuses the connector's `ApiUrl`, `OAuthClientId`, and `OAuthClientSecret` fields (see [Connection](#connection)) rather than separate V2-only credentials. `ApiUrl` becomes the V2 host, and the client ID and secret authenticate against it regardless of `AuthMode`. Two fields are specific to V2:

| Field | Required | Description |
|---|---|---|
| `UseV2Api` | Optional | Enables the V2 code path for connection tests, enrollment, revocation, status checks, and synchronization. Default: `false`. |
| `V2SyncLookbackHours` | Optional | Hours subtracted from the last-sync time on incremental sync. Default: `72`. |
| `V2InlineCsr` | Optional | SSL/TLS only. `true` sends the CSR inline in the create call (a single `POST /ssl-certificates`) instead of creating the order and then submitting the CSR. It is about 4-5 seconds faster, but the create call can hold about 20 seconds until issuance, and a create that times out or returns a 5xx can leave an order that issues and is imported by the next sync rather than cancelled. Private PKI always uses two calls. Default: `false`. |

- **Why a lookback:** the API's `from`/`to` filter may bracket either the order-placement date or the issuance date. The window keeps an order created before the last sync but issued afterward (for example a slow DCV order) from being missed.

#### V2 OAuth2 Setup

1. Log in to the CERTInext portal for your environment.
2. Navigate to **Integrations → APIs**.
3. Click **+ Create API Credentials**, set **API Type** to `REST`, and select the **OAuth** auth type (not `Access Key`). The V2 spec requires the key to be generated in OAuth mode. A key that wasn't gets HTTP 403 `unauthorized_client` at token time.
4. Note the client ID and client secret. Enter them in `OAuthClientId` and `OAuthClientSecret`. The V2 spec's token example uses the account number as `client_id`, but the plugin never substitutes `AccountNumber` for it, so set `OAuthClientId` explicitly. See [Step 1 of the migration guide](#step-1--create-a-v2-oauth2-credential) for the failure modes.
5. Set `UseV2Api` to `true` and set `ApiUrl` to the V2 base URL (no trailing path suffix), e.g. `https://sandbox-us-api.certinext.io`.
6. V1-only fields (`ApiKey`, `AccountNumber`, `AuthMode`) are not required in this mode and can be left blank.

#### V2 Token Caching

The plugin obtains a V2 bearer token via the standard OAuth2 `client_credentials` grant (`grant_type=client_credentials`, form-encoded) against `{ApiUrl}/oauth/token`. Tokens are cached in memory and reused until 60 seconds before expiry (minimum 30-second cache). Token refresh is thread-safe.

### V2 Certificate Template Fields

When `UseV2Api` is `true`, two additional enrollment parameters become relevant:

| Parameter | Required / Optional | Type | Description | Example / Default |
|---|---|---|---|---|
| `ProductFamily` | Optional | String | CERTInext V2 product family: `ssl` or `private-pki` (see [V2 Private PKI Orders](#v2-private-pki-orders)). Default: `ssl`. | `ssl` |
| `ProductVariant` | Optional | String | Variant within the family. `ssl`: `dv`, `ov`, or `ev`. `private-pki`: `intranet-ssl` or `igtf-host` (required). | Derived from `ProductId` (for example `dv`) |

- **`ProductVariant` default:** when omitted for `ssl`, the plugin derives it from the selected product (an OV product sends `ov`, an EV product sends `ev`). An explicit value that contradicts the product fails enrollment.
- **`signature` (Document Signer):** the parameter accepts it, but enrollment is not supported and fails before any order is placed.
- **Unrecognized family:** treated as `ssl`.
- **`ProductCode`:** optional on V2. When set, it is sent in the `X-Product-Code` header as an override; when blank, no header is sent and CERTInext resolves the product.

### V2 Product Code Resolution

When `UseV2Api` is `true`, the plugin does not choose a numeric product code. The V2 spec treats the `X-Product-Code` header on order create as an optional override: CERTInext's wrapper picks the right catalog product from the variant (`productVariant` for SSL/TLS, `variant` for Private PKI), whether `certificate.domain` is a wildcard (it starts with `*.`), and whether `additionalDomains` is non-empty (multi-domain, UCC). The create response reports the product it chose as `resolvedProductCode`, which the plugin logs at Information level.

1. **No `ProductCode` on the template (the default)** — no `X-Product-Code` header is sent. The connector's `DefaultProductCode` is not used, and neither is the catalog: save-time validation does no catalog check, and enrollment makes no catalog call. The plugin decides whether the order is wildcard or multi-domain from the request itself:
   - **Wildcard:** the primary domain starts with `*.`.
   - **Multi-domain:** the selected product is a UCC product, or the CSR or gateway SAN list carries DNS names beyond the primary domain (its `www.` variant, and a wildcard's bare apex, don't count). Those names are sent as `additionalDomains`, which makes CERTInext choose a UCC product.
2. **Explicit `ProductCode` (or the deprecated `ProfileId` alias)** — the override. It is sent as-is in the `X-Product-Code` header, after template save-time validation confirms it exists in the live V2 catalog and matches the selected product. Use it when your account holds several matching products (for example different CA profiles for the same variant) and you want to force one. With an override, the plugin reads the catalog once per enrollment to recognize UCC and wildcard products, and rejects extra SANs on a single-domain product.

This differs from V1, where `DefaultProductCode` only affects renewals (see [DefaultProductCode](#defaultproductcode)).

### V2 Private PKI Orders

With `ProductFamily=private-pki`, the plugin places the order against CERTInext's Private PKI endpoint using the Private PKI request body, which differs from the SSL/TLS one:

- **Product code is optional.** CERTInext resolves the Private PKI product from `ProductVariant`. Set `ProductCode` to your account's Private PKI catalog code only to pick between several matching products; template validation then checks that it is a Private PKI product (`productTypeID` `39`).
- **Which `ProductID` to pick.** The plugin advertises SSL/TLS product names only, so the template still needs one from that list. It does not affect a `private-pki` order, which is built from `ProductVariant` (and `ProductCode`, if set), so any ProductID (for example `DV SSL`) works.
- **Variant is required.** Set `ProductVariant` to `intranet-ssl` or `igtf-host`.
- **Hostname.** The order's primary `hostname` comes from `DomainName`, or from the CSR's CN when `DomainName` isn't set.
- **SANs.** Sent in `additionalHosts`, which accepts DNS names and IPv4/IPv6 addresses. They come from the gateway's SAN list, or from the CSR when the gateway supplies none.
- **Unsupported SANs.** Email and URI SANs can't be expressed, so they are left off the order and a warning is logged. `SubmitNonDnsSans` isn't consulted.
- **No DCV, organization, or subscriber agreement.** Private PKI orders have none of these steps, so DCV is never attempted for them, and `OrganizationNumber`, `AutoSecureWww`, `SignerName`, `SignerPlace`, and `SignerIp` aren't used.
- **Shared fields.** The requestor, technical contact, subscription, email-notification, and group settings are sent exactly as they are for SSL/TLS orders.
- **Two-call CSR delivery.** The plugin creates the order without a CSR and then submits it, always. CERTInext rejects an inline CSR on the Private PKI create (HTTP 422), so the SSL/TLS-only `V2InlineCsr` setting doesn't apply; when it's on, the plugin logs a one-time notice that Private PKI ignores it.

### V2 Order Lifecycle

A V2 enrollment places the order, submits the CSR (or, with `V2InlineCsr` on for SSL/TLS, sends it inline in the create call), and then checks the order status; see [V2 enrollment flow](#v2-enrollment-flow) for the full sequence. V2 orders are identified by the `orderId` the V2 order placement endpoint returns, which the plugin stores unchanged as the `CARequestID` and uses for all later tracking, certificate download, and revocation calls. The V2 spec's examples show `ord_`-prefixed IDs, but V2 returns numeric order numbers in the same format as V1 (e.g. `6625262451`). Treat the ID as an opaque string.

V2 status strings map to Keyfactor enrollment statuses as follows:

| V2 Status | Keyfactor Status | Notes |
|---|---|---|
| `issued` | Issued | Certificate is immediately downloaded and returned to Command. |
| `pending-dcv` | Pending External Validation | Order is awaiting domain control validation. |
| `pending-csr` | Pending External Validation | Order is awaiting CSR submission or processing. |
| `pending-agreement` | Pending External Validation | Order requires subscriber agreement acceptance. |
| `pending-organization-verification` | Pending External Validation | OV/EV order is awaiting organization verification. |
| `pending-documents` | Pending External Validation | Order is awaiting supporting document submission. |
| `pending-approval` | Pending External Validation | Order is awaiting final CA/LRA approval before issuance. |
| `revoked` | Revoked | Order has been revoked. |
| `cancelled` | Failed | Order was cancelled; a new enrollment is required. |
| `rejected` | Failed | Order was rejected by the CA/LRA; a new enrollment is required. |
| `expired` | Issued | An expired-but-not-revoked order is reported as issued (GENERATED), matching V1's convention — it remains visible in Command's inventory rather than disappearing as a failure. |
| `unknown` | Pending External Validation | CERTInext can't currently report where the order is; the order is kept pending and re-checked on the next status poll or sync, and the plugin logs a warning. |

Any V2 status not in this table (e.g. a value CERTInext adds in the future) maps to Failed, and the
plugin logs a warning distinguishing "unmapped status" from the statuses above that are deliberately
mapped to Failed — see the gateway trace log if certificates unexpectedly show as failed.

**V2 synchronization:**

- Synchronize pages through `/reports/orders`. Pages are capped at 100 rows, and `PageSize` is clamped to that.
- The report carries display strings (for example `Order Fulfilled`, `Certificate Downloaded`) rather than the status enum above. Recognized strings are mapped directly. Any other combination falls back to a live order-status call, so a new display value never silently misclassifies an order.
- Cancelled and rejected orders are skipped. Issued orders have their certificate chain downloaded.
- CERTInext does not serve the certificate body of a revoked order. A revoked order is propagated as revoked only when the gateway already holds that certificate (the revocation date and reason come from a live status call).
- Otherwise a revoked order is reported as Failed (the gateway has a record without a body) or skipped (no record), so the gateway never stores a revoked record without a certificate.
- `IgnoreExpired` is applied here: expired certificates are skipped.

V2 has no *renew* endpoint. CERTInext does document a `/reissue` endpoint (`mode: rekey|update-sans`, with optional `revokePrevious`/`revokeReason`), but the plugin does not use it — every enrollment type (New, Reissue, Renew, RenewOrReissue) places a fresh V2 order, and the prior order/certificate is left issued rather than auto-revoked.

### V2 Revocation Reason Handling

CERTInext's V2 revoke endpoint accepts only a subset of its own documented reason enum. When Command's revoke reason maps to one CERTInext rejects, the plugin substitutes an accepted reason and retries once, rather than failing the revoke outright: CA-compromise and AA-compromise are retried as key-compromise; unspecified (Command's default when no reason is given) and certificate-hold are retried as cessation-of-operation. See [Revocation Reason Codes](#revocation-reason-codes) in the migration guide below for the full accepted/rejected matrix.

{% include 'migration-v1-to-v2.md' %}
