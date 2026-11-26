## Overview

> [!CAUTION]
> **The CERTInext V1 API is deprecated and no longer works.** CERTInext changed its API, so plugin
> 1.x and any connector with `UseV2Api` set to `false` can no longer be relied on. **Upgrade to
> 2.0.0 and move every connector to the V2 API** — see [Migrating from V1 to V2](#migrating-from-v1-to-v2).
> From 2.0.0, `UseV2Api` defaults to `true`. V1 is documented only under
> [Legacy V1 API (Deprecated)](#legacy-v1-api-deprecated).

The CERTInext AnyCA Gateway REST plugin extends the certificate lifecycle capabilities of the CERTInext platform (by eMudhra) to Keyfactor Command via the Keyfactor AnyCA Gateway REST, using the order-centric CERTInext V2 REST API. The plugin represents a fully featured AnyCA REST plugin with the following capabilities:

* CA Synchronization:
    * Download all certificates issued through the CERTInext CA, either as a full inventory or incrementally since the last sync.
    * Expired certificates can optionally be excluded from synchronization using the `IgnoreExpired` configuration flag.
* Certificate Enrollment for SSL/TLS (DV, OV, EV, including wildcard and multi-domain) and Private PKI products:
    * New certificate enrollment (new keys and certificate).
    * Certificate renewal — every renewal places a new order.
    * Certificate reissuance (new keys) through CERTInext's SSL/TLS reissue endpoint when outside the renewal window.
    * Synchronous certificate pickup — a fast-issuing order (DV, or already-approved) can return the certificate in the same enrollment call instead of always waiting for the next sync, via `PickupRetries`/`PickupDelay`.
    * DNS-01 domain control validation (DCV) — the plugin publishes the validation TXT record through a DNS provider plugin deployed on the gateway and asks CERTInext to verify it, during enrollment and during synchronization (`DcvEnabled`, on by default).
* Certificate Revocation:
    * Request revocation of a previously issued certificate using RFC 5280 reason codes, mapped to the reasons CERTInext accepts (see [Revocation Reason Codes](#revocation-reason-codes)).
* Authentication with an OAuth2 `client_credentials` bearer token.

## Requirements

* Keyfactor Command 25.5 or later
* AnyCA Gateway REST framework version 26.2.0 or later (`IAnyCAPlugin` 3.3.0)
* A DNS provider plugin deployed on the AnyCA Gateway if the connector validates domains with DNS-01 DCV (the default; see `DcvEnabled`)
* A CERTInext account with API access enabled, an OAuth-mode API credential, and at least one certificate product configured
* Network connectivity from the AnyCA Gateway host to the CERTInext API endpoint for your region (see table below)
* The AnyCA Gateway host must trust the TLS certificate presented by the CERTInext API endpoint

### CERTInext Environments

CERTInext operates three separate environments. Use the sandbox environment for initial integration testing. Switch to a production environment only after all functionality has been verified.

| Environment | Portal Sign-in URL | API Base URL (`ApiUrl`) |
|---|---|---|
| Sandbox | https://sandbox-us.certinext.io/ | `https://sandbox-us-api.certinext.io` |
| Production — India (Global) | https://in.certinext.io/ | `https://api.certinext.io` |
| Production — US | https://us.certinext.io/ | `https://us-api.certinext.io` |

> Note: Product catalogs differ between sandbox and production. Check your account's catalog (`GET /api/certinext/v2/catalog/products`) in the environment you are targeting before going live.

## CERTInext API Setup

The plugin authenticates with an OAuth2 `client_credentials` bearer token, requested from `{ApiUrl}/oauth/token` and sent in the `Authorization: Bearer` header. Create an OAuth-mode credential in the CERTInext portal:

1. Log in to the CERTInext portal for your environment.
2. Navigate to **Integrations → APIs**.
3. Click **+ Create API Credentials**, set **API Type** to `REST`, and select the **OAuth** auth type (not `Access Key`). The V2 spec requires the key to be generated in OAuth mode. A key that wasn't gets HTTP 403 `unauthorized_client` at token time.
4. Note the client ID and client secret. Enter them in `OAuthClientId` and `OAuthClientSecret`. The V2 spec's token example uses the account number as `client_id`, but the plugin never substitutes `AccountNumber` for it, so set `OAuthClientId` explicitly. See [Step 1 of the migration guide](#step-1--create-a-v2-oauth2-credential) for the failure modes.

> Note: Credentials are stored in Keyfactor Command's encrypted gateway configuration and are never written to disk by the plugin.

## Gateway Registration

Before enrolling certificates, the Keyfactor Command server must trust the CERTInext issuing CA chain.

1. Log in to the CERTInext portal and download the root CA certificate and any intermediate CA certificates in the chain as PEM or DER files.
2. On the Keyfactor Command server, import those certificates into the appropriate Windows certificate store — **Trusted Root Certification Authorities** for the root CA and **Intermediate Certification Authorities** for any subordinate CAs.
3. In the Keyfactor Command Management Portal, navigate to **CA Connectors** and add a new CA using the **CERTInext AnyCA REST Gateway Plugin**.
4. Complete the CA connector configuration fields described in the next section, then save and test the connection. The gateway performs a live connectivity test during validation: a token request, then `GET /api/certinext/v2/auth/me`.

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

Also confirm with CERTInext whether your account's product catalog changes. If a template sets `ProductCode`, update it.

## CA Configuration

The following fields are presented in the Keyfactor Command Management Portal when creating or editing the CERTInext CA connector. Fields used only by the deprecated V1 API (`AccountNumber`, `ApiKey`, `AuthMode`, `OAuthTokenUrl`, `AccountingModel`, `SignerIp`, `SubmitNonDnsSans`, `DefaultProductCode`, `DcvWaitForChallengeSeconds`, `DcvWaitForIssuanceSeconds`) are ignored and can be left blank; see [V1 Connector Fields](#v1-connector-fields).

### Save-Time Validation

When the connector is saved (and `Enabled` is `true`), the plugin checks only the fields below. Every other field marked **Required** in the tables is needed by CERTInext for a successful order, but the connector saves without it — enrollment then fails, or the order is parked pending, until it is set.

- `ApiUrl` must be present and use `https` (`http` is allowed only for a loopback host: `localhost`, `127.0.0.1`, `::1`).
- `OAuthClientId`, `OAuthClientSecret`, and `SignerPlace` must be set.
- `V2InlineCsr`, `V2ReissueRevokePrevious`, and `SslComSubmitOrganization`, when present, must be booleans, and `SslComAdminEmail`, when set, must be a single email address.

### Connection

| Field | Required | Description |
|---|---|---|
| `ApiUrl` | Required | CERTInext API base URL: the bare host, no path suffix (see [CERTInext Environments](#certinext-environments)). A trailing slash is accepted. Must use `https`, because the OAuth client secret is sent to it; `http` is rejected except for a loopback host, for local test servers only. |
| `UseV2Api` | Optional | Selects the API. Leave it unset or `true`. `false` selects the [deprecated V1 API](#legacy-v1-api-deprecated), which no longer works. Default: `true`. |
| `OAuthClientId` | Required | OAuth client ID. The key must be generated in OAuth mode. |
| `OAuthClientSecret` | Required | OAuth client secret. Masked in the UI. |
| `Enabled` | Optional | Set to `false` to create the connector record before credentials exist; skips validation and the live connectivity test. Default: `true`. |

### Requestor and Signer

| Field | Required | Description |
|---|---|---|
| `RequestorName` | Required | Default name of the person or service submitting orders, sent in the order's `requestor` block. Example: `PKI Automation`. |
| `RequestorEmail` | Required | Default requestor email. Use a monitored inbox registered in your CERTInext account. |
| `RequestorIsdCode` | Optional | Dialing code for the requestor phone, digits only, no `+`. The phone is sent as `+<ISD code><number>`. Default: `1`. |
| `RequestorMobileNumber` | Optional | Requestor mobile number, digits only, no country code. |
| `RequestorDesignation` | Optional | Job title of the requestor, sent as `requestor.designation`. Omitted when blank. |
| `TechnicalContactName`<br>`TechnicalContactEmail`<br>`TechnicalContactIsdCode`<br>`TechnicalContactMobileNumber` | Optional | Technical point of contact, sent as the order's `technicalPointOfContact` on SSL/TLS and Private PKI orders. Each defaults to the matching `Requestor*` field. `designation` is always `Technical Contact`. |
| `SignerPlace` | Required | City of the person accepting the subscriber agreement, sent in the order's `agreement` block. A template `SignerPlace` overrides it. Example: `Austin`. |

- **Signer values per order:** the agreement signer name is the template `SignerName`, else the requestor name (the template `RequesterName`, else the connector's `RequestorName`). The signer place is the template `SignerPlace`, else the connector's. The V2 agreement block has no signer IP field (the CA records the signer's IP itself).

### Order Defaults

| Field | Required | Description |
|---|---|---|
| `GroupNumber` | Optional | CERTInext group (delegation) number, from **Delegation → Groups**. Sent as `groupNumber` on order create and as a query parameter on the catalog and orders-report calls. When blank, CERTInext uses the account's default group. |
| `OrganizationNumber` | Optional | Pre-vetted organization number, from **Organizations → Pre-vetted Organizations**. Required for OV/EV: those orders send `organization.organizationNumber` with `preVetted=true`, and enrollment fails before any CA call if it is blank. DV orders never send an organization block. |
| `EmailNotifications` | Optional | Lifecycle emails to the requestor. See [EmailNotifications values](#emailnotifications-values). Default: `0`. |
| `SubscriptionValidityYears` | Optional | Default validity in years: `1`, `2`, or `3`. Used when the template sets no `ValidityYears`. Default: `1`. |
| `SubscriptionAutoRenew` | Optional | `0` = CERTInext does not auto-renew (recommended; Command drives renewal), `1` = enabled (`subscription.autoRenew=true`). Default: `0`. |
| `SubscriptionRenewCriteriaDays` | Optional | Days before expiry at which CERTInext auto-renews, sent as `subscription.renewBeforeDays`; CERTInext acts on it only when `SubscriptionAutoRenew` is `1`. Blank omits it, so the CA's default applies. An unparseable or negative value fails the enrollment before any CA call. Default: `30`. |
| `AutoSecureWww` | Optional | `1` adds the `www.` variant of the primary domain as an extra SAN, which must also pass domain validation. Default: `0`. |

- **`GroupNumber` is not `AccountNumber`:** each CERTInext group (cost center or department) has its own `groupNumber`, which is separate from your account number and from any organization number on the Organizations page.
- **Non-DNS SANs:** an SSL/TLS order's `additionalDomains` takes DNS names only, so IP, email, and URI SANs are left off with a gateway-log warning. Private PKI sends DNS names and IPs (see [V2 Private PKI Orders](#v2-private-pki-orders)).

#### EmailNotifications Values

| Value | Sent as |
|---|---|
| `1` | `all` |
| `0` | `consent-only`, the quietest value the V2 spec allows (its enum is `consent-only` or `all`) |
| Blank | Omitted, so the CA default (`all`, not silent) applies. Set `0` explicitly for silent orders. |
| Anything else | Enrollment fails before any CA call |

### Synchronization and Pickup

| Field | Required | Description |
|---|---|---|
| `IgnoreExpired` | Optional | Skip expired certificates during sync: a report row with a parseable, past `certificateExpiryDate` is skipped, and a row with a missing or unparseable date is kept. Default: `false`. |
| `PageSize` | Optional | Orders fetched per page during sync. Maximum `100`; larger values are clamped, and 0 or less falls back to 100. Reduce it if sync requests time out. Default: `100`. |
| `V2SyncLookbackHours` | Optional | Extra hours subtracted from the last-sync time on incremental sync, so a slow order is not missed. Default: `72`. |
| `SyncRecentOrderGraceSeconds` | Optional | A sync (full or incremental) skips pending or issued orders created less than this many seconds ago (plus a 5-second clock margin); the next incremental sync imports them. This keeps a sync that runs during an in-flight enrollment from causing that enrollment to fail with a duplicate key. Held issued orders aren't downloaded; revoked and failed orders, and orders with no usable order date, are never held. `0` disables it. Default: `120`. |
| `PickupRetries` | Optional | Times `Enroll` polls CERTInext for the certificate after a successful order. `0` disables the wait. Default: `5`. |
| `PickupDelay` | Optional | Seconds between pickup polls. Default: `10`. |
| `EnrollmentCallBudgetSeconds` | Optional | Seconds from the start of an enrollment after which the pickup stops waiting and returns the order as pending, so the call returns before Command's workflow step timeout. Set it about 10 s below Command's **Workflow Step Run Timeout (seconds)** application setting. `0` disables it. Default: `50`. Maximum: `90`. |

- **Why a lookback:** the API's `from`/`to` filter may bracket either the order-placement date or the issuance date. The window keeps an order created before the last sync but issued afterward (for example a slow DCV order) from being missed.
- **`PickupRetries` and `PickupDelay`:** only a result with a certificate body counts as issued. OV/EV orders validate asynchronously (minutes to hours) and typically exhaust the wait regardless of these values.

#### Pickup Limits

| Setting | Minimum | Maximum | Default | Out-of-range behavior |
|---|---|---|---|---|
| `PickupRetries` | 0 (disabled) | 30 | 5 | Negative becomes 0; above 30 becomes 30 |
| `PickupDelay` (seconds) | 1 | 60 | 10 | Zero or negative becomes 10; above 60 becomes 60 |
| Total wait | — | 75 s | ~55 s | The retry count is reduced to fit the cap |
| `EnrollmentCallBudgetSeconds` | 0 (no deadline) | 90 | 50 | Negative becomes 50; above 90 becomes 90 |

> **Pickup timing detail:** after a successful order placement, the plugin waits a fixed 5-second initial delay before the first poll, then polls CERTInext every `PickupDelay` seconds up to `PickupRetries` times. Each poll checks the order's status and downloads the certificate once it is issued. The total time budget is **5 s + (`PickupRetries` × `PickupDelay`) + about 1 s API round trip per poll**. With the defaults this is 5 + (5 × 10) = **~55 s plus round trips**.
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

#### Command's workflow step timeout and `EnrollmentCallBudgetSeconds`

Command runs the gateway enrollment inside the **Keyfactor-Enroll** step of the enrollment workflow. The step is bounded by the global application setting **Workflow Step Run Timeout (seconds)** (System Settings > Application Settings > Workflow > General; API short name `Workflow.General.Timeout`), which defaults to 60. The step itself has no timeout field of its own. If the plugin's `Enroll` call is still running when that time is up, Command fails the request with "Step 'Keyfactor-Enroll' failed: Failed to complete in 60 seconds", even though the order already exists at CERTInext. The certificate then arrives only through a later sync, and a resubmit creates a duplicate order.

The pickup budget above is counted from the start of the pickup, so the time spent placing the order is added on top of it. On the lab, a new order's create took about 1 s and the pickup started about 3 s after `Enroll` was called; a reissue call alone took about 26 s. With the default 55 s pickup, both ran past 60 s when the certificate wasn't ready.

`EnrollmentCallBudgetSeconds` (default 50) is a deadline measured from the start of `Enroll`. The pickup shortens its waits to fit inside it, skips the delay after its last poll, and stops early, returning the order as pending, when no further poll fits (it keeps a 3-second margin for the poll itself). It logs one Information line saying how much of the budget had passed and how many polls ran. The deadline only limits waiting: a create, reissue, Submit CSR or revoke call already in flight is never cut short, and orders are still never retried. `PickupRetries=0` still disables the pickup entirely. Inline DCV during `Enroll` isn't bounded by this deadline (it has its own `DcvTimeoutMinutes`), so an enrollment that runs DCV inline can still exceed the workflow step timeout.

- **If you raise Workflow Step Run Timeout**, for example because DNS propagation is slow, raise `EnrollmentCallBudgetSeconds` to about 10 s less than the new value. The 10 s leaves time for the Command-to-gateway call and the response.
- **The maximum is 90 s.** Separately from the workflow setting, Command's HTTP call into the gateway uses the .NET default timeout of 100 s, and no Command setting for it is documented. Neither the Command API nor the documentation states a maximum for Workflow Step Run Timeout.

### Domain Control Validation (DCV)

DCV needs a DNS provider plugin (for example `azure-azuredns-dnsplugin`) deployed on the gateway. Without one, orders that need validation stay pending and the plugin logs why. DCV applies to SSL/TLS orders; Private PKI orders have no DCV step.

| Field | Required | Description |
|---|---|---|
| `DcvEnabled` | Optional | Perform DNS-based DCV during enrollment and synchronization. Set to `false` to validate domains another way. Default: `true`. |
| `DcvTxtRecordTemplate` | Optional | TXT record hostname format; `{0}` is the domain being validated. Not used for domains SSL.com validates, which use SSL.com's own record name. Default: `_emsign-validation.{0}`. |
| `DcvPropagationDelaySeconds` | Optional | Seconds to wait after publishing the TXT record before asking CERTInext to verify. Default: `30`. |
| `DcvTimeoutMinutes` | Optional | Maximum minutes for the whole DCV flow before the order is left pending. Can also be set with `CERTINEXT_DCV_TIMEOUT_MINUTES`, which wins when both are set and it is a positive integer. Default: `10`. |
| `DcvSyncMaxOrderAgeHours` | Optional | During sync, only pending DV orders younger than this are driven through DCV. `0` disables the filter. Default: `24`. |
| `DcvSyncMaxPerPass` | Optional | Maximum pending DV orders driven through DCV per sync pass. `0` disables the cap. Default: `50`. |

- **Sync limits:** `DcvSyncMaxOrderAgeHours` and `DcvSyncMaxPerPass` keep a large backlog of old or abandoned pending orders from slowing every sync pass.
- **No challenge waits:** the plugin publishes the challenge as soon as the order exists and polls the order until it leaves `pending-dcv` (bounded by `DcvTimeoutMinutes`). When DCV ran inside the `Enroll` call, the pickup poll is skipped.

### Diagnostics

| Field | Required | Description |
|---|---|---|
| `LogSensitiveRequestData` | Optional | Temporary diagnostic switch. When `true`, requestor personal data and full CA request/response payloads are written to the gateway logs. Default: `false`. |

- **Use it briefly:** turn it on only while verifying a new deployment (to confirm exactly what was sent to the CA), then turn it off.
- **When `false`:** personal-data fields are redacted. Emails are masked but keep their domain (for example `j***@example.com`), including email addresses in CERTInext error text, and the enrollment log line omits the requester name.
- **SANs:** `rfc822Name` values in log lines are masked the same way, and URI SANs have their userinfo and `mailto:` addresses masked. DNS and IP SANs are always logged in full.
- **Payload dumps:** full request and response payloads are written only at Trace level.
- **Credentials:** the OAuth client secret, OAuth access and refresh tokens, access keys, passwords, and `Authorization` headers are redacted from logged payloads whatever this setting is. The token endpoint's response body is never logged.

## Certificate Template Creation Step

A Keyfactor Command certificate template maps an enrollment request to a specific CERTInext product. Create one template per CERTInext product that you want to make available to requesters.

The AnyCA Gateway REST portal also needs one certificate profile per product before Command templates can be created against it. Create the profiles by hand in the gateway portal, or with the helper script this repository ships (`make register-profiles`; set `DRY_RUN=1` to preview). By default the script also registers a `<ProductID> V2` profile per product, for a second set of templates that carry no `ProductCode` (see [V2 Product Code Resolution](#v2-product-code-resolution)); set `V2_TEMPLATES=0` to skip them. See [scripts/register/README.md](https://github.com/Keyfactor/certinext-caplugin/blob/main/scripts/register/README.md) for authentication and options.

In the Keyfactor Command Management Portal, navigate to **Certificate Templates** and create a new template associated with the CERTInext CA connector. The following enrollment parameters are available:

| Parameter | Required / Optional | Type | Description | Example / Default |
|---|---|---|---|---|
| `ProductFamily` | Optional | String | CERTInext product family: `ssl` or `private-pki` (see [V2 Private PKI Orders](#v2-private-pki-orders)). Default: `ssl`. | `ssl` |
| `ProductVariant` | Optional | String | Variant within the family. `ssl`: `dv`, `ov`, or `ev`. `private-pki`: `intranet-ssl` or `igtf-host` (required). | Derived from `ProductId` (for example `dv`) |
| `ProductCode` | Optional | String | Override for the product CERTInext resolves, sent as `X-Product-Code`. Leave it blank and CERTInext resolves the product (see [V2 Product Code Resolution](#v2-product-code-resolution)). | Blank |
| `ProfileId` | Deprecated | String | Legacy alias for `ProductCode`. Used in its place when `ProductCode` is not set. New templates should use `ProductCode`. | Blank |
| `ValidityYears` | Optional | Number | Subscription term in years: `1`, `2`, or `3`. Default: `1`. CERTInext certificates are issued within a subscription term at up to 390 days per certificate, with free renewals within the term. | `1` |
| `AutoApprove` | Optional | Boolean | **Currently has no effect** — reserved for future use. The plugin does not call any approval endpoint against CERTInext regardless of this setting. | `false` |
| `RequesterName` | Optional | String | Overrides the connector `RequestorName` for this template when non-blank. Never derived from the certificate subject. | `Keyfactor Automation` |
| `RequesterEmail` | Optional | String | Overrides the connector `RequestorEmail` for this template when non-blank. Never derived from the certificate subject. | `pki-admin@example.com` |
| `RenewalWindowDays` | Optional | Number | Decides whether `RenewOrReissue` uses the SSL/TLS reissue endpoint (prior certificate expires after the window) or places a new order (inside it). Default: `90`. | `90` |
| `KeyType` | Optional | String | Informational. The CSR decides the key algorithm. CERTInext accepts only RSA 2048/3072/4096 and ECC P-256/P-384. | `RSA2048`, `RSA3072`, `RSA4096`, `EC256`, `EC384` |
| `DomainName` | Optional | String | Primary domain name for SSL/TLS orders (for Private PKI, the primary hostname). If omitted, the plugin uses the CSR subject `CN`. For an SSL/TLS request with no `CN`, it uses the first DNS SAN that isn't a wildcard, else the first wildcard one (when the SANs are a name and its own wildcard, the wildcard is the domain and the plain name an additional domain), and CERTInext sets the issued certificate's `CN` to that domain. | `example.com` |
| `SignerName` | Optional | String | Per-template override for the subscriber agreement signer name. When omitted, defaults to the requestor name. | `Jane Smith` |
| `SignerPlace` | Optional | String | Per-template override for the subscriber agreement signer location. When omitted, defaults to the connector-level `SignerPlace`. | `Austin` |
| `OrgRepresentativeName` | Optional (OV only) | String | Registers a new Organization Representative on the order (`organization.useNewOrgRepresentative`), together with `OrgRepresentativeEmail`. Leave all five `OrgRepresentative*` parameters blank to keep the organization's existing representative. Personal data: never logged. | `Jane Doe` |
| `OrgRepresentativeEmail` | Optional (OV only) | String | The new representative's email address; required with `OrgRepresentativeName`. | `jane.doe@example.com` |
| `OrgRepresentativePhone` | Optional (OV only) | String | The new representative's phone: 6-15 digits, with an optional leading `+` and spaces, dashes, dots or parentheses. | `+1 555 010 0199` |
| `OrgRepresentativeDesignation` | Optional (OV only) | String | The new representative's job title. | `CISO` |
| `OrgRepresentativeEmployeeId` | Optional (OV only) | String | The new representative's employee ID. | `E-1042` |

`ValidityDays` and `SignerIp` are V1-only parameters and are ignored.

- **`ProductVariant` default:** when omitted for `ssl`, the plugin derives it from the selected product (an OV product sends `ov`, an EV product sends `ev`). An explicit value that contradicts the product fails enrollment.
- **`signature` (Document Signer):** `ProductFamily` accepts it, but enrollment is not supported and fails before any order is placed. An unrecognized family is treated as `ssl`.
- **New Organization Representative (OV):** setting `OrgRepresentativeName` and `OrgRepresentativeEmail` sends `useNewOrgRepresentative: true` with an `organizationRepresentative` block on the create call. The order is bound to that person. If the organization is already approved by a Validation Agent, CERTInext queues the change of the organization's representative of record for review, and the plugin logs `OrganizationRepresentativeStatus=pending-approval`; otherwise it reports `applied`. The plugin checks CERTInext's rules before any CA call, both when the template is saved and at enrollment:
  - OV products only; DV and EV are rejected (`EMS-1315`).
  - The connector needs `OrganizationNumber` (`EMS-1316`).
  - Name and email must both be set (`EMS-1319`/`EMS-1320`), including when only the phone, designation or employee ID is set.
  - The email must be a single address, and the phone must contain 6-15 digits (`EMS-1321`).

  An email that is already a representative of the organization is rejected by CERTInext (`EMS-1317`); clear the parameters to keep the existing one. A reissue doesn't send the block, so the reissued order keeps the original order's representative. The values are never logged, and are redacted from payload logs unless `LogSensitiveRequestData` is on.
- **Key types:** larger RSA, ECC P-521, and the Ed25519/Ed448 curves are rejected by the CA (`Invalid key size`).

## Product Codes

**Templates don't need product codes.** CERTInext picks the product from the template's `ProductVariant` and the request's shape, so leave `ProductCode` blank. Set it only to choose one product when several match (see [V2 Product Code Resolution](#v2-product-code-resolution)). The variants the V2 API defines are:

| Family (`ProductFamily`) | `ProductVariant` values | How the exact product is chosen |
|---|---|---|
| `ssl` | `dv`, `ov`, `ev` | The variant plus the domain's shape: a `*.` domain selects a wildcard product, and extra DNS names select a multi-domain (UCC) product |
| `private-pki` | `intranet-ssl`, `igtf-host` | The variant |

Where several catalog products match a variant, CERTInext picks one, and it may not be the one you want: on the US sandbox, `dv` resolves to a 1-month product (`917`) that rejects a client CSR. If that happens, set `ProductCode` on the template.

**Product codes are provisioned per account by eMudhra**, and they depend on which CA the account issues from: accounts that issue through SSL.com report codes such as `1011`-`1020`. Your account's own catalog (`GET /api/certinext/v2/catalog/products`) is the only authority for an override code. "Invalid Product Code" (EMS-1162) means your account does not have that product provisioned; contact your eMudhra account representative.

- **Private PKI** products need a separate entitlement. On an account without it, an order returns EMS-1162.
- **S/MIME and Document Signing are not supported.** `GetProductIds` advertises SSL/TLS products only, and `ProductFamily=signature` enrollment fails before any order is placed. Their codes can still appear in your account's catalog.

## Extension Mechanics

### Authentication

Every call carries an `Authorization: Bearer` header. The plugin obtains the token with the OAuth2 `client_credentials` grant (`grant_type=client_credentials`, form-encoded) against `{ApiUrl}/oauth/token`, using `OAuthClientId` and `OAuthClientSecret`.

#### V2 Token Caching

Tokens are cached in memory and reused until 60 seconds before expiry (minimum 30-second cache). Token refresh is thread-safe. A token request that gets no HTTP response (for example a dropped connection) is retried twice, after 1 and 3 seconds. An HTTP error such as 401 or 403 is not retried. A call that gets no response logs `TransportDetail=`, which gives the response status and the exception chain, with credentials removed.

### HTTP Timeout and Retries

Every CERTInext API call (enroll, sync, revoke) uses a fixed 120-second request timeout. The OAuth token request is the exception: it uses the HTTP client's default timeout. The 120 seconds is hardcoded and is not exposed as a connector setting or environment variable. If a call doesn't return within 120 seconds, the plugin aborts it and the operation fails.

- **Order placement and CSR submission are never auto-retried after a timeout or server error**, because CERTInext may have already created the order. If the CA did create it, the next synchronization imports it. Do not resubmit immediately; check the CERTInext portal first.
- **Other calls are never auto-retried either.** The exceptions are the token request's transport retry above and the one-time revoke-reason fallback described under [V2 Revocation Reason Handling](#v2-revocation-reason-handling).

### Enrollment Decision Logic

An SSL/TLS `Reissue`, or a `RenewOrReissue` whose prior certificate is unexpired and expires after `RenewalWindowDays`, uses CERTInext's reissue endpoint (see [V2 reissue](#v2-reissue)). Every other enrollment, and every Private PKI enrollment, places a new order. See [V2 Order Lifecycle](#v2-order-lifecycle).

### Templates for Synced Certificates

The gateway gives a synced certificate a template only when the record's product matches a configured template's product name (`DV SSL`, `OV SSL Wildcard`, …) exactly. CERTInext reports a product code instead, so each sync pass reads the account's product catalog once and names the code by its product type. On the sandbox, for example, `842` and `917` both become `DV SSL`, and `847` becomes `OV SSL Wildcard`. Accounts that issue through SSL.com use codes `1011`-`1020` instead, which are named the same way (for example, `1013` becomes `DV SSL Multi-Domain (UCC)`). A certificate ordered outside Command, for example in the CERTInext portal, then arrives in Command with the first template configured for that product. A code with no matching plugin product (Private PKI, S/MIME, Document Signer), or one the account's catalog no longer lists (such as an older order's code), is passed on unchanged and gets no template. If the catalog can't be read, the pass logs one warning and keeps the codes. The sync summary reports `ProductNames: Resolved=…, Unresolved=…`. Certificates enrolled through Command keep the template Command recorded at enrollment.

## V2 API

V2 is the plugin's API and the default (`UseV2Api` unset or `true`). It is fully self-contained: Ping, Enroll, GetSingleRecord, Revoke, and Synchronize all route through it. Known limitations are listed under [Known Gaps](#known-gaps).

### V2 CA Connector Fields

| Field | Required | Description |
|---|---|---|
| `SslComSubmitOrganization` | Optional | OV/EV only. `true` lets the plugin submit an unvalidated organization to SSL.com, which **accepts SSL.com's subscriber agreement on the organization's behalf**; see [SSL.com organization validation](#sslcom-organization-validation). Default: `false`. |
| `SslComAdminEmail` | Optional | Administrator email sent as `adminEmail` on that submission. Blank omits it. Example: `pki-admin@example.com`. |
| `V2InlineCsr` | Optional | SSL/TLS only. `true` (the default) sends the CSR inline in the create call (a single `POST /ssl-certificates`), as a direct API integration does. `false` creates the order and then submits the CSR; that two-call flow fails for a domain the account has already validated, because CERTInext approves the order at create and then rejects the CSR. A create that times out or returns a 5xx can leave an order that issues and is imported by the next sync rather than cancelled, and the create call can hold about 20 seconds until issuance. Private PKI always uses two calls. Default: `true`. |
| `V2ReissueRevokePrevious` | Optional | SSL/TLS reissue only. `true` makes the reissue call also revoke the previous certificate with reason `superseded`; the intent is audit-logged first. `false` leaves the previous certificate valid. See [V2 reissue](#v2-reissue). Default: `false`. |

The connection, requestor, order, synchronization, DCV, and diagnostics fields are under [CA Configuration](#ca-configuration).

### V2 Product Code Resolution

The plugin does not choose a numeric product code. The V2 spec treats the `X-Product-Code` header on order create as an optional override: CERTInext's wrapper picks the right catalog product from the variant (`productVariant` for SSL/TLS, `variant` for Private PKI), whether `certificate.domain` is a wildcard (it starts with `*.`), and whether `additionalDomains` is non-empty (multi-domain, UCC). The create response reports the product it chose as `resolvedProductCode`, which the plugin logs at Information level.

CERTInext advises sending only the variant and leaving `X-Product-Code` out, so the plugin never adds the header on its own.

1. **No `ProductCode` on the template (the default and recommended)** — no `X-Product-Code` header is sent. Neither save-time validation nor enrollment reads the catalog. The plugin decides whether the order is wildcard or multi-domain from the request itself:
   - **Wildcard:** the primary domain starts with `*.`.
   - **Multi-domain:** the selected product is a UCC product, or the gateway's SAN list carries DNS names beyond the primary domain (its `www.` variant, and a wildcard's bare apex, don't count). Those names are sent as `additionalDomains`, which makes CERTInext choose a UCC product.
   - **SAN source:** Command's SAN list (passed by the gateway) is authoritative. A DNS name that is only in the CSR doesn't make the order multi-domain and isn't sent in `additionalDomains`; the CSR itself is still sent to CERTInext unchanged. The CSR's SANs are used only when the gateway passes no SAN list at all. This matches the other Keyfactor CA plugins that build a SAN list for their CA.
   - **Wildcard in the SANs only:** the CN is a plain name, such as `example.com`, and a SAN is a wildcard, such as `*.example.com`. The CN stays the domain (CERTInext requires the domain to match the CSR CN, `EMS-1056`), and the wildcard is sent in `additionalDomains`. On some accounts CERTInext rejects this shape with `EMS-1173 Invalid Additional Domain Names`; if it does, set `ProductCode` on the template to the account's Wildcard UCC product code.
2. **Explicit `ProductCode` (or the deprecated `ProfileId` alias)** — the override. It is sent as-is in the `X-Product-Code` header. CERTInext advises against sending it, so use it only when your account holds several matching products (for example different CA profiles for the same variant) and you want to force one. The plugin doesn't check the code against the catalog, either when the template is saved or at enrollment. It decides wildcard and multi-domain from the request the same way as without an override, and CERTInext rejects a code that doesn't exist or can't carry the request.

The connector's `DefaultProductCode` is not used.

### V2 Private PKI Orders

With `ProductFamily=private-pki`, the plugin places the order against CERTInext's Private PKI endpoint using the Private PKI request body, which differs from the SSL/TLS one:

- **Product code is optional.** CERTInext resolves the Private PKI product from `ProductVariant`. Set `ProductCode` to your account's Private PKI catalog code only to pick between several matching products. It isn't checked against the catalog; CERTInext rejects a code that isn't a Private PKI product on your account.
- **Which `ProductID` to pick.** The plugin advertises SSL/TLS product names only, so the template still needs one from that list. It does not affect a `private-pki` order, which is built from `ProductVariant` (and `ProductCode`, if set), so any ProductID (for example `DV SSL`) works.
- **Variant is required.** Set `ProductVariant` to `intranet-ssl` or `igtf-host`.
- **Hostname.** The order's primary `hostname` comes from `DomainName`, or from the CSR's CN when `DomainName` isn't set.
- **SANs.** Sent in `additionalHosts`, which accepts DNS names and IPv4/IPv6 addresses. They come from the gateway's SAN list, or from the CSR when the gateway supplies none.
- **Unsupported SANs.** Email and URI SANs can't be expressed, so they are left off the order and a warning is logged.
- **No DCV, organization, or subscriber agreement.** Private PKI orders have none of these steps, so DCV is never attempted for them, and `OrganizationNumber`, `AutoSecureWww`, `SignerName`, and `SignerPlace` aren't used.
- **Shared fields.** The requestor, technical contact, subscription, email-notification, and group settings are sent exactly as they are for SSL/TLS orders.
- **Two-call CSR delivery.** The plugin creates the order without a CSR and then submits it, always. CERTInext rejects an inline CSR on the Private PKI create (HTTP 422), so the SSL/TLS-only `V2InlineCsr` setting doesn't apply; when it's on, the plugin logs a one-time notice that Private PKI ignores it.

### V2 Order Lifecycle

An enrollment places the order, submits the CSR (or, with `V2InlineCsr` on for SSL/TLS, sends it inline in the create call), and then checks the order status; see [V2 enrollment flow](#v2-enrollment-flow) for the full sequence. Orders are identified by the `orderId` the order placement endpoint returns, which the plugin stores unchanged as the `CARequestID` and uses for all later tracking, certificate download, and revocation calls. The V2 spec's examples show `ord_`-prefixed IDs, but CERTInext returns numeric order numbers (e.g. `6625262451`), and reissues return derived IDs such as `1984857369R001`. Treat the ID as an opaque string.

Status strings map to Keyfactor enrollment statuses as follows:

| V2 Status | Keyfactor Status | Notes |
|---|---|---|
| `issued` | Issued | Certificate is immediately downloaded and returned to Command. CERTInext can report `issued` for a while before the certificate is generated (Download Certificate answers 422 `EMS-1165`); see [Issued but not generated yet](#issued-but-not-generated-yet). |
| `pending-dcv` | Pending External Validation | Order is awaiting domain control validation. |
| `pending-csr` | Pending External Validation | Order is awaiting CSR submission or processing. |
| `pending-agreement` | Pending External Validation | Order requires subscriber agreement acceptance. For SSL/TLS orders the plugin accepts it (see [Subscriber agreement fallback](#subscriber-agreement-fallback)). |
| `pending-organization-verification` | Pending External Validation | OV/EV order is awaiting organization verification. |
| `pending-documents` | Pending External Validation | Order is awaiting supporting document submission. |
| `pending-approval` | Pending External Validation | Order is awaiting final CA/LRA approval before issuance. |
| `revoked` | Revoked | Order has been revoked. |
| `cancelled` | Failed | Order was cancelled; a new enrollment is required. |
| `rejected` | Failed | Order was rejected by the CA/LRA; a new enrollment is required. |
| `expired` | Issued | An expired-but-not-revoked order is reported as issued (GENERATED) — it remains visible in Command's inventory rather than disappearing as a failure. |
| `unknown` | Pending External Validation | CERTInext can't currently report where the order is; the order is kept pending and re-checked on the next status poll or sync, and the plugin logs a warning. |

Any status not in this table (e.g. a value CERTInext adds in the future) maps to Failed, and the
plugin logs a warning distinguishing "unmapped status" from the statuses above that are deliberately
mapped to Failed — see the gateway trace log if certificates unexpectedly show as failed.

**Synchronization:**

- Synchronize pages through `/reports/orders`. Pages are capped at 100 rows, and `PageSize` is clamped to that.
- The report carries display strings (for example `Order Fulfilled`, `Certificate Downloaded`) rather than the status enum above. Recognized strings are mapped directly. Any other combination falls back to a live order-status call, so a new display value never silently misclassifies an order. If that call finds the order in no product family, as for every `On Hold | Setup Pending` row on the sandbox, the order is skipped for that pass and counted as `UntrackableListedOrders`; it isn't treated as an error. CERTInext doesn't document these display strings, so the sync summary names every pair it didn't recognize (`UnmappedReportStatuses=[...]`). Report a new pair so it can be mapped. One known pair is deliberately left unmapped: `Order Fulfilled | Pending for Approver` (the order fulfilled, the certificate still pending). Track Order returns `issued` for it, so the plugin asks Track Order and tries to download the certificate. If CERTInext answers that the certificate isn't generated (422 `EMS-1165`), the order is reported as pending, as its certificate status says. The download is tried again on every sync, so the certificate is imported once it exists.
- Cancelled and rejected orders are skipped. An order the gateway still holds as pending is the exception: it's emitted once as failed, so the gateway records that it's finished instead of showing it pending indefinitely. An order the gateway holds as issued or revoked is never changed, and one it doesn't hold at all is still skipped. The sync summary counts these as `FailedPropagated`. Issued orders have their certificate chain downloaded.
- CERTInext does not serve the certificate body of a revoked order. A revoked order is propagated as revoked only when the gateway already holds that certificate (the revocation date and reason come from a live status call).
- Otherwise a revoked order is reported as Failed (the gateway has a record without a body) or skipped (no record), so the gateway never stores a revoked record without a certificate.
- `IgnoreExpired` is applied here: expired certificates are skipped.
- An issued order whose download answers 422 `EMS-1165` is counted as `IssuedNotGeneratedYet` in the sync summary instead of logging a warning per order. It is emitted as pending when the row's certificate status says pending, otherwise without a certificate body; a later pass picks it up.
- If more than 25% of the records processed so far have failed (after at least 50 records), the sync aborts and is retried on the next cycle.

#### SSL.com organization validation

OV and EV certificates are issued under an organization that SSL.com must have validated. Before placing an OV or EV SSL/TLS order for the connector's `OrganizationNumber`, the plugin reads that organization's SSL.com validation status (`GET /organizations/{orgNumber}/ca-validations/sslcom`):

1. **Validated at the order's level (OV or EV):** nothing more is done.
2. **Not validated:** the plugin asks SSL.com to refresh the status once (`POST .../sslcom/sync`) and checks again.
3. **Still not validated, and `SslComSubmitOrganization` is `true`,** the level isn't already requested, and SSL.com's readiness block says the organization is ready for that level (`ready` for OV, `evReady` for EV, with nothing missing): the plugin submits it (`POST .../sslcom` with `levels` set to the order's level, `subscriberAgreementAccepted: true`, and `adminEmail` when `SslComAdminEmail` is set). **This accepts SSL.com's subscriber agreement on the organization's behalf.** The intent is logged at Information level before the call, and the connector start-up log warns that the setting is on. Leave it `false` (the default) unless you are authorized to accept that agreement; the plugin then only reads and refreshes the status.
4. **Whatever happens, the order is still placed.** A not-validated organization, a not-ready organization, or any failed SSL.com call logs one warning and never blocks or fails the enrollment (a not-validated organization's OV/EV order simply stays pending until SSL.com validates it). The warning includes SSL.com's status, `lastError`, and the fields it reports missing; email addresses are masked unless `LogSensitiveRequestData` is on.

DV and Private PKI orders skip this check entirely.

**How "validated" is decided.** The spec describes the response only in prose ("status per level (OV, EV) with validTill"), so the plugin reads it defensively. A level counts as validated when its entry in `levels` carries a validated status word (`VALIDATED`, `VALID`, `APPROVED`, `ACTIVE`, `COMPLETE`, `COMPLETED`, or `ISSUED`) or a true `validated` flag, or has no status but a `validTill` in the future; an entry whose `validTill` has passed is not validated. A bare level name in `levels` counts only when the overall `status` is itself a validated word. The overall `status` and `validatedAt` alone never count, since they aren't per level. Any shape the plugin doesn't recognize is treated as not validated; because that only produces a warning, the cost of a false "not validated" is a log line.

#### Subscriber agreement fallback

The create body already carries the agreement (`signerName`, `signerPlace`, `accepted: true`), but if Track Order still shows an SSL/TLS order at `pending-agreement`, the CA won't release the certificate until the agreement is accepted. The plugin then calls `POST /api/certinext/v2/ssl-certificates/{orderId}/agreement` with the same signer values:

- **Enrollment:** at most once per order per `Enroll` call, whether the status is seen right after create, after DCV, or during the pickup poll. The signer is the template's `SignerName` (else the requestor name) and `SignerPlace` (else the connector's), as on create.
- **Synchronize:** at most once per order per pass, using the connector's `RequestorName` and `SignerPlace` (a sync has no template). A pending SSL/TLS order in the listing that wasn't already tracked costs one extra status call per pass; with no `SignerPlace` or `RequestorName` configured the step is skipped entirely.
- **Audit and failures:** the intent is logged at Information before the call (the signer's name and place appear only when `LogSensitiveRequestData` is on). A failed call is logged as a warning and never fails the enrollment or the sync; the order stays pending.
- **Not applicable:** Private PKI orders have no Subscriber Agreement, and `GetSingleRecord` doesn't accept agreements.

#### Issued but not generated yet

CERTInext can report an order as `issued` before the certificate exists: Download Certificate then answers HTTP 422 `EMS-1165 Invalid request status.` Normally the certificate is generated about 20 seconds later, but the sandbox has been seen to take far longer. The plugin treats this as an expected state, not an error:

- **Enrollment:** the pickup poll keeps waiting (within `PickupRetries` x `PickupDelay`), logging each attempt at Debug level and writing one Information summary if the budget runs out. The enrollment returns pending, and a later synchronization imports the certificate.
- **`GetSingleRecord` and Synchronize:** logged at Information (single record) or Debug with a count in the sync summary, rather than a warning. When the order's certificate status says pending (`Pending for Approver`, `Approved by System` or `Order Accepted`), the record is returned as **pending**. `GetSingleRecord` reads that status from Track Order's `certificateState`, and the sync from the report's `certificateStatus`, which use the same text. Otherwise the record is returned as issued without a certificate body, as for any failed download. A later pass downloads the certificate once it exists.
- **Log fields:** the lines include CERTInext's `orderState` and `certificateState` text (for example `Approved by System` versus `Certificate Generated`) for diagnosis. Their vocabulary isn't documented, so the plugin acts on it only in the case above, and only to report pending rather than issued; an unrecognized value keeps the issued-without-body result.
- **Any other download error** is still logged as a warning.

#### V2 reissue

V2 has no *renew* endpoint, so `New`, `Renew`, and a `RenewOrReissue` inside the renewal window place a new order. An SSL/TLS reissue uses `POST /ssl-certificates/{orderId}/reissue` instead:

1. **When.** The enrollment type is `Reissue`, or `RenewOrReissue` with a prior certificate that hasn't expired and expires after `RenewalWindowDays`.
2. **Which order.** The plugin finds the prior order from `PriorCertSN` in the gateway database.
3. **What it sends.** `mode: rekey` with the new CSR, plus `additionalDomains` for a UCC order (the same SAN rules as create), and the reason "Reissued via Keyfactor Command AnyCA REST Gateway." The plugin always rekeys, because Command supplies a new CSR and gives no signal that only the SANs changed. It never uses `update-sans`.
4. **What comes back.** CERTInext creates a new order derived from the original, for example `1984857369R001`. That id is not numeric. It becomes the new certificate's `CARequestID`, and the usual post-create steps run on it: track, Subscriber Agreement, DCV, and pickup. The original order is left as it is.
5. **The previous certificate.** It stays valid unless `V2ReissueRevokePrevious` is `true`. Then the reissue also asks CERTInext to revoke it with reason `superseded`, and the intent is audit-logged before the call.

**Fallbacks:**
- **A new order is placed instead,** and the enrollment result says so, in three cases: no `PriorCertSN`, no matching order in the gateway, or a 404 or 422 from the reissue call (for example, the original is not `issued`).
- **Nothing is placed on a 5xx or a lost response.** The derived order may already exist. The enrollment fails with a "do not resubmit" message, as an order create does, and the next sync imports the order if it was created.
- **Private PKI and Document Signer** have no reissue endpoint in the spec, so they keep placing a new order.

**Not verified live:** this path is covered by unit and WireMock tests only.

### V2 Revocation Reason Handling

CERTInext's revoke endpoint accepts only a subset of its own documented reason enum. When Command's revoke reason maps to one CERTInext rejects, the plugin substitutes an accepted reason and retries once, rather than failing the revoke outright: CA-compromise and AA-compromise are retried as key-compromise; unspecified (Command's default when no reason is given), certificate-hold, and privilege-withdrawn are retried as cessation-of-operation. See [Revocation Reason Codes](#revocation-reason-codes) for the full accepted/rejected matrix.

{% include 'migration-v1-to-v2.md' %}
