## Overview

The CERTInext AnyCA Gateway REST plugin extends the certificate lifecycle capabilities of the CERTInext platform (by eMudhra) to Keyfactor Command via the Keyfactor AnyCA Gateway REST. The plugin represents a fully featured AnyCA REST plugin with the following capabilities:

* CA Synchronization:
    * Download all certificates issued through the CERTInext CA, either as a full inventory or incrementally since the last sync.
    * Expired certificates can optionally be excluded from synchronization using the `IgnoreExpired` configuration flag.
* Certificate Enrollment for profiles configured in CERTInext:
    * New certificate enrollment (new keys and certificate).
    * Certificate renewal via the CERTInext renew API when the prior certificate is within the configured renewal window.
    * Certificate reissuance (new keys with the same or updated subject/SANs) when outside the renewal window or no prior certificate is found.
* Certificate Revocation:
    * Request revocation of a previously issued certificate using any RFC 5280 CRL reason code.
* Supported authentication modes for calls to the CERTInext API:
    * AccessKey (HMAC-based request signing) — the primary and recommended mode
    * OAuth (bearer token via client credentials flow)

## Requirements

* Keyfactor Command 10.x or later
* AnyCA Gateway REST framework version 24.2.0 or later
* A CERTInext account with API access enabled and at least one certificate product configured
* Network connectivity from the AnyCA Gateway host to the CERTInext API endpoint for your region (see table below)
* The AnyCA Gateway host must trust the TLS certificate presented by the CERTInext API endpoint

### CERTInext Environments

CERTInext operates three separate environments. Use the sandbox environment for initial integration testing. Switch to a production environment only after all functionality has been verified.

| Environment | Portal Sign-in URL | API Base URL |
|---|---|---|
| Sandbox | https://sandbox-us.certinext.io/ | `https://sandbox-us-api.certinext.io/emSignHub-API/` |
| Production — India (Global) | https://in.certinext.io/ | `https://api.certinext.io/emSignHub-API/` |
| Production — US | https://us.certinext.io/ | `https://us-api.certinext.io/emSignHub-API/` |

> Note: Product codes differ between sandbox and production. Always confirm product codes from the GetProductDetails API call against the environment you are targeting before going live.

## CERTInext API Setup

### AccessKey (HMAC) — the primary auth mode

The CERTInext REST API uses HMAC-style request signing. Every API call includes a computed `authKey` field in the request body. The access key itself is never transmitted — only the derived hash is sent.

The `authKey` is computed as:

```
authKey = SHA256(accessKey + requestTs + requestTxnId)
```

Where `requestTs` is the ISO 8601 timestamp of the request and `requestTxnId` is the unique transaction ID generated per request. The gateway performs this computation automatically on every outbound API call.

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

### OAuth — alternative auth mode

If your CERTInext account has OAuth enabled, you can use OAuth client credentials as an alternative to AccessKey signing.

1. Log in to the CERTInext portal.
2. Navigate to **Integrations → APIs**.
3. Click **+ Create API Credentials**.
4. Set **API Type** to `REST` and **Auth Type** to `OAuth`.
5. Complete the form and click **Generate**.
6. Note the **Client ID** and **Client Secret**. Enter them in the `OAuthClientId` and `OAuthClientSecret` fields respectively.
7. Confirm the OAuth token endpoint URL with eMudhra and enter it in the `OAuthTokenUrl` field.
8. Set the `AuthMode` connector field to `OAuth`.

> Note: Credentials are stored in Keyfactor Command's encrypted gateway configuration and are never written to disk by the plugin.

## Gateway Registration

Before enrolling certificates, the Keyfactor Command server must trust the CERTInext issuing CA chain.

1. Log in to the CERTInext portal and download the root CA certificate and any intermediate CA certificates in the chain as PEM or DER files.
2. On the Keyfactor Command server, import those certificates into the appropriate Windows certificate store — **Trusted Root Certification Authorities** for the root CA and **Intermediate Certification Authorities** for any subordinate CAs.
3. In the Keyfactor Command Management Portal, navigate to **CA Connectors** and add a new CA using the **CERTInext AnyCA REST Gateway Plugin**.
4. Complete the CA connector configuration fields described in the next section, then save and test the connection. The gateway performs a live connectivity test against the CERTInext `ValidateCredentials` endpoint during validation.

## CA Configuration

The following fields are presented in the Keyfactor Command Management Portal when creating or editing the CERTInext CA connector. All fields marked **Required** must be provided before the connector can be saved in an enabled state.

| Field | Required / Optional | Description | Where to find it | Example |
|---|---|---|---|---|
| `ApiUrl` | Required | CERTInext API base URL for your environment. Must include the `/emSignHub-API/` path segment. No trailing slash is required but is accepted. | See the environments table above. | `https://api.certinext.io/emSignHub-API` |
| `AccountNumber` | Required | Your CERTInext account number (numeric string). Included in the `meta` block of every API request. | Portal → click your name or avatar → **Account Settings** or **My Profile**. | `1234567890` |
| `AuthMode` | Required | Authentication mode. `AccessKey` uses HMAC signing (recommended). `OAuth` uses a bearer token. | N/A — choose based on the credential type you created. | `AccessKey` |
| `ApiKey` | Conditional | The REST API Access Key generated in the CERTInext portal. Used to compute `authKey = SHA256(accessKey + ts + txn)`. The raw key is never transmitted. Required when `AuthMode` is `AccessKey`. This field is masked in the UI. | Portal → **Integrations → APIs** → generate or view the credential row. | *(generated, masked in UI)* |
| `OAuthTokenUrl` | Conditional | OAuth token endpoint URL. Required when `AuthMode` is `OAuth`. | Provided by eMudhra for your account. | `https://auth.certinext.io/oauth/token` |
| `OAuthClientId` | Conditional | OAuth client ID. Required when `AuthMode` is `OAuth`. | Portal → **Integrations → APIs** → the OAuth credential row. | `keyfactor-gateway` |
| `OAuthClientSecret` | Conditional | OAuth client secret. Required when `AuthMode` is `OAuth`. This field is masked in the UI. | Generated at OAuth credential creation time. | *(generated, masked in UI)* |
| `RequestorName` | Required | Default name of the person or service submitting certificate orders. Sent in the `requestorInformation` block of every order request. | Use the name of the team or automation account responsible for these certificates. | `PKI Automation` |
| `RequestorEmail` | Required | Default email address for the requestor. Must be a valid email address associated with your CERTInext account. Sent in the `requestorInformation` block of every order request. | Use a monitored team inbox or the account holder's email. | `pki-admin@example.com` |
| `RequestorIsdCode` | Optional | International dialing code for the requestor phone number (digits only, no `+` prefix). Default: `1` (United States). | N/A — use the country code for your requestor. | `1` |
| `RequestorMobileNumber` | Optional | Requestor mobile number (digits only, no country code). Included in the `requestorInformation` block. | N/A | `5551234567` |
| `SignerPlace` | Required | City or location of the person accepting the subscriber agreement on behalf of your organization. Required by CERTInext for all orders. | Use the physical city where the signer is located. | `Austin` |
| `SignerIp` | Required | Public IP address of the host accepting the subscriber agreement. Required by CERTInext for all orders. | Use the outbound IP of the AnyCA Gateway host, or the IP of the workstation from which the agreement was accepted. | `203.0.113.10` |
| `GroupNumber` | Optional | CERTInext group (delegation) number. When set, it is passed in the `productDetails.groupNumber` field of `GetProductDetails` requests. Some sandbox accounts return an empty product list from `GetProductDetails` unless this field is included. Available in the CERTInext portal under **Delegation → Groups**. | Portal → **Delegation → Groups**. | `2345678901` |
| `DefaultProductCode` | Optional | Default numeric product code to use when no product code is set on the certificate template. If omitted and the template also has no product code, enrollment will fail. Product codes are provisioned per account by eMudhra — contact your eMudhra account representative to obtain the numeric codes available to your account. | Call `GetProductDetails` against your account/environment (see product code table below). | `842` |
| `IgnoreExpired` | Optional | If `true`, expired certificates are skipped during synchronization and are not imported into Keyfactor Command. Default: `false`. | N/A | `false` |
| `PageSize` | Optional | Number of orders to retrieve per page during synchronization. Default: `100`. Maximum: `500`. Reduce this value if synchronization requests time out. | N/A | `100` |
| `Enabled` | Optional | Enables or disables the CA connector. Setting this to `false` allows the connector record to be created before all credentials are available, without triggering a live connectivity test. Default: `true`. | N/A | `true` |
| `DcvEnabled` | Optional | When `true`, the gateway performs DNS-based Domain Control Validation (DCV) during enrollment for orders that require it. Requires a DNS provider plugin (e.g. `azure-azuredns-dnsplugin`) to be deployed on the gateway. Default: `false`. | N/A | `false` |
| `DcvTxtRecordTemplate` | Optional | Format string for the DNS TXT record hostname published during DCV. `{0}` is replaced with the domain being validated. Default: `_emsign-validation.{0}`. | N/A | `_emsign-validation.{0}` |
| `DcvPropagationDelaySeconds` | Optional | Seconds to wait after publishing the DNS TXT record before asking CERTInext to verify it. Increase for zones with slow propagation. Default: `30`. | N/A | `30` |
| `DcvTimeoutMinutes` | Optional | Maximum minutes to wait for the entire DCV flow (DNS publish + propagation + verify) before cancelling the enrollment. Can also be set via the `CERTINEXT_DCV_TIMEOUT_MINUTES` environment variable; the environment variable takes precedence when both are set. Default: `10`. | N/A | `10` |

> Note: `AccountNumber` and group-level identifiers are distinct values. The `AccountNumber` is your top-level user account identifier. CERTInext groups (cost centers or departments) each have their own `groupNumber`, which is passed per-order and is separate from any organization number displayed on the Organizations page.

> Note: Only the credential fields that correspond to the selected `AuthMode` are evaluated at runtime. Fields belonging to the other auth mode are ignored.

## Certificate Template Creation Step

A Keyfactor Command certificate template maps an enrollment request to a specific CERTInext product. Create one template per CERTInext product that you want to make available to requesters.

In the Keyfactor Command Management Portal, navigate to **Certificate Templates** and create a new template associated with the CERTInext CA connector. The following enrollment parameters are available:

| Parameter | Required / Optional | Type | Description | Example / Default |
|---|---|---|---|---|
| `ProductCode` | Optional | String | Override the numeric CERTInext product code for this template. Product codes are provisioned per account by eMudhra — obtain the correct code from `GetProductDetails` for your account. Set this explicitly when targeting the sandbox environment or when the connector `DefaultProductCode` should not apply to this template. See the [Product Codes](#product-codes) section for the sandbox/production lookup table. | DV SSL: `842` (sandbox) or `838` (production) |
| `ProfileId` | Deprecated | String | Legacy alias for `ProductCode`. Accepted for backward compatibility — if `ProductCode` is not set, `ProfileId` is used in its place. New templates should use `ProductCode`. | `838` |
| `ValidityYears` | Optional | Number | Subscription validity period in years: `1`, `2`, or `3`. Default: `1`. CERTInext certificates are issued within a subscription term at up to 390 days per certificate, with free renewals within the term. | `1` |
| `ValidityDays` | Deprecated | Number | Legacy validity field. If set, the value is divided by 365 and rounded up to derive a year count. New templates should use `ValidityYears`. | `365` |
| `AutoApprove` | Optional | Boolean | If `true`, the gateway will attempt automatic approval of certificates returned in a pending-approval state. Only set this if your CERTInext product is configured with automatic approval. Default: `false`. | `false` |
| `RequesterName` | Optional | String | Per-template override for the requestor name. When set, overrides the connector-level `RequestorName` for orders using this template. | `Keyfactor Automation` |
| `RequesterEmail` | Optional | String | Per-template override for the requestor email address. When set, overrides the connector-level `RequestorEmail` for orders using this template. | `pki-admin@example.com` |
| `RenewalWindowDays` | Optional | Number | Number of days before certificate expiration within which a renewal is attempted instead of a reissue. Default: `90`. | `90` |
| `KeyType` | Optional | String | Key algorithm to request at enrollment time. Valid values depend on what the target product supports. If omitted, the product default is used. | `RSA2048`, `RSA4096`, `EC256`, `EC384` |
| `DomainName` | Optional | String | Primary domain name for SSL/TLS orders. If omitted, the gateway derives the domain from the CSR `CN` field. | `example.com` |
| `SignerName` | Optional | String | Per-template override for the subscriber agreement signer name. When omitted, defaults to the connector-level `RequestorName`. | `Jane Smith` |
| `SignerPlace` | Optional | String | Per-template override for the subscriber agreement signer location. When omitted, defaults to the connector-level `SignerPlace`. | `Austin` |
| `SignerIp` | Optional | String | Per-template override for the subscriber agreement signer IP address. When omitted, defaults to the connector-level `SignerIp`. | `203.0.113.10` |

## Product Codes

CERTInext uses numeric product codes to identify certificate types. **Product codes are provisioned per account by eMudhra** — the codes available to your account are determined when your account is set up. The codes in the tables below are the values observed on specific sandbox and production accounts; your account may have different codes.

To retrieve the exact codes available to your account, call the `GetProductDetails` endpoint:
- If you have a `GroupNumber` configured, include it in the request `productDetails` block — some accounts require this to return a non-empty list.
- Use the `make get-product-details-group` Makefile target to retrieve products from the sandbox with `groupNumber` included.

> Note: Product codes differ between the sandbox and production environments. Always verify the correct code before switching environments.

> Note: Product codes are per-account. If you receive "Invalid Product Code" (EMS-1162) when placing an order, your account does not have that product provisioned. Contact your eMudhra account representative to request provisioning of the product codes you need.

### SSL/TLS

The product codes in this table were observed on:
- the US sandbox environment (`sandbox-us-api.certinext.io`) in April–May 2026
- the Production India environment (`api.certinext.io`) via the live draft-order coverage matrix in [development.md](development.md)

**Your account may still have different codes.** Always call `GetProductDetails` against your target environment before going live.

| Product | Sandbox Code | Production Code | Required fields beyond base (`domainName`, `csr`, `requestorInformation`, `subscriptionDetails`, `agreementDetails`) |
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

> Note: SSL/TLS codes appear to be offset by 4 between the US sandbox and Production India in the snapshots we've observed — but treat that as a coincidence, not a guarantee. eMudhra controls the per-account mapping and may use different numeric codes for any new account. Always confirm via `GetProductDetails`.

> Note: The CERTInext portal may display additional short-validity products (e.g. **DV SSL Certificate 1 Month**, **DV SSL Certificate Wildcard 1 Month**) that do not appear in the `GetProductDetails` API response and have no published product code. These products are not accessible via the API and are therefore **not supported by this plugin**. Contact eMudhra to determine whether API ordering is available for these products on your account.

### Private PKI

| Product | Sandbox Code | Production Code | Availability |
|---|---|---|---|
| emSign Intranet SSL 1 year | `149` | `100` | Requires special provisioning by eMudhra. Not orderable on standard accounts. |
| IGTF Host 1 year | (not observed) | `104` | Requires special provisioning by eMudhra. Not orderable on standard accounts. |

> Note: Private PKI products are not available for ordering on standard CERTInext accounts. Attempting to place an order will return EMS-1162 (product not provisioned). The sandbox Private PKI code (`149`) also returns EMS-1162 on standard sandbox accounts even though it appears in the `GetProductDetails` list. Contact eMudhra to have these products enabled on your account.

### S/MIME and Document Signing

The same numeric product codes have been observed for S/MIME and document-signing products on both the US sandbox and Production India in the snapshots we have. **Treat that as an empirical observation, not a contract** — eMudhra is free to assign different codes per account. Always confirm via `GetProductDetails`.

| Product | Sandbox / Production Code | Availability |
|---|---|---|
| S/MIME | `894` | Requires a separate S/MIME entitlement on the account. Not available on standard SSL accounts. |
| Natural Person Doc Signer (tier 1) | `825` | Requires document signing entitlement. Not orderable on standard accounts. |
| Natural Person Doc Signer (tier 2) | `826` | Requires document signing entitlement. Not orderable on standard accounts. |
| Natural Person Doc Signer (tier 3) | `827` | Requires document signing entitlement. Not orderable on standard accounts. |
| Legal Person Doc Signer (tier 1) | `822` | Requires document signing entitlement. Not orderable on standard accounts. |
| Legal Person Doc Signer (tier 2) | `823` | Requires document signing entitlement. Not orderable on standard accounts. |
| Legal Person Doc Signer (tier 3) | `824` | Requires document signing entitlement. Not orderable on standard accounts. |
| Legal Entity Doc Signer (tier 1) | `819` | Requires document signing entitlement. Not orderable on standard accounts. |
| Legal Entity Doc Signer (tier 2) | `820` | Requires document signing entitlement. Not orderable on standard accounts. |
| Legal Entity Doc Signer (tier 3) | `821` | Requires document signing entitlement. Not orderable on standard accounts. |

> Note: S/MIME (894) and document signing products (819–827) require a separate entitlement that is not included in a standard SSL/TLS account. Contact eMudhra to request access.

To retrieve the full list of product codes available to your account, call the `GetProductDetails` endpoint against your target environment. The sandbox and production APIs each return their own set of codes.

> Note: SSL/TLS products are supported on standard accounts — see the SSL/TLS table above for the exact sandbox/production code pair for each product. Private PKI (Production `100`, `104` / Sandbox `149`), S/MIME (`894`), and document-signing products (`819`–`827`) require special provisioning by eMudhra and are not available on standard SSL/TLS accounts — ordering them returns EMS-1162.


## Mechanics

### Authentication

Every CERTInext API call is an HTTP POST with a JSON body. There is no Authorization header. Instead, the body carries a `meta` block with an `authKey` field computed as:

```
authKey = SHA256(accessKey + requestTs + requestTxnId)
```

Where `requestTs` is the ISO 8601 timestamp and `requestTxnId` is a unique transaction UUID generated per request. The raw access key is never transmitted — only the derived hash is sent. This computation happens automatically on every outbound call. When `AuthMode` is `OAuth`, the gateway obtains a bearer token via the configured client credentials flow and injects it into the `meta` block instead.

### Enrollment Decision Logic

When the gateway calls `Enroll`, the plugin selects between three paths based on the enrollment type and the age of the prior certificate:

1. **New enrollment** — no prior certificate exists. A new `GenerateOrderSSL` request is submitted.
2. **Renewal** — a prior certificate exists and its expiry is within the `RenewalWindowDays` threshold (default: 90 days). The plugin calls the CERTInext renew API, which reuses the existing subscription term.
3. **Reissue** — a prior certificate exists but is outside the renewal window. A new order is placed with the updated CSR/subject, replacing the prior certificate under a new subscription.

The `RenewalWindowDays` template parameter controls the renewal/reissue boundary per certificate template.

### Required Order Fields

The `GenerateOrderSSL` API requires an `additionalInformation.remarks` field in every order request body. The gateway populates this field automatically with the text `"Issued via Keyfactor Command AnyCA REST Gateway."`. If you encounter error `EMS-918: Additional Information cannot be empty`, verify that the gateway version is current and that the field is being sent.

### Order Lifecycle and Pending Approval

CERTInext orders pass through several internal status stages before a certificate is issued. The plugin maps these to Keyfactor enrollment statuses as follows:

- **Issued** (status 9, 20) → certificate returned immediately.
- **Pending approval** (status 2, 8, 15, 24) → enrollment returns a pending status to Command. If `AutoApprove` is enabled on the template, the plugin attempts automatic approval before returning.
- **Rejected / cancelled** (status 4, 5, 13, 14) → enrollment fails with an error.

The gateway polls the `TrackOrder` endpoint during sync to pick up certificates that were approved after the initial enrollment call.

### Synchronization

Synchronization uses the `GetOrderReport` endpoint with paginated results (controlled by `PageSize`, default 100, max 500). Each page is fetched sequentially until all orders are retrieved. The plugin maps each order's status to a Keyfactor certificate status and returns the result set to the gateway framework, which reconciles it against the Command inventory.

Expired certificates are included by default. Set `IgnoreExpired: true` on the connector to skip them during sync.

### Product Code Resolution

When an enrollment request arrives, the numeric CERTInext product code is resolved in this order:

1. `ProductCode` template parameter (explicit override — use for sandbox or non-standard codes).
2. `ProfileId` template parameter (deprecated alias, accepted for backward compatibility).
3. Default production code looked up from the selected product name (e.g. **DV SSL** → `838`).

If none of these yield a code, enrollment fails with a validation error.

{% include 'architecture.md' %}
