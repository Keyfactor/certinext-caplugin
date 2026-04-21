<h1 align="center" style="border-bottom: none">
    CERTInext AnyCA Gateway REST Plugin
</h1>

<p align="center">
  <!-- Badges -->
<img src="https://img.shields.io/badge/integration_status-prototype-3D1973?style=flat-square" alt="Integration Status: prototype" />
<a href="https://github.com/Keyfactor/certinext-caplugin/releases"><img src="https://img.shields.io/github/v/release/Keyfactor/certinext-caplugin?style=flat-square" alt="Release" /></a>
<img src="https://img.shields.io/github/issues/Keyfactor/certinext-caplugin?style=flat-square" alt="Issues" />
<img src="https://img.shields.io/github/downloads/Keyfactor/certinext-caplugin/total?style=flat-square&label=downloads&color=28B905" alt="GitHub Downloads (all assets, all releases)" />
</p>

<p align="center">
  <!-- TOC -->
  <a href="#support">
    <b>Support</b>
  </a> 
  ·
  <a href="#requirements">
    <b>Requirements</b>
  </a>
  ·
  <a href="#installation">
    <b>Installation</b>
  </a>
  ·
  <a href="#license">
    <b>License</b>
  </a>
  ·
  <a href="https://github.com/orgs/Keyfactor/repositories?q=anycagateway">
    <b>Related Integrations</b>
  </a>
</p>


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

## Compatibility

The CERTInext AnyCA Gateway REST plugin is compatible with the Keyfactor AnyCA Gateway REST 24.2.0 and later.

## Support
The CERTInext AnyCA Gateway REST plugin is open source and there is **no SLA**. Keyfactor will address issues as resources become available. Keyfactor customers may request escalation by opening up a support ticket through their Keyfactor representative. 

> To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.

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

## Installation

1. Install the AnyCA Gateway REST per the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/InstallIntroduction.htm).

2. On the server hosting the AnyCA Gateway REST, download and unzip the latest [CERTInext AnyCA Gateway REST plugin](https://github.com/Keyfactor/certinext-caplugin/releases/latest) from GitHub.

3. Copy the unzipped directory (usually called `net6.0` or `net8.0`) to the Extensions directory:


    ```shell
    Depending on your AnyCA Gateway REST version, copy the unzipped directory to one of the following locations:
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net6.0\Extensions
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net8.0\Extensions
    ```

    > The directory containing the CERTInext AnyCA Gateway REST plugin DLLs (`net6.0` or `net8.0`) can be named anything, as long as it is unique within the `Extensions` directory.

4. Restart the AnyCA Gateway REST service.

5. Navigate to the AnyCA Gateway REST portal and verify that the Gateway recognizes the CERTInext plugin by hovering over the ⓘ symbol to the right of the Gateway on the top left of the portal.

## Configuration

1. Follow the [official AnyCA Gateway REST documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Gateway.htm) to define a new Certificate Authority, and use the notes below to configure the **Gateway Registration** and **CA Connection** tabs:

    * **Gateway Registration**

        Before enrolling certificates, the Keyfactor Command server must trust the CERTInext issuing CA chain.

        1. Log in to the CERTInext portal and download the root CA certificate and any intermediate CA certificates in the chain as PEM or DER files.
        2. On the Keyfactor Command server, import those certificates into the appropriate Windows certificate store — **Trusted Root Certification Authorities** for the root CA and **Intermediate Certification Authorities** for any subordinate CAs.
        3. In the Keyfactor Command Management Portal, navigate to **CA Connectors** and add a new CA using the **CERTInext AnyCA REST Gateway Plugin**.
        4. Complete the CA connector configuration fields described in the next section, then save and test the connection. The gateway performs a live connectivity test against the CERTInext `ValidateCredentials` endpoint during validation.

    * **CA Connection**

        Populate using the configuration fields collected in the [requirements](#requirements) section.

        * **ApiUrl** - REQUIRED: CERTInext API base URL. Sandbox (US): https://sandbox-us-api.certinext.io/emSignHub-API/ — Production (US): https://us-api.certinext.io/ — Production (Global/India): https://api.certinext.io/ 
        * **AccountNumber** - REQUIRED: Your CERTInext account number (numeric string). Available in the CERTInext portal. 
        * **AuthMode** - REQUIRED: Authentication mode. 'AccessKey' (default) — uses authKey = SHA256(accessKey + ts + txn) in every request body. 'OAuth' — uses an OAuth2 bearer token (requires OAuthTokenUrl, OAuthClientId, OAuthClientSecret). 
        * **ApiKey** - REQUIRED when AuthMode is 'AccessKey': the REST API Access Key generated in the CERTInext portal under Integrations → APIs. This value is used to compute authKey = SHA256(accessKey + ts + txn); it is never transmitted directly. 
        * **OAuthTokenUrl** - OAuth token endpoint URL. Required when AuthMode is 'OAuth'. 
        * **OAuthClientId** - OAuth client ID. Required when AuthMode is 'OAuth'. 
        * **OAuthClientSecret** - OAuth client secret. Required when AuthMode is 'OAuth'. 
        * **RequestorName** - REQUIRED: Default requestor name submitted with all certificate orders. This is the name of the person/service responsible for the certificates. 
        * **RequestorEmail** - REQUIRED: Default requestor email submitted with all certificate orders. Must be a valid email address registered in your CERTInext account. 
        * **RequestorIsdCode** - International dialing code for the requestor phone number (e.g. '1' for US). Default: '1'. 
        * **RequestorMobileNumber** - Requestor mobile number (digits only, no country code). 
        * **SignerPlace** - City or location of the subscriber agreement signer. Required by CERTInext for all orders. 
        * **SignerIp** - IP address of the subscriber agreement signer. Required by CERTInext for all orders. 
        * **DefaultProductCode** - OPTIONAL: Default numeric product code used when not specified at template level. Product codes are provided by eMudhra (e.g. the SSL DV 1-year code for your account). Retrieve available codes from Integrations → APIs → GetProductDetails. 
        * **IgnoreExpired** - If true, expired certificates will be skipped during synchronization. Default: false. 
        * **PageSize** - Number of orders to fetch per page during synchronization. Default: 100, max: 500. 
        * **Enabled** - Flag to Enable or Disable gateway functionality. Disabling is primarily used to allow creation of the CA connector prior to configuration information being available. 

2. TODO Certificate Template Creation Step is a required section

3. Follow the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Keyfactor.htm) to add each defined Certificate Authority to Keyfactor Command and import the newly defined Certificate Templates.

4. In Keyfactor Command (v12.3+), for each imported Certificate Template, follow the [official documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/Configuring%20Template%20Options.htm) to define enrollment fields for each of the following parameters:

    * **ProductCode** - REQUIRED: The numeric CERTInext product code for this certificate type (e.g. '844' for DV SSL 1-year). Provided by eMudhra for your account. Overrides the connector-level DefaultProductCode when set. 
    * **ProfileId** - DEPRECATED: Use ProductCode instead. Kept for backward compatibility — mapped to ProductCode if ProductCode is not set. 
    * **ValidityYears** - OPTIONAL: Subscription validity in years: 1, 2, or 3. Default: 1. Note: CERTInext validates per 390-day certificate within the subscription; the 'validity' field in the order is the subscription term, not certificate lifetime. 
    * **ValidityDays** - DEPRECATED: Use ValidityYears instead. If set, value is divided by 365 and rounded up to get the subscription year count. 
    * **AutoApprove** - OPTIONAL: If true, the gateway will attempt automatic approval of certificates that are returned in a pending-approval state. Default: false. 
    * **RequesterName** - OPTIONAL: Default requester name to include in the enrollment request. Used when no requester name can be derived from the subject. 
    * **RequesterEmail** - OPTIONAL: Default requester email address. Used when no email can be derived from the subject. 
    * **RenewalWindowDays** - OPTIONAL: Number of days before expiration within which a renewal is attempted instead of a reissue. Default: 90. 
    * **KeyType** - OPTIONAL: Key algorithm to request (e.g. 'RSA2048', 'RSA4096', 'EC256', 'EC384'). If omitted, the profile default is used. 


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

## CA Configuration

The following fields are presented in the Keyfactor Command Management Portal when creating or editing the CERTInext CA connector. All fields marked **Required** must be provided before the connector can be saved in an enabled state.

| Field | Required / Optional | Description | Where to find it | Example |
|---|---|---|---|---|
| `ApiUrl` | Required | CERTInext API base URL for your environment. Must include the `/emSignHub-API/` path segment. No trailing slash is required but is accepted. | See the environments table above. | `https://api.certinext.io/emSignHub-API` |
| `AccountNumber` | Required | Your CERTInext account number (numeric string). Included in the `meta` block of every API request. | Portal → click your name or avatar → **Account Settings** or **My Profile**. | `4461259728` |
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
| `DefaultProductCode` | Optional | Default numeric product code to use when no product code is set on the certificate template. If omitted and the template also has no product code, enrollment will fail. | Portal → **Integrations → APIs** → call `GetProductDetails`, or refer to the product code table below. | `100` |
| `IgnoreExpired` | Optional | If `true`, expired certificates are skipped during synchronization and are not imported into Keyfactor Command. Default: `false`. | N/A | `false` |
| `PageSize` | Optional | Number of orders to retrieve per page during synchronization. Default: `100`. Maximum: `500`. Reduce this value if synchronization requests time out. | N/A | `100` |
| `Enabled` | Optional | Enables or disables the CA connector. Setting this to `false` allows the connector record to be created before all credentials are available, without triggering a live connectivity test. Default: `true`. | N/A | `true` |

> Note: `AccountNumber` and group-level identifiers are distinct values. The `AccountNumber` is your top-level user account identifier. CERTInext groups (cost centers or departments) each have their own `groupNumber`, which is passed per-order and is separate from any organization number displayed on the Organizations page.

> Note: Only the credential fields that correspond to the selected `AuthMode` are evaluated at runtime. Fields belonging to the other auth mode are ignored.

## Certificate Template Creation

A Keyfactor Command certificate template maps an enrollment request to a specific CERTInext product. Create one template per CERTInext product that you want to make available to requesters.

In the Keyfactor Command Management Portal, navigate to **Certificate Templates** and create a new template associated with the CERTInext CA connector. The following enrollment parameters are available:

| Parameter | Required / Optional | Type | Description | Example / Default |
|---|---|---|---|---|
| `ProductCode` | Required | String | The numeric CERTInext product code for the type of certificate to issue (e.g. `838` for DV SSL). Overrides the connector-level `DefaultProductCode` when set. See the product code table below. | `838` |
| `ProfileId` | Deprecated | String | Legacy alias for `ProductCode`. Accepted for backward compatibility — if `ProductCode` is not set, `ProfileId` is used in its place. New templates should use `ProductCode`. | `838` |
| `ValidityYears` | Optional | Number | Subscription validity period in years: `1`, `2`, or `3`. Default: `1`. CERTInext certificates are issued within a subscription term at up to 390 days per certificate, with free renewals within the term. | `1` |
| `ValidityDays` | Deprecated | Number | Legacy validity field. If set, the value is divided by 365 and rounded up to derive a year count. New templates should use `ValidityYears`. | `365` |
| `AutoApprove` | Optional | Boolean | If `true`, the gateway will attempt automatic approval of certificates returned in a pending-approval state. Only set this if your CERTInext product is configured with automatic approval. Default: `false`. | `false` |
| `RequesterName` | Optional | String | Per-template override for the requestor name. When set, overrides the connector-level `RequestorName` for orders using this template. | `Keyfactor Automation` |
| `RequesterEmail` | Optional | String | Per-template override for the requestor email address. When set, overrides the connector-level `RequestorEmail` for orders using this template. | `pki-admin@example.com` |
| `RenewalWindowDays` | Optional | Number | Number of days before certificate expiration within which a renewal is attempted instead of a reissue. Default: `90`. | `90` |
| `KeyType` | Optional | String | Key algorithm to request at enrollment time. Valid values depend on what the target product supports. If omitted, the product default is used. | `RSA2048`, `RSA4096`, `EC256`, `EC384` |
| `DomainName` | Optional | String | Primary domain name for SSL/TLS orders. If omitted, the gateway derives the domain from the CSR `CN` field. | `example.com` |
| `SANFormat` | Optional | String | Controls how Subject Alternative Names from the CSR are formatted in the order request. Refer to plugin documentation for valid values. | *(see plugin docs)* |
| `SignerName` | Optional | String | Per-template override for the subscriber agreement signer name. When omitted, defaults to the connector-level `RequestorName`. | `Jane Smith` |
| `SignerPlace` | Optional | String | Per-template override for the subscriber agreement signer location. When omitted, defaults to the connector-level `SignerPlace`. | `Austin` |
| `SignerIp` | Optional | String | Per-template override for the subscriber agreement signer IP address. When omitted, defaults to the connector-level `SignerIp`. | `203.0.113.10` |

## Product Codes

CERTInext uses numeric product codes to identify certificate types. The codes below are representative values returned from the `GetProductDetails` API; the exact codes available to your account may differ. Always confirm codes from a live `GetProductDetails` call against your target environment.

> Note: Product codes differ between the sandbox and production environments. Always verify the correct code before switching environments.

### SSL/TLS

| Product | Product Code | Required fields beyond base (`domainName`, `csr`, `requestorInformation`, `subscriptionDetails`, `agreementDetails`) |
|---|---|---|
| DV (Domain Validated) | `838` | None. `domainName` is derived from the CSR CN if omitted on the template. |
| DV Wildcard | `839` | CSR CN must use wildcard format (e.g. `*.example.com`). `domainName` in the order must also use the wildcard format (e.g. `*.example.com`). |
| DV UCC (Multi-domain) | `840` | `certificateInformation.additionalDomains` — array of additional SAN values beyond the primary `domainName`. |
| OV (Organization Validated) | `842` | `organizationDetails.organizationNumber` (your CERTInext org ID); `certificateInformation.locality`, `postalCode`, and full organization address fields (`streetAddress`, `city`, `state`, `country`). |
| OV Wildcard | `843` | Same as OV (842). CSR CN and `domainName` must use wildcard format. |
| OV UCC (Multi-domain) | `844` | Same as OV (842) plus `certificateInformation.additionalDomains`. |
| EV (Extended Validation) | `846` | All OV fields plus: `contractSignerInfo` object (`name`, `email`, `isdCode`, `mobileNumber`, `designation`, `employeeID`); `certificateApproverInfo` object (same fields); `certificateInformation.companyRegistrationNumber`; `streetAddress2` must be non-empty. |

### Private PKI

| Product | Product Code | Availability |
|---|---|---|
| emSign Intranet SSL 1 year | `100` | Requires special provisioning by eMudhra. Not orderable on standard accounts. |
| IGTF Host 1 year | `104` | Requires special provisioning by eMudhra. Not orderable on standard accounts. |

> Note: Private PKI products (codes 100, 104) are not available for ordering on standard CERTInext accounts. Attempting to place an order will return an error (EMS-1162: product not provisioned). Contact eMudhra to have these products enabled on your account.

### S/MIME and Document Signing

| Product | Product Code | Availability |
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

> Note: SSL/TLS products (codes 838–846) are supported on standard accounts. Private PKI (100, 104), S/MIME (894), and document-signing products (819–827) require special provisioning by eMudhra and are not available on standard SSL/TLS accounts — ordering them returns EMS-1162.


## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor Any CA Gateways (REST)](https://github.com/orgs/Keyfactor/repositories?q=anycagateway).