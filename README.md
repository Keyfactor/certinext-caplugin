<h1 align="center" style="border-bottom: none">
    CERTInext AnyCA Gateway REST Plugin
</h1>

<p align="center">
  <!-- Badges -->
<img src="https://img.shields.io/badge/integration_status-production-3D1973?style=flat-square" alt="Integration Status: production" />
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
    * Certificate renewal — submits a new `GenerateOrderSSL` order when the prior certificate is within the configured renewal window (CERTInext has no dedicated renewal endpoint; the renewal-window check governs how Command tracks old→new, not which API is called).
    * Certificate reissuance (new keys with the same or updated subject/SANs) when outside the renewal window or no prior certificate is found.
    * Synchronous certificate pickup — a fast-issuing order (DV, or already-approved) can return the certificate in the same enrollment call instead of always waiting for the next sync, via `PickupRetries`/`PickupDelay`. Renewals use the same pickup; on a DCV build with `DcvEnabled`, a renewal still pending DNS-01 validation returns pending at once and the next sync completes it.
* Certificate Revocation:
    * Request revocation of a previously issued certificate using any RFC 5280 CRL reason code.
* Supported authentication modes for calls to the CERTInext API:
    * AccessKey (HMAC-based request signing) — the primary and recommended mode
    * OAuth (bearer token via client credentials flow)

## Compatibility

The CERTInext AnyCA Gateway REST plugin is compatible with the Keyfactor AnyCA Gateway REST 25.5.0 and later.

## Support
The CERTInext AnyCA Gateway REST plugin is supported by Keyfactor for Keyfactor customers. If you have a support issue, please open a support ticket via the Keyfactor Support Portal at https://support.keyfactor.com.

> To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.

## Requirements

* Keyfactor Command 25.5.x or later
* AnyCA Gateway REST framework version 25.5.0 or later
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

3. Copy the unzipped directory (usually called `net8.0` or `net10.0`) to the Extensions directory:


    ```shell
    Depending on your AnyCA Gateway REST version, copy the unzipped directory to one of the following locations:
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net8.0\Extensions
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net10.0\Extensions
    ```

    > The directory containing the CERTInext AnyCA Gateway REST plugin DLLs (`net8.0` or `net10.0`) can be named anything, as long as it is unique within the `Extensions` directory.

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

        | Field | Required | Description | Example |
        |---|---|---|---|
        | `ApiUrl` | Required | CERTInext API base URL. Sandbox (US): https://sandbox-us-api.certinext.io/emSignHub-API/ — Production (US): https://us-api.certinext.io/emSignHub-API/ — Production (Global/India): https://api.certinext.io/emSignHub-API/ | https://sandbox-us-api.certinext.io/emSignHub-API/ |
        | `AccountNumber` | Required | Your CERTInext account number (numeric string). Available in the CERTInext portal. |  |
        | `GroupNumber` | Optional | CERTInext group (delegation) number. When set, it is included in GetProductDetails requests AND in the `orderDetails.groupNumber` field of every SSL order (new and renewal) so the order is routed to the configured account group. When blank, CERTInext uses the account's default group. Available in the CERTInext portal under Delegation → Groups. |  |
        | `OrganizationNumber` | Optional | Numeric CERTInext organization number for a pre-vetted organization. When set, every SSL order is submitted with `organizationDetails.preVetting="1"` and this `organizationNumber`, so CERTInext can reuse that organization's pre-verified domains without fresh DCV. Leave blank to omit `organizationDetails`. Available in the CERTInext portal under Organizations → Pre-vetted Organizations. |  |
        | `TechnicalContactName` | Optional | Technical point of contact name, sent as `technicalPointOfContact.pocFirstName` / `pocLastName` on every SSL order (new and renewal). The name is split on the first whitespace: the first word is the first name and the rest is the last name; a single-word name is sent in both. Defaults to the configured RequestorName when blank. If no contact name or no email resolves (including from RequestorName/RequestorEmail), the whole technicalPointOfContact block is omitted from the order and a Warning is logged, since CERTInext requires both inside the block. |  |
        | `TechnicalContactEmail` | Optional | Email sent in the `technicalPointOfContact.pocEmail` field of every SSL order. Defaults to the configured RequestorEmail when blank. If no contact name or no email resolves (including from RequestorName/RequestorEmail), the whole technicalPointOfContact block is omitted from the order and a Warning is logged, since CERTInext requires both inside the block. |  |
        | `TechnicalContactIsdCode` | Optional | International dialing code for the technical contact phone number, sent as `technicalPointOfContact.pocIsdCode`. Defaults to the configured RequestorIsdCode when blank. |  |
        | `TechnicalContactMobileNumber` | Optional | Mobile number for the technical contact (digits only), sent as `technicalPointOfContact.pocMobileNumber`. Defaults to the configured RequestorMobileNumber when blank. |  |
        | `AuthMode` | Required | Authentication mode. 'AccessKey' (default) — uses authKey = SHA256(accessKey + ts + txn) in every request body. 'OAuth' — uses an OAuth2 bearer token (requires OAuthTokenUrl, OAuthClientId, OAuthClientSecret). | AccessKey |
        | `ApiKey` | Conditional | The REST API Access Key generated in the CERTInext portal under Integrations → APIs. This value is used to compute authKey = SHA256(accessKey + ts + txn); it is never transmitted directly. |  |
        | `OAuthTokenUrl` | Conditional | OAuth token endpoint URL. Required when AuthMode is 'OAuth'. |  |
        | `OAuthClientId` | Conditional | OAuth client ID. Required when AuthMode is 'OAuth'. |  |
        | `OAuthClientSecret` | Conditional | OAuth client secret. Required when AuthMode is 'OAuth'. |  |
        | `RequestorName` | Required | Default requestor name submitted with all certificate orders. This is the name of the person/service responsible for the certificates. |  |
        | `RequestorEmail` | Required | Default requestor email submitted with all certificate orders. Must be a valid email address registered in your CERTInext account. |  |
        | `RequestorIsdCode` | Optional | International dialing code for the requestor phone number (e.g. '1' for US). Default: '1'. | 1 |
        | `RequestorMobileNumber` | Optional | Requestor mobile number (digits only, no country code). |  |
        | `SignerPlace` | Optional | City or location of the subscriber agreement signer. Required by CERTInext for all orders. A template SignerPlace overrides it. If neither is set, the placeholder "Gateway" is sent and a Warning is logged; set it so the agreement audit record is accurate. |  |
        | `SignerIp` | Optional | IP address of the subscriber agreement signer. Required by CERTInext for all orders. A template SignerIp overrides it. If neither is set, the placeholder 127.0.0.1 is sent and a Warning is logged. A value that is not an IP address is still sent unchanged, with a Warning. | 127.0.0.1 |
        | `DefaultProductCode` | Optional | Connector-level fallback product code. Enroll and renewal do not use it: the template must resolve a product code (ProductCode, ProfileId, or the built-in code for the selected product name), otherwise enrollment is rejected with "Template parameter 'ProfileId' is required." Set ProductCode on the template instead. Product codes are provided by eMudhra. Retrieve available codes from Integrations → APIs → GetProductDetails. |  |
        | `AccountingModel` | Optional | CERTInext billing model sent in `orderDetails.accountingModel`. "2" = credit-based (most accounts, default). "1" = cash model. | 2 |
        | `EmailNotifications` | Optional | Whether CERTInext sends lifecycle-event emails to the requestor. "1" = enabled, "0" = silent (recommended for gateway-driven orders so end users aren't surprised by CA emails). Default: "0". | 0 |
        | `SubscriptionValidityYears` | Optional | Default validity in years for SSL orders. "1", "2", or "3". Used when the template sets neither ValidityYears nor ValidityDays; a template value overrides it. Default: "1". | 1 |
        | `SubscriptionAutoRenew` | Optional | Whether CERTInext should auto-renew certificates issued through this connector. "0" = disabled (recommended — renewal is driven by Keyfactor Command), "1" = enabled. Default: "0". | 0 |
        | `SubscriptionRenewCriteriaDays` | Optional | Days before expiry at which CERTInext auto-renews (only honored when SubscriptionAutoRenew = "1"). Typical values: "30" or "60". Default: "30". | 30 |
        | `AutoSecureWww` | Optional | Sent as `orderDetails.autoSecureWWW` on every SSL order (new and renewal). If "1", CERTInext automatically adds the `www.` variant of the primary domain as an additional SAN, which must also pass domain validation. "0" = use only the CN/SANs supplied with the CSR. Default: "0". | 0 |
        | `IgnoreExpired` | Optional | If true, expired certificates will be skipped during synchronization. Default: false. | false |
        | `SubmitNonDnsSans` | Optional | If true (default), SANs that are not DNS names (IP address, email, URI) are submitted to CERTInext in additionalDomains along with the DNS names. CERTInext registers them verbatim as order domains and they cannot pass domain validation, so such an order will not issue until they are removed — but nothing the subscriber requested is dropped silently. Set to false to submit DNS names only, which restores the pre-1.0.1 behaviour: the order issues, but the certificate will not contain the non-DNS names. Default: true. | true |
        | `PageSize` | Optional | Number of orders to fetch per page during synchronization. Default: 100, max: 500. | 100 |
        | `Enabled` | Optional | Enables or disables the CA connector. Set to false to create the connector record before credentials are available. Default: true. | true |
        | `LogSensitiveRequestData` | Optional | Diagnostic escape hatch. When true, requestor personal data (name, email, phone, and other organization contact details) and full CA request/response payloads are written to the gateway logs: the Trace-level order request/response bodies and the API-failure response bodies are left unredacted (beyond the credential scrubbing that always applies), SAN values and CA error text are logged unmasked, and the Information-level enrollment-attempt log line includes the requestor's name and email in full. A startup Warning is logged whenever it is on. This is meant for temporary use while verifying a new deployment — confirming exactly what was sent to the CA and that the order succeeded — and should be turned back off once verification is complete. When false (default), personal data fields are redacted to '***REDACTED***' (email is masked but keeps its domain, e.g. 'j***@example.com'), email SAN values and email addresses in CA error text are masked the same way, mailto:/sip:-style URI SANs are masked and 'user:pw@' userinfo in URI SANs is replaced with '***', and the enrollment log line omits the requester name entirely. DNS and IP SANs are always logged in full. Credentials (the values of the authKey, client_secret, apiKey, accessKey and password fields, and Authorization header lines) are always redacted from logged request/response bodies regardless of this setting. Default: false. | false |
        | `PickupRetries` | Optional | Number of times Enroll() will poll CERTInext to download the certificate after a successful order submission. If the certificate has not issued within this window it is picked up during the next synchronization instead. Set to 0 to disable the wait; values are clamped to 0-30. Default: 5. NOTE: CERTInext issues OV/EV certificates asynchronously (organization verification, minutes to hours), so those typically exhaust the wait and are returned pending regardless of this value. On the DCV build, an order that DNS-01 DCV engages for uses the DCV waits (DcvWaitForIssuanceSeconds) instead of this pickup. | 5 |
        | `PickupDelay` | Optional | Number of seconds between certificate-pickup retries. PickupRetries times this delay (plus a short initial delay) is the maximum time an enrollment call occupies a Command worker thread. If the duration is too long the request may time out, so target a total well under ~90s. As a safety backstop the plugin additionally caps the effective total at 180s regardless of how PickupRetries/PickupDelay are set, reducing the retry count to fit. Values are clamped to 1-60; a non-positive value uses the default. Default: 10 (with default retries this yields a ~55s ceiling). | 10 |
        | `DcvEnabled` | Optional | When true, the gateway will perform DNS-based Domain Control Validation (DCV) during enrollment for orders that require it, using the configured DNS provider plugin. Requires a DNS provider plugin (e.g. azure-azuredns-dnsplugin) to be deployed on the gateway. On the default (non-DCV) build there is no DNS validation support, so setting this only logs a startup Warning. Default: false. | false |
        | `DcvTxtRecordTemplate` | Optional | Format string for the DNS TXT record hostname used during DCV. {0} is replaced with the domain name being validated. Default: _emsign-validation.{0} | _emsign-validation.{0} |
        | `DcvPropagationDelaySeconds` | Optional | Seconds to wait after publishing the DNS TXT record before asking CERTInext to verify it. Increase for zones with slow propagation. Default: 30. | 30 |
        | `DcvTimeoutMinutes` | Optional | Maximum minutes to wait for the entire DCV flow (DNS publish + propagation + verify) before timing out the enrollment. Can also be set via the CERTINEXT_DCV_TIMEOUT_MINUTES environment variable; the env var takes precedence when both are set. Default: 10. | 10 |
        | `DcvWaitForChallengeSeconds` | Optional | How long (seconds) the plugin will wait inside Enroll() for CERTInext to expose the DCV challenge (i.e. populate `domainVerification` in TrackOrder). Under concurrent load CERTInext sometimes takes a few seconds after GenerateOrderSSL before the slot appears. Without this wait, the plugin's initial TrackOrder check sees null and skips DCV — the order then has to wait for the next gateway sync cycle to be picked up. Setting to 0 disables the wait (single-check behaviour). Can also be set via the CERTINEXT_DCV_WAIT_FOR_CHALLENGE_SECONDS environment variable; the env var takes precedence when both are set. Default: 60. | 60 |
        | `DcvWaitForIssuanceSeconds` | Optional | How long (seconds) the plugin will wait inside Enroll() after DCV verifies for CERTInext to finish generating the certificate. CERTInext issuance is async — DCV may be verified but the cert PEM isn't yet available for download. Without this wait, Enroll() returns a pending result and the issued cert is picked up by the next sync cycle. Setting to 0 disables the wait (single-fetch behaviour). Can also be set via the CERTINEXT_DCV_WAIT_FOR_ISSUANCE_SECONDS environment variable; the env var takes precedence when both are set. Default: 60. | 60 |
        | `DcvSyncMaxOrderAgeHours` | Optional | During synchronization, only pending DV orders younger than this many hours are eligible to be driven through DCV. This keeps a sync pass fast when there is a large backlog of old, never-completing pending orders (e.g. abandoned orders or domains outside the configured DNS provider's zone): they age out and are simply reported as pending rather than retried every pass. Recently-placed orders (the ones that legitimately deferred DCV) are always within the window and complete via the normal scan cadence. Set to 0 to disable the age filter (attempt DCV for all pending). Default: 24. | 24 |
        | `DcvSyncMaxPerPass` | Optional | Maximum number of pending DV orders the plugin will attempt to drive through DCV in a single synchronization pass. Bounds the per-pass cost regardless of backlog size; remaining pending orders are reported as-is and picked up on a later pass (the per-minute incremental scan keeps recent orders moving). Set to 0 to disable the cap. Default: 50. | 50 |

2. Define [Certificate Profiles](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCP-Gateway.htm) and [Certificate Templates](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Gateway.htm) for the Certificate Authority as required. One Certificate Profile must be defined per Certificate Template. It's recommended that each Certificate Profile be named after the Product ID. The CERTInext plugin supports the following product IDs:

    * **DV SSL**
    * **DV SSL Wildcard**
    * **DV SSL Multi-Domain (UCC)**
    * **DV SSL Wildcard Multi-Domain (UCC)**
    * **OV SSL**
    * **OV SSL Wildcard**
    * **OV SSL Multi-Domain (UCC)**
    * **OV SSL Wildcard Multi-Domain (UCC)**
    * **EV SSL**
    * **EV SSL Multi-Domain (UCC)**

3. Follow the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Keyfactor.htm) to add each defined Certificate Authority to Keyfactor Command and import the newly defined Certificate Templates.

4. In Keyfactor Command (v12.3+), for each imported Certificate Template, follow the [official documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/Configuring%20Template%20Options.htm) to define enrollment fields for each of the following parameters:

    * **ProductCode** - OPTIONAL: Override the numeric CERTInext product code for this template. When omitted, the default production code for the selected product is used automatically (e.g. DV SSL → 838). Set this explicitly when targeting sandbox or a non-standard code.
    * **ProfileId** - DEPRECATED: Use ProductCode instead. Kept for backward compatibility — mapped to ProductCode if ProductCode is not set.
    * **ValidityYears** - OPTIONAL: Subscription validity in years: 1, 2, or 3. A value on the template overrides the connector's SubscriptionValidityYears; precedence is ValidityYears, then the deprecated ValidityDays (rounded up to whole years), then SubscriptionValidityYears. The default of 1 applies if the template is saved with it, so set ValidityYears explicitly on templates that need a different term. Default: 1. Note: CERTInext validates per 390-day certificate within the subscription; the 'validity' field in the order is the subscription term, not certificate lifetime.
    * **ValidityDays** - DEPRECATED: Use ValidityYears instead. Used only when ValidityYears is not set: the value is divided by 365 and rounded up to get the subscription year count.
    * **AutoApprove** - Currently has no effect — reserved for future use. The plugin does not call any approval endpoint against CERTInext regardless of this setting.
    * **RequesterName** - OPTIONAL: Per-template override for the requestor name; when blank, the connector's RequestorName is used.
    * **RequesterEmail** - OPTIONAL: Per-template override for the requestor email; when blank, the connector's RequestorEmail is used.
    * **RenewalWindowDays** - OPTIONAL: Number of days before certificate expiration within which a renewal is triggered. Certificates expiring further than this window are reissued instead. Certificates that have already expired also fall back to reissue. Default: 90.
    * **KeyType** - OPTIONAL: Key algorithm to request (e.g. 'RSA2048', 'RSA4096', 'EC256', 'EC384'). If omitted, the profile default is used.
    * **DomainName** - OPTIONAL: Primary domain for SSL/TLS orders. Derived from the CSR CN if omitted.
    * **SignerName** - OPTIONAL: Per-template subscriber agreement signer name. Falls back to the connector-level RequestorName if omitted, then to the placeholder "Keyfactor Gateway" (Warning logged).
    * **SignerPlace** - OPTIONAL: Per-template signer city/location. Falls back to the connector-level SignerPlace if omitted, then to the placeholder "Gateway" (Warning logged).
    * **SignerIp** - OPTIONAL: Per-template signer IP address. Falls back to the connector-level SignerIp if omitted, then to the placeholder 127.0.0.1 (Warning logged). A value that is not an IP address is sent unchanged, with a Warning.

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

## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor Any CA Gateways (REST)](https://github.com/orgs/Keyfactor/repositories?q=anycagateway).
