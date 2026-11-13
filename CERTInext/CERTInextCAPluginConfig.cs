// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using System.Text.Json.Serialization;
using Keyfactor.AnyGateway.Extensions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext
{
    /// <summary>
    /// Provides the UI annotation metadata for all CA connector and enrollment template
    /// configuration fields shown in the Keyfactor Command console.
    /// </summary>
    public static class CERTInextCAPluginConfig
    {
        /// <summary>
        /// Returns the annotation metadata for all CA connector-level configuration fields.
        /// These appear in the Command UI when an administrator sets up the CA connector.
        /// </summary>
        public static Dictionary<string, PropertyConfigInfo> GetCAConnectorAnnotations()
        {
            return new Dictionary<string, PropertyConfigInfo>
            {
                [Constants.Config.ApiUrl] = new PropertyConfigInfo
                {
                    Comments = "REQUIRED: CERTInext API base URL. V1 (default): host plus /emSignHub-API/, e.g. " +
                               "https://us-api.certinext.io/emSignHub-API/. V2 (UseV2Api=true): bare host, e.g. " +
                               "https://us-api.certinext.io. Must use https.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.AccountNumber] = new PropertyConfigInfo
                {
                    Comments = "REQUIRED when UseV2Api is false: your CERTInext account number (numeric string). " +
                               "Included in the `meta` block of every V1 request. Not used when UseV2Api is true. " +
                               "Available in the CERTInext portal.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.GroupNumber] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: CERTInext group (delegation) number. When set, it is included in " +
                               "product-catalog requests and in the order (`delegationInformation.groupNumber` on V1, " +
                               "`groupNumber` on V2) so the order is routed to the correct account group, and V2 " +
                               "synchronization is scoped to the group. Some accounts will queue orders for additional " +
                               "review when this field is omitted. Available in the CERTInext portal under Delegation → " +
                               "Groups.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.OrganizationNumber] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Pre-vetted CERTInext organization number. Required for OV/EV on V2; " +
                               "recommended for V1 OV/EV and faster DV. Skips CERTInext's manual vetting queue.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.TechnicalContactName] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Name sent as the order's technical point of contact (V1 " +
                               "`technicalPointOfContact.tpcName`, V2 `technicalPointOfContact.name`). Defaults to the " +
                               "configured RequestorName when blank. Some product configurations require a TPoC to be " +
                               "present; omitting it can cause CERTInext to park orders awaiting manual completion of " +
                               "the field.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.TechnicalContactEmail] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Email sent as the order's technical point of contact (V1 `tpcEmail`, V2 " +
                               "`email`). Defaults to the configured RequestorEmail when blank.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.TechnicalContactIsdCode] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: International dialing code for the technical contact phone number. Defaults to " +
                               "the configured RequestorIsdCode when blank.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.TechnicalContactMobileNumber] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Mobile number for the technical contact (digits only). Defaults to the " +
                               "configured RequestorMobileNumber when blank.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.AuthMode] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL, legacy (V1 only): leave as 'AccessKey' (default). V1 does not honor OAuth " +
                               "tokens, so 'OAuth' is unsupported. Ignored when UseV2Api is true.",
                    Hidden = false,
                    DefaultValue = Constants.Config.AuthModeAccessKey,
                    Type = "String"
                },
                [Constants.Config.ApiKey] = new PropertyConfigInfo
                {
                    Comments = "REQUIRED when UseV2Api is false: the REST API Access Key generated in the CERTInext " +
                               "portal under Integrations → APIs. Used to compute authKey = SHA256(accessKey + ts + " +
                               "txn); never transmitted directly. Not used when UseV2Api is true.",
                    Hidden = true,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.OAuth2TokenUrl] = new PropertyConfigInfo
                {
                    Comments = "Legacy / unsupported (V1): V1 does not honor OAuth tokens; leave blank. Ignored when " +
                               "UseV2Api is true — V2 requests its token from {ApiUrl}/oauth/token.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.OAuth2ClientId] = new PropertyConfigInfo
                {
                    Comments = "OAuth client ID. REQUIRED when UseV2Api is true: V2 authenticates with " +
                               "client_credentials against {ApiUrl}/oauth/token. The key must be generated in OAuth mode " +
                               "in the CERTInext portal. Not used on V1.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.OAuth2ClientSecret] = new PropertyConfigInfo
                {
                    Comments = "OAuth client secret. REQUIRED when UseV2Api is true (see OAuthClientId). Not used on V1.",
                    Hidden = true,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.RequestorName] = new PropertyConfigInfo
                {
                    Comments = "REQUIRED: Default requestor name submitted with all certificate orders. " +
                               "This is the name of the person/service responsible for the certificates.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.RequestorEmail] = new PropertyConfigInfo
                {
                    Comments = "REQUIRED: Default requestor email submitted with all certificate orders. " +
                               "Must be a valid email address registered in your CERTInext account.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.RequestorIsdCode] = new PropertyConfigInfo
                {
                    Comments = "International dialing code for the requestor phone number (e.g. '1' for US). Default: '1'.",
                    Hidden = false,
                    DefaultValue = "1",
                    Type = "String"
                },
                [Constants.Config.RequestorMobileNumber] = new PropertyConfigInfo
                {
                    Comments = "Requestor mobile number (digits only, no country code).",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.RequestorDesignation] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Job title / role of the requestor (e.g. 'IT Administrator'). Sent as " +
                               "requestorInformation.requestorDesignation (V1) and requestor.designation (V2). Free " +
                               "text. Omitted when blank.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.SignerPlace] = new PropertyConfigInfo
                {
                    Comments = "City or location of the subscriber agreement signer (e.g. 'San Francisco, CA'). " +
                               "REQUIRED when UseV2Api is on: the V2 Subscriber Agreement sent with every SSL order " +
                               "requires it, so the connector cannot be saved with it blank. A per-template " +
                               "SignerPlace enrollment parameter overrides it.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.SignerIp] = new PropertyConfigInfo
                {
                    Comments = "IP address of the subscriber agreement signer. V1 sends 127.0.0.1 with a warning when " +
                               "blank; V2 omits it. A template-level SignerIp enrollment parameter overrides it on V2.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                ["DefaultProductCode"] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Default numeric product code. V1: used for renewals when the template supplies " +
                               "none. V2: disambiguates a ProductId-only template when the catalog has several matches. " +
                               "Get codes via GetProductDetails.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.AccountingModel] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: CERTInext billing model sent in `orderDetails.accountingModel` on V1 orders. " +
                               "\"2\" = credit-based (most accounts, default). \"1\" = cash model. Not used by V2.",
                    Hidden = false,
                    DefaultValue = "2",
                    Type = "String"
                },
                [Constants.Config.EmailNotifications] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Lifecycle emails to the requestor. \"1\" = full set (V2: \"all\"), \"0\" = silent. " +
                               "Blank: silent on V1, omitted on V2 (CA default applies). Other values fail V2 " +
                               "enrollment. Default: \"0\".",
                    Hidden = false,
                    DefaultValue = "0",
                    Type = "String"
                },
                [Constants.Config.SubscriptionValidityYears] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Default validity in years for SSL orders. \"1\", \"2\", or \"3\". " +
                               "Override per template via the ValidityYears product parameter. Default: \"1\".",
                    Hidden = false,
                    DefaultValue = "1",
                    Type = "String"
                },
                [Constants.Config.SubscriptionAutoRenew] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Whether CERTInext should auto-renew certificates issued through " +
                               "this connector. \"0\" = disabled (recommended — renewal is driven by Keyfactor " +
                               "Command), \"1\" = enabled. Default: \"0\".",
                    Hidden = false,
                    DefaultValue = "0",
                    Type = "String"
                },
                [Constants.Config.SubscriptionRenewCriteriaDays] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Days before expiry at which CERTInext auto-renews (only honored when " +
                               "SubscriptionAutoRenew = \"1\"). Typical values: \"30\" or \"60\". Default: \"30\".",
                    Hidden = false,
                    DefaultValue = "30",
                    Type = "String"
                },
                [Constants.Config.AutoSecureWww] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: If \"1\", CERTInext automatically adds the `www.` variant of the " +
                               "primary domain as an additional SAN. \"0\" = use only the CN/SANs supplied " +
                               "with the CSR. Default: \"0\".",
                    Hidden = false,
                    DefaultValue = "0",
                    Type = "String"
                },
                [Constants.Config.IgnoreExpired] = new PropertyConfigInfo
                {
                    Comments = "If true, expired certificates are skipped during synchronization. V2 only: the V1 sync " +
                               "does not currently apply it. Default: false.",
                    Hidden = false,
                    DefaultValue = false,
                    Type = "Boolean"
                },
                [Constants.Config.SubmitNonDnsSans] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL (V1 only): If true (default), non-DNS SANs (IP, email, URI) are submitted, but " +
                               "CERTInext cannot validate them, so the order won't issue. If false, only DNS names are " +
                               "submitted.",
                    Hidden = false,
                    DefaultValue = true,
                    Type = "Boolean"
                },
                [Constants.Config.PageSize] = new PropertyConfigInfo
                {
                    Comments = $"Number of orders to fetch per page during synchronization (1 or higher). Default: " +
                               $"{Constants.Api.DefaultPageSize}, max: {Constants.Api.MaxPageSize} (V2 `/reports/orders` " +
                               $"pages are capped at {Constants.ApiV2.OrdersReportMaxPageSize}).",
                    Hidden = false,
                    DefaultValue = Constants.Api.DefaultPageSize,
                    Type = "Number"
                },
                [Constants.Config.Enabled] = new PropertyConfigInfo
                {
                    Comments = "Flag to Enable or Disable gateway functionality. Disabling is primarily used to allow " +
                               "creation of the CA connector prior to configuration information being available.",
                    Hidden = false,
                    DefaultValue = true,
                    Type = "Boolean"
                },
                [Constants.Config.LogSensitiveRequestData] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL temporary diagnostic switch. When true, requestor personal data (name, email, " +
                               "phone) and full CA payloads are logged. Credentials are always redacted. Turn off after " +
                               "verifying. Default: false.",
                    Hidden = false,
                    DefaultValue = false,
                    Type = "Boolean"
                },
                [Constants.Config.PickupRetries] = new PropertyConfigInfo
                {
                    Comments = $"OPTIONAL: Times Enroll() polls CERTInext for the certificate after order submission " +
                               $"(0-{Constants.Pickup.MaxRetries}; 0 disables the wait). Unissued orders are picked up by " +
                               $"sync. Default: {Constants.Pickup.DefaultRetries}.",
                    Hidden = false,
                    DefaultValue = Constants.Pickup.DefaultRetries,
                    Type = "Number"
                },
                [Constants.Config.PickupDelay] = new PropertyConfigInfo
                {
                    Comments = $"OPTIONAL: Seconds between certificate-pickup polls " +
                               $"(1-{Constants.Pickup.MaxDelaySeconds}). Total wait is " +
                               $"{Constants.Pickup.InitialDelaySeconds} s + PickupRetries x this value. Command's own " +
                               $"enrollment call into the gateway is bounded at roughly " +
                               $"{Constants.Pickup.CommandEnrollmentBudgetSeconds} s, so the plugin caps the total at " +
                               $"{Constants.Pickup.MaxTotalWaitSeconds} s regardless of how PickupRetries/PickupDelay " +
                               $"are set, reducing the retry count to fit. Keep your configured total well under that " +
                               $"ceiling. Default: {Constants.Pickup.DefaultDelaySeconds} " +
                               $"(~{Constants.Pickup.InitialDelaySeconds + Constants.Pickup.DefaultRetries * Constants.Pickup.DefaultDelaySeconds} " +
                               $"s with default retries).",
                    Hidden = false,
                    DefaultValue = Constants.Pickup.DefaultDelaySeconds,
                    Type = "Number"
                },
                [Constants.Config.DcvEnabled] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: When true, the plugin performs DNS-based Domain Control Validation (DCV) " +
                               "during enrollment and synchronization for orders that require it, using the DNS provider " +
                               "plugin deployed on the gateway (e.g. azure-azuredns-dnsplugin). Without a DNS provider " +
                               "plugin, orders that need validation stay pending and the plugin logs why. Set to false " +
                               "to skip DCV. Default: true.",
                    Hidden = false,
                    DefaultValue = true,
                    Type = "Boolean"
                },
                [Constants.Config.DcvTxtRecordTemplate] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Format string for the DNS TXT record hostname used during DCV. " +
                               "{0} is replaced with the domain name being validated. " +
                               $"Default: {Constants.Dcv.DefaultTxtRecordTemplate}",
                    Hidden = false,
                    DefaultValue = Constants.Dcv.DefaultTxtRecordTemplate,
                    Type = "String"
                },
                [Constants.Config.DcvPropagationDelaySeconds] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Seconds to wait after publishing the DNS TXT record before asking CERTInext " +
                               "to verify it. Increase for zones with slow propagation. Default: 30.",
                    Hidden = false,
                    DefaultValue = 30,
                    Type = "Number"
                },
                [Constants.Config.DcvTimeoutMinutes] = new PropertyConfigInfo
                {
                    Comments = $"OPTIONAL: Maximum minutes to wait for the entire DCV flow (DNS publish + propagation + verify) " +
                               $"before timing out the enrollment. Can also be set via the {Constants.Config.DcvTimeoutMinutesEnvVar} " +
                               $"environment variable; the env var takes precedence when both are set. Default: 10.",
                    Hidden = false,
                    DefaultValue = 10,
                    Type = "Number"
                },
                [Constants.Config.DcvWaitForChallengeSeconds] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL (V1 only): Seconds Enroll() waits for CERTInext to expose the DCV challenge. 0 " +
                               "disables the wait. CERTINEXT_DCV_WAIT_FOR_CHALLENGE_SECONDS overrides it. Default: 60.",
                    Hidden = false,
                    DefaultValue = 60,
                    Type = "Number"
                },
                [Constants.Config.DcvWaitForIssuanceSeconds] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL (V1 only): Seconds Enroll() waits for issuance after DCV verifies. 0 disables " +
                               "the wait. CERTINEXT_DCV_WAIT_FOR_ISSUANCE_SECONDS overrides it. Default: 60.",
                    Hidden = false,
                    DefaultValue = 60,
                    Type = "Number"
                },
                [Constants.Config.DcvSyncMaxOrderAgeHours] = new PropertyConfigInfo
                {
                    Comments = $"OPTIONAL: During synchronization, only pending DV orders younger than this many hours " +
                               $"are driven through DCV. 0 disables the filter. Default: " +
                               $"{Constants.Dcv.DefaultSyncMaxOrderAgeHours}.",
                    Hidden = false,
                    DefaultValue = Constants.Dcv.DefaultSyncMaxOrderAgeHours,
                    Type = "Number"
                },
                [Constants.Config.DcvSyncMaxPerPass] = new PropertyConfigInfo
                {
                    Comments = $"OPTIONAL: Maximum pending DV orders driven through DCV per synchronization pass. 0 " +
                               $"disables the cap. Default: {Constants.Dcv.DefaultSyncMaxPerPass}.",
                    Hidden = false,
                    DefaultValue = Constants.Dcv.DefaultSyncMaxPerPass,
                    Type = "Number"
                },

                // -----------------------------------------------------------------------
                // V2 API settings — only required when UseV2Api = true
                // -----------------------------------------------------------------------

                [Constants.ConfigV2.UseV2Api] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: When true, the plugin routes Ping / Enroll / GetSingleRecord / Revoke / " +
                               "Synchronize through the CERTInext V2 REST API (/api/certinext/v2/), including V2 " +
                               "/reports/orders for Synchronize. Requires ApiUrl (the V2 base URL in this mode), " +
                               "OAuthClientId, OAuthClientSecret, and SignerPlace. V1 credentials " +
                               "(ApiKey/AccountNumber/AuthMode) are not required when this is true. Default: false (V1 " +
                               "API).",
                    Hidden = false,
                    DefaultValue = false,
                    Type = "Boolean"
                },
                [Constants.Config.V2SyncLookbackHours] = new PropertyConfigInfo
                {
                    Comments = $"OPTIONAL (V2 only): Hours subtracted from the last-sync time on incremental sync, so an " +
                               $"order created earlier but issued later is not missed. Default: " +
                               $"{Constants.ApiV2.DefaultSyncLookbackHours}.",
                    Hidden = false,
                    DefaultValue = Constants.ApiV2.DefaultSyncLookbackHours,
                    Type = "Number"
                },
                [Constants.Config.SyncRecentOrderGraceSeconds] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: during a Synchronize (full or incremental, in both V1 and V2 modes), a pending or issued " +
                               "order created less than this many seconds ago (plus a small clock margin) is not emitted to " +
                               "the gateway; the next incremental pass imports it. This stops the sync from inserting a " +
                               "gateway row for an order whose enrollment is still in flight, which would make the " +
                               "enrollment's own save fail with a duplicate key. Revoked and failed orders are never held " +
                               "back. 0 disables the hold; a negative value uses the default. " +
                               $"Default: {Constants.ApiV2.DefaultSyncRecentOrderGraceSeconds}.",
                    Hidden = false,
                    DefaultValue = Constants.ApiV2.DefaultSyncRecentOrderGraceSeconds,
                    Type = "Number"
                },
                [Constants.Config.V2InlineCsr] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL (V2 mode only): when true, SSL/TLS enrollment sends the CSR inline in the " +
                               "order create call (a single POST /ssl-certificates) instead of the default two-call " +
                               "flow (create the order, then PUT .../csr). This matches a direct single-call API " +
                               "integration and is about 4-5 seconds faster, but the create call then often holds " +
                               "about 20 seconds until the certificate is issued, and a create that times out or " +
                               "returns a 5xx can leave an order that still issues; it is not cancelled and the next " +
                               "synchronization imports it, so do not resubmit. Private PKI orders ignore this " +
                               "setting and always use the two-call flow (the CA rejects an inline CSR on Private " +
                               "PKI create). Ignored when UseV2Api is false. Default: false (two-call).",
                    Hidden = false,
                    DefaultValue = false,
                    Type = "Boolean"
                }
            };
        }

        /// <summary>
        /// Returns the annotation metadata for all per-template enrollment parameters.
        /// These appear in the Command UI when an administrator configures a certificate template.
        /// </summary>
        public static Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
        {
            return new Dictionary<string, PropertyConfigInfo>
            {
                [Constants.EnrollmentParam.ProductCode] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Override the numeric CERTInext product code for this template. When omitted: " +
                               "on V1, the default production code for the selected product is used (e.g. DV SSL → 838); " +
                               "on V2, the code is resolved from the live CERTInext product catalog by matching the " +
                               "selected product, so it stays correct even though V2 catalog numbering varies by " +
                               "account. Required for ProductFamily 'private-pki'. Set this explicitly when targeting " +
                               "sandbox or a non-standard code.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.EnrollmentParam.ProfileId] = new PropertyConfigInfo
                {
                    Comments = "DEPRECATED: Use ProductCode instead. " +
                               "Kept for backward compatibility — mapped to ProductCode if ProductCode is not set.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.EnrollmentParam.ValidityYears] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Subscription validity in years: 1, 2, or 3. Default: 1. " +
                               "Note: CERTInext validates per 390-day certificate within the subscription; " +
                               "the 'validity' field in the order is the subscription term, not certificate lifetime.",
                    Hidden = false,
                    DefaultValue = 1,
                    Type = "Number"
                },
                [Constants.EnrollmentParam.ValidityDays] = new PropertyConfigInfo
                {
                    Comments = "DEPRECATED: Use ValidityYears instead. V1 only: if set, value is divided by 365 and " +
                               "rounded up to get the subscription year count.",
                    Hidden = false,
                    DefaultValue = 365,
                    Type = "Number"
                },
                [Constants.EnrollmentParam.AutoApprove] = new PropertyConfigInfo
                {
                    Comments = "Currently has no effect — reserved for future use. The plugin does not call " +
                               "any approval endpoint against CERTInext regardless of this setting.",
                    Hidden = false,
                    DefaultValue = false,
                    Type = "Boolean"
                },
                [Constants.EnrollmentParam.RequesterName] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Overrides the connector RequestorName for this template when non-blank. Never " +
                               "derived from the certificate subject.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.EnrollmentParam.RequesterEmail] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Overrides the connector RequestorEmail for this template when non-blank. Never " +
                               "derived from the certificate subject.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.EnrollmentParam.RenewalWindowDays] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: V1 only. Number of days before certificate expiration within which a renewal " +
                               "is triggered. Certificates expiring further than this window are reissued instead. " +
                               "Certificates that have already expired also fall back to reissue. V2 places a new order " +
                               "for every renewal and reissue. Default: 90.",
                    Hidden = false,
                    DefaultValue = 90,
                    Type = "Number"
                },
                [Constants.EnrollmentParam.KeyType] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Informational. The key algorithm is determined by the submitted CSR; CERTInext " +
                               "accepts RSA 2048/3072/4096 and ECC P-256/P-384 and rejects larger RSA, ECC P-521, and " +
                               "Ed25519/Ed448.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.EnrollmentParam.DomainName] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Primary domain for SSL/TLS orders (for V2 private-pki orders, the primary hostname). " +
                               "Derived from the CSR CN if omitted.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.EnrollmentParam.SignerName] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: V2 only. Per-template subscriber agreement signer name. Falls back to the " +
                               "requestor name if omitted. V1 uses the connector-level RequestorName.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.EnrollmentParam.SignerPlace] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: V2 only. Per-template signer city/location. Falls back to the connector-level " +
                               "SignerPlace if omitted. V1 uses the connector-level SignerPlace.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.EnrollmentParam.SignerIp] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: V2 only. Per-template signer IP address. Falls back to the connector-level " +
                               "SignerIp if omitted. V1 uses the connector-level SignerIp.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },

                // -----------------------------------------------------------------------
                // V2 API enrollment parameters (only used when UseV2Api = true)
                // -----------------------------------------------------------------------

                [Constants.EnrollmentParam.ProductFamily] = new PropertyConfigInfo
                {
                    Comments = "V2 ONLY: Product family for this template. Accepted values: 'ssl' (default) or " +
                               "'private-pki'. 'private-pki' requires an explicit ProductCode and a Private PKI " +
                               "ProductVariant. 'signature' (Document Signer) is accepted by the parameter, but Document " +
                               "Signer enrollment is not supported.",
                    Hidden = false,
                    DefaultValue = "ssl",
                    Type = "String"
                },
                [Constants.EnrollmentParam.ProductVariant] = new PropertyConfigInfo
                {
                    Comments = "V2 ONLY: Product variant sent in the V2 order body. ProductFamily 'ssl': 'dv', 'ov', or " +
                               "'ev' — if omitted, derived from the selected product; an explicit value that contradicts " +
                               "the product fails enrollment. ProductFamily 'private-pki': 'intranet-ssl' or 'igtf-host' " +
                               "(required; no default).",
                    Hidden = false,
                    DefaultValue = "dv",
                    Type = "String"
                }
            };
        }
    }

    /// <summary>
    /// Strongly-typed configuration object deserialized from the CA connector's
    /// <see cref="IAnyCAPluginConfigProvider.CAConnectionData"/> dictionary.
    /// </summary>
    public class CERTInextConfig
    {
        // -----------------------------------------------------------------------
        // Required
        // -----------------------------------------------------------------------

        /// <summary>
        /// CERTInext API base URL. V1 (default): host plus the /emSignHub-API/ path, e.g.
        /// "https://us-api.certinext.io/emSignHub-API/". V2 (UseV2Api=true): the bare host, e.g.
        /// "https://us-api.certinext.io". A trailing slash is optional; the client trims and re-adds it.
        /// </summary>
        [JsonPropertyName("ApiUrl")]
        public string ApiUrl { get; set; } = string.Empty;

        /// <summary>
        /// CERTInext account number (numeric string) used in every request meta block.
        /// </summary>
        [JsonPropertyName("AccountNumber")]
        public string AccountNumber { get; set; } = string.Empty;

        /// <summary>
        /// Optional CERTInext group (delegation) number.  When set, it is passed in
        /// the <c>productDetails.groupNumber</c> field of <c>GetProductDetails</c>
        /// requests AND in the <c>delegationInformation.groupNumber</c> field of every
        /// SSL order body so the order is routed to the correct account group.  Some
        /// accounts queue orders for extra review when this field is omitted.
        /// </summary>
        [JsonPropertyName("GroupNumber")]
        public string GroupNumber { get; set; } = string.Empty;

        /// <summary>
        /// CERTInext organization number for a pre-vetted organization (e.g. the customer's
        /// company).  When set, every SSL order is submitted with
        /// <c>organizationDetails.preVetting="1"</c> and the configured
        /// <c>organizationNumber</c>, telling CERTInext to skip the manual organization
        /// vetting queue.  Strongly recommended for OV/EV products; significantly speeds
        /// up DV issuance because CERTInext otherwise parks orders in <c>Pending System RA</c>
        /// for extended manual review (observed tens of hours on the sandbox).
        /// Empty by default — the plugin omits the <c>organizationDetails</c> block when
        /// this is unset, preserving prior behavior.
        /// </summary>
        [JsonPropertyName("OrganizationNumber")]
        public string OrganizationNumber { get; set; } = string.Empty;

        // -----------------------------------------------------------------------
        // Authentication
        // -----------------------------------------------------------------------

        /// <summary>
        /// Legacy. "AccessKey" (default). V1 does not honor OAuth tokens, so "OAuth" is unsupported;
        /// the field is kept so connectors saved with it keep loading. Ignored when UseV2Api is true.
        /// </summary>
        [JsonPropertyName("AuthMode")]
        public string AuthMode { get; set; } = Constants.Config.AuthModeAccessKey;

        /// <summary>
        /// Raw REST API Access Key generated in CERTInext portal (Integrations → APIs).
        /// Used to compute authKey = SHA256(accessKey + ts + txn).
        /// Required on V1 (AccessKey); not used on V2.
        /// NEVER logged or transmitted directly — only the derived authKey is sent.
        /// </summary>
        [JsonPropertyName("ApiKey")]
        public string ApiKey { get; set; } = string.Empty;

        /// <summary>Legacy / unsupported: V1 does not honor OAuth tokens. Ignored on V2, which uses {ApiUrl}/oauth/token.</summary>
        [JsonPropertyName("OAuthTokenUrl")]
        public string OAuthTokenUrl { get; set; } = string.Empty;

        /// <summary>OAuth client ID. Required when UseV2Api is true; not used on V1.</summary>
        [JsonPropertyName("OAuthClientId")]
        public string OAuthClientId { get; set; } = string.Empty;

        /// <summary>OAuth client secret. Required when UseV2Api is true; not used on V1.</summary>
        [JsonPropertyName("OAuthClientSecret")]
        public string OAuthClientSecret { get; set; } = string.Empty;

        // Legacy OAuth2 property aliases (kept for JSON round-trip compat)
        [JsonPropertyName("OAuth2TokenUrl")]
        public string OAuth2TokenUrl { get => OAuthTokenUrl; set => OAuthTokenUrl = value; }
        [JsonPropertyName("OAuth2ClientId")]
        public string OAuth2ClientId { get => OAuthClientId; set => OAuthClientId = value; }
        [JsonPropertyName("OAuth2ClientSecret")]
        public string OAuth2ClientSecret { get => OAuthClientSecret; set => OAuthClientSecret = value; }

        // Unused legacy fields — retained so existing config snapshots deserialize cleanly
        [JsonPropertyName("Username")]
        public string Username { get; set; } = string.Empty;
        [JsonPropertyName("Password")]
        public string Password { get; set; } = string.Empty;

        // -----------------------------------------------------------------------
        // Requestor defaults — injected into order requests when not overridden
        // by template parameters
        // -----------------------------------------------------------------------

        /// <summary>Default requestor name sent with all orders.</summary>
        [JsonPropertyName("RequestorName")]
        public string RequestorName { get; set; } = string.Empty;

        /// <summary>Default requestor email sent with all orders.</summary>
        [JsonPropertyName("RequestorEmail")]
        public string RequestorEmail { get; set; } = string.Empty;

        /// <summary>Default ISD (country) code for requestor phone. Default "1" (US).</summary>
        [JsonPropertyName("RequestorIsdCode")]
        public string RequestorIsdCode { get; set; } = "1";

        /// <summary>Default requestor mobile number.</summary>
        [JsonPropertyName("RequestorMobileNumber")]
        public string RequestorMobileNumber { get; set; } = string.Empty;

        /// <summary>
        /// Default requestor job title / role. Blank by default; when blank, the V2 order's
        /// <c>requestor.designation</c> field is omitted rather than sent with any default value.
        /// </summary>
        [JsonPropertyName("RequestorDesignation")]
        public string RequestorDesignation { get; set; } = string.Empty;

        /// <summary>Subscriber agreement signer place (city/location). Required by CERTInext.</summary>
        [JsonPropertyName("SignerPlace")]
        public string SignerPlace { get; set; } = string.Empty;

        /// <summary>Subscriber agreement signer IP address. Required by CERTInext.</summary>
        [JsonPropertyName("SignerIp")]
        public string SignerIp { get; set; } = string.Empty;

        /// <summary>
        /// Default product code used when the template-level ProductCode is not specified.
        /// Product codes are numeric strings provided by eMudhra (e.g. "844" for DV SSL 1-year).
        /// </summary>
        [JsonPropertyName("DefaultProductCode")]
        public string DefaultProductCode { get; set; } = string.Empty;

        // -----------------------------------------------------------------------
        // Technical point-of-contact — populated into technicalPointOfContact on SSL orders.
        // When any field is blank, the corresponding Requestor* default is used.
        // -----------------------------------------------------------------------

        /// <summary>Technical contact name. Defaults to <see cref="RequestorName"/> when blank.</summary>
        [JsonPropertyName("TechnicalContactName")]
        public string TechnicalContactName { get; set; } = string.Empty;

        /// <summary>Technical contact email. Defaults to <see cref="RequestorEmail"/> when blank.</summary>
        [JsonPropertyName("TechnicalContactEmail")]
        public string TechnicalContactEmail { get; set; } = string.Empty;

        /// <summary>Technical contact ISD code. Defaults to <see cref="RequestorIsdCode"/> when blank.</summary>
        [JsonPropertyName("TechnicalContactIsdCode")]
        public string TechnicalContactIsdCode { get; set; } = string.Empty;

        /// <summary>Technical contact mobile number. Defaults to <see cref="RequestorMobileNumber"/> when blank.</summary>
        [JsonPropertyName("TechnicalContactMobileNumber")]
        public string TechnicalContactMobileNumber { get; set; } = string.Empty;

        // -----------------------------------------------------------------------
        // SSL order body defaults — every value matches a CERTInext-documented field
        // and is overridable per-connector via the gateway admin UI.
        // -----------------------------------------------------------------------

        /// <summary>CERTInext billing model ("2" credit, "1" cash). Default "2".</summary>
        [JsonPropertyName("AccountingModel")]
        public string AccountingModel { get; set; } = "2";

        /// <summary>
        /// "1" = full notification set (V1 sends it as-is; V2 maps to "all"). "0" = silent on
        /// both V1 and V2 (default). Blank stays silent on V1 (sent
        /// as "0") but is omitted on V2, letting the CA's own default ("all") apply instead. Any
        /// other value fails V2 enrollment before any CA call.
        /// </summary>
        [JsonPropertyName("EmailNotifications")]
        public string EmailNotifications { get; set; } = "0";

        /// <summary>Default validity in years sent in subscriptionDetails. "1", "2", or "3". Default "1".</summary>
        [JsonPropertyName("SubscriptionValidityYears")]
        public string SubscriptionValidityYears { get; set; } = "1";

        /// <summary>"0" = disable CERTInext-side auto-renew (recommended — renewal is driven by Command). "1" = enable.</summary>
        [JsonPropertyName("SubscriptionAutoRenew")]
        public string SubscriptionAutoRenew { get; set; } = "0";

        /// <summary>Days before expiry at which CERTInext auto-renews (only honored when SubscriptionAutoRenew="1").</summary>
        [JsonPropertyName("SubscriptionRenewCriteriaDays")]
        public string SubscriptionRenewCriteriaDays { get; set; } = "30";

        /// <summary>"1" = let CERTInext auto-add the www. variant, "0" = use only the supplied CN/SANs (default).</summary>
        [JsonPropertyName("AutoSecureWww")]
        public string AutoSecureWww { get; set; } = "0";

        // -----------------------------------------------------------------------
        // Sync / behaviour
        // -----------------------------------------------------------------------

        [JsonPropertyName("IgnoreExpired")]
        public bool IgnoreExpired { get; set; } = false;

        /// <summary>
        /// Whether non-DNS SANs (IP address, email, URI) are submitted to CERTInext.
        ///
        /// Defaults to <c>true</c>: nothing the subscriber requested is dropped silently. CERTInext
        /// registers such values verbatim as order domains, and they cannot pass domain validation,
        /// so the order will not issue until they are removed — a visible failure, deliberately
        /// preferred over a certificate quietly missing requested names.
        ///
        /// Set to <c>false</c> to submit DNS names only, restoring the pre-1.0.1 behaviour where the
        /// order issues but the non-DNS names are absent from the certificate. This exists as an
        /// upgrade escape hatch: on a host that was issuing certificates for requests carrying an IP
        /// or email SAN, the default flips those enrollments from "issues (incomplete)" to "parks
        /// pending", and an operator needs a way back that does not involve downgrading the plugin.
        /// </summary>
        [JsonPropertyName("SubmitNonDnsSans")]
        public bool SubmitNonDnsSans { get; set; } = true;

        [JsonPropertyName("PageSize")]
        public int PageSize { get; set; } = Constants.Api.DefaultPageSize;

        [JsonPropertyName("Enabled")]
        public bool Enabled { get; set; } = true;

        /// <summary>
        /// OPTIONAL diagnostic escape hatch. When true, full CA request/response payloads are
        /// logged at Trace (beyond the credential scrubbing that always applies), and the
        /// enrollment-attempt Information log line includes the requestor's name and email in
        /// full. This writes personal data belonging to whoever placed the order — name, email,
        /// phone, and other organization contact fields — plus complete CA request/response
        /// bodies into the gateway's log files. Intended only for temporary use while verifying
        /// a new deployment (confirming exactly what was sent to the CA and that the order
        /// succeeded); turn it back off once verification is complete. When false (default),
        /// personal-data fields are replaced with "***REDACTED***" (email values are masked but
        /// keep their domain, e.g. "j***@example.com") and the enrollment log line omits the
        /// requester name entirely. Credentials (API keys, OAuth secrets, tokens) are always
        /// redacted regardless of this setting. Default: false.
        /// </summary>
        [JsonPropertyName("LogSensitiveRequestData")]
        public bool LogSensitiveRequestData { get; set; } = false;

        // -----------------------------------------------------------------------
        // DCV — domain control validation via DNS provider plugins
        // -----------------------------------------------------------------------

        /// <summary>
        /// When true, the plugin will run DNS DCV for orders that require it during enrollment.
        /// Requires <c>IDomainValidatorFactory</c> to be injected by the gateway (available from
        /// <c>IAnyCAPlugin 3.3.0</c>). Default: true.
        /// </summary>
        [JsonPropertyName("DcvEnabled")]
        public bool DcvEnabled { get; set; } = true;

        /// <summary>
        /// Format string for the TXT record hostname.  <c>{0}</c> is replaced with the domain.
        /// Default: <c>_emsign-validation.{0}</c>.
        /// </summary>
        [JsonPropertyName("DcvTxtRecordTemplate")]
        public string DcvTxtRecordTemplate { get; set; } = Constants.Dcv.DefaultTxtRecordTemplate;

        /// <summary>
        /// Seconds to wait after publishing the DNS TXT record before calling VerifyDcv.
        /// Default: 30.
        /// </summary>
        /// <summary>
        /// Number of GetCertificate poll attempts inside <c>Enroll()</c> after an order is
        /// submitted, before falling back to a pending result (picked up by the next sync).
        /// Mirrors the legacy Sectigo connector's <c>PickupRetries</c>. Set to 0 to disable.
        /// Default: 5.
        /// </summary>
        [JsonPropertyName("PickupRetries")]
        public int PickupRetries { get; set; } = Constants.Pickup.DefaultRetries;

        /// <summary>
        /// Seconds between certificate-pickup retries. <c>PickupRetries * PickupDelay</c> (plus a
        /// short initial delay) bounds the time an enrollment call occupies a Command worker
        /// thread. Mirrors the legacy Sectigo connector's <c>PickupDelay</c>. Default: 10.
        /// </summary>
        [JsonPropertyName("PickupDelay")]
        public int PickupDelayInSeconds { get; set; } = Constants.Pickup.DefaultDelaySeconds;

        [JsonPropertyName("DcvPropagationDelaySeconds")]
        public int DcvPropagationDelaySeconds { get; set; } = 30;

        /// <summary>
        /// Maximum minutes for the entire DCV flow before the enrollment is cancelled.
        /// Overridden by the <c>CERTINEXT_DCV_TIMEOUT_MINUTES</c> environment variable when set.
        /// Default: 10.
        /// </summary>
        [JsonPropertyName("DcvTimeoutMinutes")]
        public int DcvTimeoutMinutes { get; set; } = 10;

        /// <summary>
        /// Seconds the plugin will poll inside <c>Enroll()</c> waiting for CERTInext to populate
        /// <c>domainVerification</c> in <c>TrackOrder</c>.  Under concurrent load the slot can
        /// take a few seconds to appear after <c>GenerateOrderSSL</c> returns; without this
        /// wait the plugin's initial single-shot check sees <c>null</c> and skips DCV.
        /// Set to <c>0</c> to disable the wait (preserving the single-check behaviour).
        /// Overridden by <c>CERTINEXT_DCV_WAIT_FOR_CHALLENGE_SECONDS</c> when set.  Default: 60.
        /// </summary>
        [JsonPropertyName("DcvWaitForChallengeSeconds")]
        public int DcvWaitForChallengeSeconds { get; set; } = 60;

        /// <summary>
        /// Seconds the plugin will poll <c>GetCertificate</c> inside <c>Enroll()</c> after DCV
        /// verifies, waiting for CERTInext to finish generating the certificate.  CERTInext
        /// issuance is async — DCV may be verified but the cert PEM isn't yet available.
        /// Set to <c>0</c> to disable the wait (preserving the single-fetch behaviour, where
        /// the cert is picked up on the next sync cycle).  Overridden by
        /// <c>CERTINEXT_DCV_WAIT_FOR_ISSUANCE_SECONDS</c> when set.  Default: 60.
        /// </summary>
        [JsonPropertyName("DcvWaitForIssuanceSeconds")]
        public int DcvWaitForIssuanceSeconds { get; set; } = 60;

        /// <summary>
        /// During synchronization, only pending DV orders younger than this many hours are
        /// eligible for DCV completion. Bounds a sync pass against a large backlog of old,
        /// never-completing pending orders (issue 0002). 0 disables the age filter.
        /// Default: 24.
        /// </summary>
        [JsonPropertyName("DcvSyncMaxOrderAgeHours")]
        public int DcvSyncMaxOrderAgeHours { get; set; } = Constants.Dcv.DefaultSyncMaxOrderAgeHours;

        /// <summary>
        /// Maximum number of pending DV orders the plugin attempts to drive through DCV in a
        /// single sync pass (issue 0002). Bounds per-pass cost regardless of backlog size; the
        /// remainder are reported pending and revisited on a later pass. 0 disables the cap.
        /// Default: 50.
        /// </summary>
        [JsonPropertyName("DcvSyncMaxPerPass")]
        public int DcvSyncMaxPerPass { get; set; } = Constants.Dcv.DefaultSyncMaxPerPass;

        // -----------------------------------------------------------------------
        // V2 API settings
        // -----------------------------------------------------------------------

        /// <summary>
        /// When true, Enroll / GetSingleRecord / Revoke / Synchronize use the CERTInext V2 REST
        /// API. In this mode <see cref="ApiUrl"/> is the V2 base URL (e.g.
        /// https://sandbox-us-api.certinext.io, no trailing path suffix) and V2 OAuth2 auth reuses
        /// <see cref="OAuthClientId"/> / <see cref="OAuthClientSecret"/>. V1-only credentials
        /// (<see cref="ApiKey"/>, <see cref="AccountNumber"/>, <see cref="AuthMode"/>) are not
        /// required when this is true. Default: false.
        /// </summary>
        [JsonPropertyName("UseV2Api")]
        public bool UseV2Api { get; set; } = false;

        /// <summary>
        /// V2 mode only: during an incremental Synchronize, query V2 /reports/orders with a
        /// 'from' date of (lastSync minus this many hours) rather than exactly lastSync — see
        /// <see cref="Constants.ApiV2.DefaultSyncLookbackHours"/> (the
        /// from/to filter's order-date-vs-issue-date semantics are not documented).
        /// Ignored when <see cref="UseV2Api"/> is false. Default: 72.
        /// </summary>
        [JsonPropertyName("V2SyncLookbackHours")]
        public int V2SyncLookbackHours { get; set; } = Constants.ApiV2.DefaultSyncLookbackHours;

        /// <summary>
        /// During a Synchronize (full or incremental, V1 and V2 modes), pending and issued orders created
        /// less than this many seconds ago (plus <see cref="Constants.ApiV2.SyncRecentOrderClockMarginSeconds"/>)
        /// are not emitted, so the sync cannot create the gateway row an in-flight enrollment is about to
        /// save (issue 0090). 0 disables; a negative value falls back to the default. Revoked and failed
        /// orders are never held back. Default: 120.
        /// </summary>
        [JsonPropertyName("SyncRecentOrderGraceSeconds")]
        public int SyncRecentOrderGraceSeconds { get; set; } = Constants.ApiV2.DefaultSyncRecentOrderGraceSeconds;

        /// <summary>
        /// OPTIONAL (V2 mode only), default false. When true, SSL/TLS orders carry the CSR inline in the
        /// create call (single call, no <c>PUT .../csr</c>). When false, the plugin creates the order
        /// without a CSR and then submits it. Private PKI ignores this and always uses the two-call
        /// flow. Ignored when <see cref="UseV2Api"/> is false.
        /// </summary>
        [JsonPropertyName("V2InlineCsr")]
        public bool V2InlineCsr { get; set; } = false;

        /// <summary>
        /// Returns the effective DCV timeout, preferring the environment variable over the
        /// config field so operators can adjust the ceiling without a connector reconfiguration.
        /// </summary>
        public int GetEffectiveDcvTimeoutMinutes()
        {
            var env = System.Environment.GetEnvironmentVariable(Constants.Config.DcvTimeoutMinutesEnvVar);
            if (!string.IsNullOrEmpty(env) && int.TryParse(env, out int envVal) && envVal > 0)
                return envVal;
            return DcvTimeoutMinutes > 0 ? DcvTimeoutMinutes : 10;
        }

        /// <summary>
        /// Returns the effective wait for the DCV challenge to appear in TrackOrder, preferring
        /// the env var so operators can tune without re-saving the connector. A value of 0
        /// (either field or env var) disables the wait entirely.
        /// </summary>
        public int GetEffectiveDcvWaitForChallengeSeconds()
        {
            var env = System.Environment.GetEnvironmentVariable(Constants.Config.DcvWaitForChallengeSecondsEnvVar);
            if (!string.IsNullOrEmpty(env) && int.TryParse(env, out int envVal) && envVal >= 0)
                return envVal;
            return DcvWaitForChallengeSeconds >= 0 ? DcvWaitForChallengeSeconds : 60;
        }

        /// <summary>
        /// Returns the effective post-DCV wait for cert issuance, preferring the env var.
        /// A value of 0 disables the wait.
        /// </summary>
        public int GetEffectiveDcvWaitForIssuanceSeconds()
        {
            var env = System.Environment.GetEnvironmentVariable(Constants.Config.DcvWaitForIssuanceSecondsEnvVar);
            if (!string.IsNullOrEmpty(env) && int.TryParse(env, out int envVal) && envVal >= 0)
                return envVal;
            return DcvWaitForIssuanceSeconds >= 0 ? DcvWaitForIssuanceSeconds : 60;
        }

        /// <summary>
        /// Effective number of certificate-pickup retries, clamped to
        /// [0, <see cref="Constants.Pickup.MaxRetries"/>]. 0 disables the synchronous pickup.
        /// </summary>
        public int GetEffectivePickupRetries()
            => System.Math.Max(0, System.Math.Min(PickupRetries, Constants.Pickup.MaxRetries));

        /// <summary>
        /// Effective seconds between pickup retries, clamped to
        /// [1, <see cref="Constants.Pickup.MaxDelaySeconds"/>]. A non-positive configured value
        /// falls back to the default rather than producing a tight busy-loop.
        /// </summary>
        public int GetEffectivePickupDelaySeconds()
            => System.Math.Max(1, System.Math.Min(
                PickupDelayInSeconds > 0 ? PickupDelayInSeconds : Constants.Pickup.DefaultDelaySeconds,
                Constants.Pickup.MaxDelaySeconds));
    }
}
