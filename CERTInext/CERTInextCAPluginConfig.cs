// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;

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
                    Comments = "REQUIRED: CERTInext API base URL. " +
                               "Sandbox (US): https://sandbox-us-api.certinext.io/emSignHub-API/ — " +
                               "Production (US): https://us-api.certinext.io/ — " +
                               "Production (Global/India): https://api.certinext.io/",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.AccountNumber] = new PropertyConfigInfo
                {
                    Comments = "REQUIRED: Your CERTInext account number (numeric string). " +
                               "Available in the CERTInext portal.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.GroupNumber] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: CERTInext group (delegation) number. " +
                               "When set, it is included in GetProductDetails requests AND in the " +
                               "`delegationInformation.groupNumber` field of every SSL order so the order " +
                               "is routed to the correct account group. Some accounts will queue orders for " +
                               "additional review when this field is omitted. " +
                               "Available in the CERTInext portal under Delegation → Groups.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.OrganizationNumber] = new PropertyConfigInfo
                {
                    Comments = "STRONGLY RECOMMENDED for OV/EV and faster DV issuance: numeric " +
                               "CERTInext organization number for a pre-vetted organization (e.g. " +
                               "your company's pre-vetted entry). When set, every SSL order is submitted " +
                               "with `organizationDetails.preVetting=\"1\"` and the configured " +
                               "`organizationNumber`, telling CERTInext to skip the manual " +
                               "organization-vetting queue. Without this value, orders are placed without " +
                               "any organizationDetails block and CERTInext may park them in " +
                               "`Pending System RA` for extended manual review (observed: tens of hours). " +
                               "Available in the CERTInext portal under Organizations → " +
                               "Pre-vetted Organizations.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.TechnicalContactName] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Name sent in the `technicalPointOfContact.tpcName` field of every " +
                               "SSL order. Defaults to the configured RequestorName when blank. " +
                               "Some product configurations require a TPoC to be present; omitting it can " +
                               "cause CERTInext to park orders awaiting manual completion of the field.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.TechnicalContactEmail] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Email sent in the `technicalPointOfContact.tpcEmail` field of every " +
                               "SSL order. Defaults to the configured RequestorEmail when blank.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.TechnicalContactIsdCode] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: International dialing code for the TPoC phone number. " +
                               "Defaults to the configured RequestorIsdCode when blank.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.TechnicalContactMobileNumber] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Mobile number for the TPoC (digits only). " +
                               "Defaults to the configured RequestorMobileNumber when blank.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.AuthMode] = new PropertyConfigInfo
                {
                    Comments = "REQUIRED: Authentication mode. " +
                               "'AccessKey' (default) — uses authKey = SHA256(accessKey + ts + txn) in every request body. " +
                               "'OAuth' — uses an OAuth2 bearer token (requires OAuthTokenUrl, OAuthClientId, OAuthClientSecret).",
                    Hidden = false,
                    DefaultValue = Constants.Config.AuthModeAccessKey,
                    Type = "String"
                },
                [Constants.Config.ApiKey] = new PropertyConfigInfo
                {
                    Comments = "REQUIRED when AuthMode is 'AccessKey': the REST API Access Key generated in the " +
                               "CERTInext portal under Integrations → APIs. " +
                               "This value is used to compute authKey = SHA256(accessKey + ts + txn); " +
                               "it is never transmitted directly.",
                    Hidden = true,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.OAuth2TokenUrl] = new PropertyConfigInfo
                {
                    Comments = "OAuth token endpoint URL. Required when AuthMode is 'OAuth'.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.OAuth2ClientId] = new PropertyConfigInfo
                {
                    Comments = "OAuth client ID. Required when AuthMode is 'OAuth'.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.OAuth2ClientSecret] = new PropertyConfigInfo
                {
                    Comments = "OAuth client secret. Required when AuthMode is 'OAuth'.",
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
                [Constants.Config.SignerPlace] = new PropertyConfigInfo
                {
                    Comments = "City or location of the subscriber agreement signer. Required by CERTInext for all orders.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.SignerIp] = new PropertyConfigInfo
                {
                    Comments = "IP address of the subscriber agreement signer. Required by CERTInext for all orders.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                ["DefaultProductCode"] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Default numeric product code used when not specified at template level. " +
                               "Product codes are provided by eMudhra (e.g. the SSL DV 1-year code for your account). " +
                               "Retrieve available codes from Integrations → APIs → GetProductDetails.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.AccountingModel] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: CERTInext billing model sent in `orderDetails.accountingModel`. " +
                               "\"2\" = credit-based (most accounts, default). \"1\" = cash model.",
                    Hidden = false,
                    DefaultValue = "2",
                    Type = "String"
                },
                [Constants.Config.EmailNotifications] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Whether CERTInext sends lifecycle-event emails to the requestor. " +
                               "\"1\" = enabled, \"0\" = silent (recommended for gateway-driven orders so end users " +
                               "aren't surprised by CA emails). Default: \"0\".",
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
                    Comments = "If true, expired certificates will be skipped during synchronization. Default: false.",
                    Hidden = false,
                    DefaultValue = false,
                    Type = "Boolean"
                },
                [Constants.Config.PageSize] = new PropertyConfigInfo
                {
                    Comments = "Number of orders to fetch per page during synchronization. " +
                               $"Default: {Constants.Api.DefaultPageSize}, max: {Constants.Api.MaxPageSize}.",
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
                [Constants.Config.EnrollmentWaitAttempts] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Number of times Enroll() polls CERTInext for the issued certificate " +
                               "after submitting an order for a DV product, so fast-issuing orders return the " +
                               "certificate synchronously in the same enrollment call. " +
                               "EnrollmentWaitAttempts × EnrollmentWaitIntervalSeconds ≈ the maximum time an " +
                               "enrollment call can occupy a Keyfactor Command worker thread (a small internal " +
                               "grace margin applies) — keep the product under ~90 seconds. " +
                               "OV/EV products never poll: CERTInext issues them asynchronously by design " +
                               "(organization verification takes minutes and may be human-gated), so those " +
                               "orders return pending and are completed by the next synchronization. " +
                               "Set to 0 (or any negative value) to disable the poll entirely. " +
                               $"Can also be set via the {Constants.Config.EnrollmentWaitAttemptsEnvVar} environment " +
                               "variable; the env var takes precedence when both are set. Default: 5.",
                    Hidden = false,
                    DefaultValue = Constants.EnrollmentWait.DefaultAttempts,
                    Type = "Number"
                },
                [Constants.Config.EnrollmentWaitIntervalSeconds] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Seconds between synchronous enrollment-wait polls inside Enroll() (see " +
                               "EnrollmentWaitAttempts). Setting this to 0 (or any negative value) disables the " +
                               "poll entirely — it does NOT mean back-to-back polling. " +
                               $"Can also be set via the {Constants.Config.EnrollmentWaitIntervalSecondsEnvVar} environment " +
                               "variable; the env var takes precedence when both are set. Default: 10.",
                    Hidden = false,
                    DefaultValue = Constants.EnrollmentWait.DefaultIntervalSeconds,
                    Type = "Number"
                },
                [Constants.Config.DcvEnabled] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: When true, the gateway will perform DNS-based Domain Control Validation (DCV) " +
                               "during enrollment for orders that require it, using the configured DNS provider plugin. " +
                               "Requires a DNS provider plugin (e.g. azure-azuredns-dnsplugin) to be deployed on the gateway. " +
                               "Default: false.",
                    Hidden = false,
                    DefaultValue = false,
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
                    Comments = "OPTIONAL: How long (seconds) the plugin will wait inside Enroll() for CERTInext to " +
                               "expose the DCV challenge (i.e. populate `domainVerification` in TrackOrder). Under " +
                               "concurrent load CERTInext sometimes takes a few seconds after GenerateOrderSSL " +
                               "before the slot appears. Without this wait, the plugin's initial TrackOrder check " +
                               "sees null and skips DCV — the order then has to wait for the next gateway sync " +
                               "cycle to be picked up. Setting to 0 disables the wait (single-check behaviour). " +
                               $"Can also be set via the {Constants.Config.DcvWaitForChallengeSecondsEnvVar} " +
                               "environment variable; the env var takes precedence when both are set. Default: 60.",
                    Hidden = false,
                    DefaultValue = 60,
                    Type = "Number"
                },
                [Constants.Config.DcvWaitForIssuanceSeconds] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: How long (seconds) the plugin will wait inside Enroll() after DCV " +
                               "verifies for CERTInext to finish generating the certificate. CERTInext issuance " +
                               "is async — DCV may be verified but the cert PEM isn't yet available for download. " +
                               "Without this wait, Enroll() returns a pending result and the issued cert is " +
                               "picked up by the next sync cycle. Setting to 0 disables the wait (single-fetch " +
                               "behaviour). " +
                               $"Can also be set via the {Constants.Config.DcvWaitForIssuanceSecondsEnvVar} " +
                               "environment variable; the env var takes precedence when both are set. Default: 60.",
                    Hidden = false,
                    DefaultValue = 60,
                    Type = "Number"
                },
                [Constants.Config.DcvSyncMaxOrderAgeHours] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: During synchronization, only pending DV orders younger than this many hours " +
                               "are eligible to be driven through DCV. This keeps a sync pass fast when there is a " +
                               "large backlog of old, never-completing pending orders (e.g. abandoned orders or domains " +
                               "outside the configured DNS provider's zone): they age out and are simply reported as " +
                               "pending rather than retried every pass. Recently-placed orders (the ones that legitimately " +
                               "deferred DCV) are always within the window and complete via the normal scan cadence. " +
                               $"Set to 0 to disable the age filter (attempt DCV for all pending). Default: {Constants.Dcv.DefaultSyncMaxOrderAgeHours}.",
                    Hidden = false,
                    DefaultValue = Constants.Dcv.DefaultSyncMaxOrderAgeHours,
                    Type = "Number"
                },
                [Constants.Config.DcvSyncMaxPerPass] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Maximum number of pending DV orders the plugin will attempt to drive through DCV " +
                               "in a single synchronization pass. Bounds the per-pass cost regardless of backlog size; " +
                               "remaining pending orders are reported as-is and picked up on a later pass (the per-minute " +
                               $"incremental scan keeps recent orders moving). Set to 0 to disable the cap. Default: {Constants.Dcv.DefaultSyncMaxPerPass}.",
                    Hidden = false,
                    DefaultValue = Constants.Dcv.DefaultSyncMaxPerPass,
                    Type = "Number"
                },
                [Constants.Config.DcvFollowCnameDelegation] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: When true, and the DNS TXT challenge hostname for a domain is delegated via " +
                               "CNAME to a different DNS zone (e.g. a validation subdomain CNAMEd to a dedicated zone, " +
                               "a common pattern for keeping automation credentials out of the production zone), the " +
                               $"plugin follows the CNAME chain (bounded to {Constants.Dcv.MaxCnameDepth} hops, with loop " +
                               "detection) and both publishes the TXT record and resolves the DNS provider plugin against " +
                               "the terminal (resolved) name instead of the raw challenge hostname. Off by default so " +
                               "existing non-delegated deployments are unaffected. Default: false.",
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
                    Comments = "OPTIONAL: Override the numeric CERTInext product code for this template. " +
                               "When omitted, the default production code for the selected product is used automatically " +
                               "(e.g. DV SSL → 838). Set this explicitly when targeting sandbox or a non-standard code.",
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
                    Comments = "DEPRECATED: Use ValidityYears instead. " +
                               "If set, value is divided by 365 and rounded up to get the subscription year count.",
                    Hidden = false,
                    DefaultValue = 365,
                    Type = "Number"
                },
                [Constants.EnrollmentParam.AutoApprove] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: If true, the gateway will attempt automatic approval of certificates " +
                               "that are returned in a pending-approval state. Default: false.",
                    Hidden = false,
                    DefaultValue = false,
                    Type = "Boolean"
                },
                [Constants.EnrollmentParam.RequesterName] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Default requester name to include in the enrollment request. " +
                               "Used when no requester name can be derived from the subject.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.EnrollmentParam.RequesterEmail] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Default requester email address. " +
                               "Used when no email can be derived from the subject.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.EnrollmentParam.RenewalWindowDays] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Number of days before certificate expiration within which a renewal is " +
                               "triggered. Certificates expiring further than this window are reissued instead. " +
                               "Certificates that have already expired also fall back to reissue. Default: 90.",
                    Hidden = false,
                    DefaultValue = 90,
                    Type = "Number"
                },
                [Constants.EnrollmentParam.KeyType] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Key algorithm to request (e.g. 'RSA2048', 'RSA4096', 'EC256', 'EC384'). " +
                               "If omitted, the profile default is used.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.EnrollmentParam.DomainName] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Primary domain for SSL/TLS orders. " +
                               "Derived from the CSR CN if omitted.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.EnrollmentParam.SignerName] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Per-template subscriber agreement signer name. " +
                               "Falls back to the connector-level RequestorName if omitted.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.EnrollmentParam.SignerPlace] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Per-template signer city/location. " +
                               "Falls back to the connector-level SignerPlace if omitted.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.EnrollmentParam.SignerIp] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Per-template signer IP address. " +
                               "Falls back to the connector-level SignerIp if omitted.",
                    Hidden = false,
                    DefaultValue = string.Empty,
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
        /// CERTInext API base URL, e.g. "https://us-api.certinext.io/emSignHub-API/".
        /// Must end with a trailing slash or the endpoint path segment.
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
        /// Authentication mode: "AccessKey" (default) or "OAuth".
        /// </summary>
        [JsonPropertyName("AuthMode")]
        public string AuthMode { get; set; } = Constants.Config.AuthModeAccessKey;

        /// <summary>
        /// Raw REST API Access Key generated in CERTInext portal (Integrations → APIs).
        /// Used to compute authKey = SHA256(accessKey + ts + txn).
        /// Required when AuthMode is "AccessKey".
        /// NEVER logged or transmitted directly — only the derived authKey is sent.
        /// </summary>
        [JsonPropertyName("ApiKey")]
        public string ApiKey { get; set; } = string.Empty;

        /// <summary>OAuth token endpoint URL. Required when AuthMode is "OAuth".</summary>
        [JsonPropertyName("OAuthTokenUrl")]
        public string OAuthTokenUrl { get; set; } = string.Empty;

        /// <summary>OAuth client ID. Required when AuthMode is "OAuth".</summary>
        [JsonPropertyName("OAuthClientId")]
        public string OAuthClientId { get; set; } = string.Empty;

        /// <summary>OAuth client secret. Required when AuthMode is "OAuth".</summary>
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

        /// <summary>"1" = enable lifecycle emails to requestor, "0" = silent (default).</summary>
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
        /// Number of times <c>Enroll()</c> polls <c>GetCertificate</c> after submitting an
        /// order for a DV product, waiting for CERTInext to issue so the certificate can be
        /// returned synchronously (mirrors the legacy Sectigo connector's pickup loop).
        /// <c>EnrollmentWaitAttempts × EnrollmentWaitIntervalSeconds</c> is the maximum time an
        /// enrollment call can occupy a Command worker thread. Set to 0 to disable the poll
        /// entirely (the certificate is then picked up on the next synchronization). Overridden
        /// by <c>CERTINEXT_ENROLLMENT_WAIT_ATTEMPTS</c> when set. Default: 5.
        /// </summary>
        [JsonPropertyName("EnrollmentWaitAttempts")]
        public int EnrollmentWaitAttempts { get; set; } = Constants.EnrollmentWait.DefaultAttempts;

        /// <summary>
        /// Seconds between synchronous enrollment-wait polls inside <c>Enroll()</c>. See
        /// <see cref="EnrollmentWaitAttempts"/>. Overridden by
        /// <c>CERTINEXT_ENROLLMENT_WAIT_INTERVAL_SECONDS</c> when set. Default: 10.
        /// </summary>
        [JsonPropertyName("EnrollmentWaitIntervalSeconds")]
        public int EnrollmentWaitIntervalSeconds { get; set; } = Constants.EnrollmentWait.DefaultIntervalSeconds;

        [JsonPropertyName("PageSize")]
        public int PageSize { get; set; } = Constants.Api.DefaultPageSize;

        [JsonPropertyName("Enabled")]
        public bool Enabled { get; set; } = true;

        // -----------------------------------------------------------------------
        // DCV — domain control validation via DNS provider plugins
        // -----------------------------------------------------------------------

        /// <summary>
        /// When true, the plugin will run DNS DCV for orders that require it during enrollment.
        /// Requires <c>IDomainValidatorFactory</c> to be injected by the gateway (available from
        /// <c>IAnyCAPlugin 3.3.0-prerelease</c>). Default: false.
        /// </summary>
        [JsonPropertyName("DcvEnabled")]
        public bool DcvEnabled { get; set; } = false;

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

        /// <summary>
        /// When true, follows CNAME delegation for the DCV challenge hostname (bounded to
        /// <see cref="Constants.Dcv.MaxCnameDepth"/> hops, with loop detection), using the
        /// resolved terminal name for both the TXT record target and the DNS-provider-plugin
        /// lookup key (issue 0006). Off by default — existing non-delegated deployments are
        /// unaffected.
        /// </summary>
        [JsonPropertyName("DcvFollowCnameDelegation")]
        public bool DcvFollowCnameDelegation { get; set; } = false;

        private static readonly ILogger EffectiveConfigLogger = LogHandler.GetClassLogger<CERTInextConfig>();

        // Tracks (envVar, rejected value) pairs already warned about so a misconfigured
        // env var produces one audit-trail warning per distinct value per process, not one
        // per enrollment/sync pass.
        private static readonly ConcurrentDictionary<string, byte> WarnedInvalidEnvValues = new();

        /// <summary>
        /// Shared resolution for the numeric "GetEffective*" knobs: the environment variable
        /// wins when set and parseable, then the configured field, then the compiled default.
        /// <paramref name="zeroAllowed"/> distinguishes knobs where 0 is a meaningful
        /// "disabled" value from knobs that require a positive value.
        /// <paramref name="negativeMeansZero"/> makes negative values coerce to 0 rather
        /// than being rejected — for the enrollment-wait knobs, where "-1 to disable" is a
        /// common operator convention and silently re-enabling the compiled default would be
        /// the opposite of the operator's intent.
        /// A set-but-invalid env var is rejected with a Warning (SOX change management /
        /// SOC2 CC7.2: the override changes runtime control behavior, so silently ignoring
        /// it would leave the deployed value unexplained in the audit trail).
        /// </summary>
        private static int GetEffectiveInt(string envVarName, int configured, int fallback,
            bool zeroAllowed, bool negativeMeansZero = false)
        {
            bool Valid(int v) => zeroAllowed ? v >= 0 : v > 0;
            int Normalize(int v) => negativeMeansZero && v < 0 ? 0 : v;

            configured = Normalize(configured);
            int effective = Valid(configured) ? configured : fallback;

            var env = System.Environment.GetEnvironmentVariable(envVarName);
            if (string.IsNullOrEmpty(env))
                return effective;

            if (int.TryParse(env, out int envVal))
            {
                envVal = Normalize(envVal);
                if (Valid(envVal))
                    return envVal;
            }

            if (WarnedInvalidEnvValues.TryAdd($"{envVarName}={env}", 0))
            {
                EffectiveConfigLogger.LogWarning(
                    "Environment variable {EnvVar} is set to '{Value}', which is not a valid value for this " +
                    "setting; falling back to the configured/default value {Effective}.",
                    envVarName, env, effective);
            }
            return effective;
        }

        /// <summary>
        /// Returns the effective DCV timeout, preferring the environment variable over the
        /// config field so operators can adjust the ceiling without a connector reconfiguration.
        /// </summary>
        public int GetEffectiveDcvTimeoutMinutes() =>
            GetEffectiveInt(Constants.Config.DcvTimeoutMinutesEnvVar, DcvTimeoutMinutes, 10, zeroAllowed: false);

        /// <summary>
        /// Returns the effective wait for the DCV challenge to appear in TrackOrder, preferring
        /// the env var so operators can tune without re-saving the connector. A value of 0
        /// (either field or env var) disables the wait entirely.
        /// </summary>
        public int GetEffectiveDcvWaitForChallengeSeconds() =>
            GetEffectiveInt(Constants.Config.DcvWaitForChallengeSecondsEnvVar, DcvWaitForChallengeSeconds, 60, zeroAllowed: true);

        /// <summary>
        /// Returns the effective post-DCV wait for cert issuance, preferring the env var.
        /// A value of 0 disables the wait.
        /// </summary>
        public int GetEffectiveDcvWaitForIssuanceSeconds() =>
            GetEffectiveInt(Constants.Config.DcvWaitForIssuanceSecondsEnvVar, DcvWaitForIssuanceSeconds, 60, zeroAllowed: true);

        /// <summary>
        /// Returns the effective synchronous-enrollment-wait attempt count, preferring the env
        /// var so operators can tune without re-saving the connector. 0 (or any negative value)
        /// disables the poll.
        /// </summary>
        public int GetEffectiveEnrollmentWaitAttempts() =>
            GetEffectiveInt(Constants.Config.EnrollmentWaitAttemptsEnvVar, EnrollmentWaitAttempts, Constants.EnrollmentWait.DefaultAttempts,
                zeroAllowed: true, negativeMeansZero: true);

        /// <summary>
        /// Returns the effective interval between synchronous enrollment-wait polls, preferring
        /// the env var. 0 (or any negative value) disables the poll.
        /// </summary>
        public int GetEffectiveEnrollmentWaitIntervalSeconds() =>
            GetEffectiveInt(Constants.Config.EnrollmentWaitIntervalSecondsEnvVar, EnrollmentWaitIntervalSeconds, Constants.EnrollmentWait.DefaultIntervalSeconds,
                zeroAllowed: true, negativeMeansZero: true);
    }
}
