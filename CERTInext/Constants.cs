// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

namespace Keyfactor.Extensions.CAPlugin.CERTInext
{
    public static class Constants
    {
        public static class Config
        {
            // CA connector-level configuration keys
            public const string ApiUrl = "ApiUrl";
            public const string ApiKey = "ApiKey";              // the raw Access Key (used to compute authKey)
            public const string AccountNumber = "AccountNumber"; // CERTInext account number
            public const string GroupNumber = "GroupNumber";     // optional delegation group number
            public const string OrganizationNumber = "OrganizationNumber"; // pre-vetted organization (declares preVetting=1)
            public const string AuthMode = "AuthMode";
            public const string Enabled = "Enabled";
            public const string IgnoreExpired = "IgnoreExpired";
            public const string PageSize = "PageSize";
            public const string RequestorName = "RequestorName";
            public const string RequestorEmail = "RequestorEmail";
            public const string RequestorIsdCode = "RequestorIsdCode";
            public const string RequestorMobileNumber = "RequestorMobileNumber";
            public const string SignerPlace = "SignerPlace";
            public const string SignerIp = "SignerIp";

            // Technical point-of-contact defaults (TpcName/Email default to Requestor* when blank)
            public const string TechnicalContactName = "TechnicalContactName";
            public const string TechnicalContactEmail = "TechnicalContactEmail";
            public const string TechnicalContactIsdCode = "TechnicalContactIsdCode";
            public const string TechnicalContactMobileNumber = "TechnicalContactMobileNumber";

            // SSL order body defaults — every value matches a CERTInext-documented field and
            // is overridable by the connector admin via the gateway's connector-config UI.
            public const string AccountingModel = "AccountingModel";
            public const string EmailNotifications = "EmailNotifications";
            public const string SubscriptionValidityYears = "SubscriptionValidityYears";
            public const string SubscriptionAutoRenew = "SubscriptionAutoRenew";
            public const string SubscriptionRenewCriteriaDays = "SubscriptionRenewCriteriaDays";
            public const string AutoSecureWww = "AutoSecureWww";

            // DCV — domain control validation via DNS provider plugins
            public const string DcvEnabled = "DcvEnabled";
            public const string DcvTxtRecordTemplate = "DcvTxtRecordTemplate";
            public const string DcvPropagationDelaySeconds = "DcvPropagationDelaySeconds";
            public const string DcvTimeoutMinutes = "DcvTimeoutMinutes";

            // How long to wait inside Enroll() for CERTInext to expose the DCV challenge
            // (domainVerification metadata in TrackOrder).  Under concurrent load CERTInext
            // sometimes takes a few seconds after GenerateOrderSSL before the slot appears.
            // Without this wait, the plugin's single TrackOrder check sees null and skips
            // DCV; the order then has to wait for the next gateway sync cycle to be picked up.
            public const string DcvWaitForChallengeSeconds = "DcvWaitForChallengeSeconds";

            // How long to wait inside Enroll() for CERTInext to finish generating the cert
            // after DCV verification succeeds.  CERTInext's issuance is async — DCV may be
            // verified but the cert PEM isn't yet available for download.  Without this
            // wait, Enroll() returns pending and the cert is picked up on the next sync.
            public const string DcvWaitForIssuanceSeconds = "DcvWaitForIssuanceSeconds";

            // Bounds on DCV-during-sync so a large pending backlog can't make a sync pass
            // slow (issue 0002). Only pending orders younger than DcvSyncMaxOrderAgeHours
            // are eligible for DCV completion during sync, and at most DcvSyncMaxPerPass
            // orders are attempted per pass; the rest are emitted as pending and revisited
            // on a later pass (the per-minute incremental cadence keeps recent orders moving).
            public const string DcvSyncMaxOrderAgeHours = "DcvSyncMaxOrderAgeHours";
            public const string DcvSyncMaxPerPass = "DcvSyncMaxPerPass";

            // Environment variable that overrides DcvTimeoutMinutes when set.
            public const string DcvTimeoutMinutesEnvVar = "CERTINEXT_DCV_TIMEOUT_MINUTES";
            public const string DcvWaitForChallengeSecondsEnvVar = "CERTINEXT_DCV_WAIT_FOR_CHALLENGE_SECONDS";
            public const string DcvWaitForIssuanceSecondsEnvVar = "CERTINEXT_DCV_WAIT_FOR_ISSUANCE_SECONDS";

            // Auth mode values
            public const string AuthModeAccessKey = "AccessKey"; // default; authKey = SHA256(accessKey+ts+txn)
            public const string AuthModeOAuth = "OAuth";         // bearer token via OAuth

            // OAuth specific (when AuthMode = "OAuth")
            public const string OAuthTokenUrl = "OAuthTokenUrl";
            public const string OAuthClientId = "OAuthClientId";
            public const string OAuthClientSecret = "OAuthClientSecret";

            // Legacy aliases kept for back-compat during migration
            public const string AuthModeApiKey = AuthModeAccessKey;
            public const string AuthModeBasic = "Basic";        // not supported by CERTInext real API
            public const string AuthModeOAuth2 = AuthModeOAuth;
            public const string OAuth2TokenUrl = OAuthTokenUrl;
            public const string OAuth2ClientId = OAuthClientId;
            public const string OAuth2ClientSecret = OAuthClientSecret;
        }

        public static class EnrollmentParam
        {
            // Template-level enrollment parameter keys
            public const string ProductCode = "ProductCode";   // CERTInext numeric product code
            public const string ProfileId = "ProfileId";       // alias for ProductCode (kept for back-compat)
            public const string ValidityYears = "ValidityYears"; // 1, 2, or 3
            public const string ValidityDays = "ValidityDays";   // legacy; mapped to years if set
            public const string AutoApprove = "AutoApprove";
            public const string RequesterName = "RequesterName";
            public const string RequesterEmail = "RequesterEmail";
            public const string RequesterIsdCode = "RequesterIsdCode";
            public const string RequesterMobileNumber = "RequesterMobileNumber";
            public const string RenewalWindowDays = "RenewalWindowDays";
            public const string SignerName = "SignerName";
            public const string SignerPlace = "SignerPlace";
            public const string SignerIp = "SignerIp";
            public const string DomainName = "DomainName";      // primary domain for SSL/TLS orders
            public const string KeyType = "KeyType";
        }

        public static class Products
        {
            public const string DvSsl                = "DV SSL";
            public const string DvSslWildcard        = "DV SSL Wildcard";
            public const string DvSslUcc             = "DV SSL Multi-Domain (UCC)";
            public const string DvSslWildcardUcc     = "DV SSL Wildcard Multi-Domain (UCC)";
            public const string OvSsl                = "OV SSL";
            public const string OvSslWildcard        = "OV SSL Wildcard";
            public const string OvSslUcc             = "OV SSL Multi-Domain (UCC)";
            public const string OvSslWildcardUcc     = "OV SSL Wildcard Multi-Domain (UCC)";
            public const string EvSsl                = "EV SSL";
            public const string EvSslUcc             = "EV SSL Multi-Domain (UCC)";

            // Default production numeric codes. These are the standard codes for the
            // CERTInext production environment. Sandbox codes differ — set ProductCode
            // explicitly on the template to override when targeting sandbox.
            public static readonly System.Collections.Generic.Dictionary<string, string> DefaultProductCodes =
                new System.Collections.Generic.Dictionary<string, string>(System.StringComparer.OrdinalIgnoreCase)
                {
                    [DvSsl]             = "838",
                    [DvSslWildcard]     = "839",
                    [DvSslUcc]          = "840",
                    [DvSslWildcardUcc]  = "841",
                    [OvSsl]             = "842",
                    [OvSslWildcard]     = "843",
                    [OvSslUcc]          = "844",
                    [OvSslWildcardUcc]  = "845",
                    [EvSsl]             = "846",
                    [EvSslUcc]          = "847",
                };
        }

        public static class CertificateStatusId
        {
            // CERTInext certificateStatusId integer values (from TrackOrder response)
            public const int SetupPending = 1;
            public const int PendingForApprover = 2;
            public const int UnderDiscrepancy = 3;
            public const int Approved = 4;
            public const int Rejected = 5;
            public const int PendingSecondApprover = 6;
            public const int ApprovedBySecondApprover = 7;
            public const int RejectedBySecondApprover = 8;
            public const int CertificateDownloaded = 9;
            public const int CertificateExpired = 12;
            public const int RejectedDueToOrderCancellation = 13;
            public const int AutoRejected = 14;
            public const int OrderAutoApproved = 15;
            public const int PendingLra = 16;
            public const int ApprovedLra = 17;
            public const int RejectedLra = 18;
            public const int InvalidConfiguration = 19;
            public const int CertificateGenerated = 20;
            public const int DownloadRejected = 21;
            public const int CertificateRevoked = 22;
            public const int RekeyApproved = 23;
            public const int PendingForApproverAutoApproval = 24;
        }

        public static class OrderStatusId
        {
            // CERTInext orderStatusId integer values (from TrackOrder response)
            public const int OrderPlaced = 1;
            public const int OrderAccepted = 2;
            public const int OrderInProgress = 3;
            public const int OrderRejected = 4;
            public const int OrderCancelled = 5;
            public const int OrderFulfilled = 6;
            public const int OnHold = 7;
            public const int PendingForApproval = 8;
            public const int PendingForAdminApproval = 9;
        }

        // Legacy string-status constants — retained so StatusMapper switch still compiles.
        // The real API returns numeric IDs; these are used only for internal mapping logic.
        public static class CertificateStatus
        {
            public const string Active = "active";
            public const string Issued = "issued";
            public const string Pending = "pending";
            public const string PendingApproval = "pending_approval";
            public const string Revoked = "revoked";
            public const string Expired = "expired";
            public const string Rejected = "rejected";
            public const string Failed = "failed";
            public const string Processing = "processing";
            public const string Cancelled = "cancelled";
        }

        public static class Api
        {
            // CERTInext REST API endpoint names (appended directly to base URL)
            // All endpoints use HTTP POST with JSON body containing a "meta" authentication block.
            public const string ValidateCredentialsPath = "ValidateCredentials";
            public const string GenerateOrderSslPath    = "GenerateOrderSSL";
            public const string GenerateOrderSmimePath  = "GenerateOrderSMIME";
            public const string GenerateOrderSignaturePath = "GenerateOrderSignature";
            public const string GenerateOrderPrivatePkiPath = "GenerateOrderPrivatePKI";
            public const string SubmitCsrPath           = "SubmitCSR";
            public const string SubmitDocumentPath      = "SubmitDocument";
            public const string TrackOrderPath          = "TrackOrder";
            public const string GetCertificatePath      = "GetCertificate";
            public const string RevokeOrderPath         = "RevokeOrder";
            public const string RejectOrderPath         = "RejectOrder";
            public const string GetProductDetailsPath   = "GetProductDetails";
            public const string GetOrderReportPath      = "GetOrderReport";
            public const string GetDcvPath              = "GetDcv";
            public const string VerifyDcvPath           = "VerifyDcv";
            public const string GetGroupDetailsPath     = "GetGroupDetails";
            public const string GetOrganizationDetailsPath = "GetOrganizationDetails";
            public const string GetDomainDetailsPath    = "GetDomainDetails";

            // Meta version string required in every request
            public const string MetaVersion = "1.0";

            // Pagination (used in GetOrderReport searchCriteria)
            public const int DefaultPageSize = 100;
            public const int MaxPageSize = 500;

            // Legacy path constants — kept so CERTInextClient can still reference them
            // without breaking existing callers while being replaced.
            // These do NOT exist in the real API.
            [System.Obsolete("The real CERTInext API does not have this endpoint. Use ValidateCredentialsPath.")]
            public const string HealthPath = "ValidateCredentials";

            [System.Obsolete("The real CERTInext API does not have this endpoint. Use GetOrderReportPath + TrackOrderPath.")]
            public const string CertificatesPath = "GetOrderReport";

            [System.Obsolete("The real CERTInext API does not have this endpoint. Use RevokeOrderPath.")]
            public const string RevokePath = "RevokeOrder";

            [System.Obsolete("The real CERTInext API does not have this endpoint. Use GenerateOrderSslPath.")]
            public const string RenewPath = "GenerateOrderSSL";

            [System.Obsolete("The real CERTInext API does not have this endpoint. Use GetProductDetailsPath.")]
            public const string ProfilesPath = "GetProductDetails";

            [System.Obsolete("The real CERTInext API does not have this token endpoint. OAuth tokens are obtained from the IdP configured in your CERTInext account.")]
            public const string TokenPath = "/oauth/token";
        }

        public static class RevocationReasonId
        {
            // CERTInext revokeReasonId integer values (from RevokeOrder request)
            // Only these five reason IDs are accepted by the API.
            public const int KeyCompromise = 1;
            public const int AffiliationChanged = 3;
            public const int Superseded = 4;
            public const int CessationOfOperation = 5;
            public const int PrivilegeWithdrawn = 9;

            // Default fallback when the CRL reason code has no CERTInext equivalent
            public const int Default = KeyCompromise;
        }

        public static class Dcv
        {
            // CERTInext dcvMethod values (dcvDetails.dcvMethod in GetDcv / VerifyDcv)
            public const string MethodDnsTxt      = "1";              // DNS TXT record (numeric, used in API requests)
            public const string MethodDnsTxtLabel = "DNS TXT Record"; // DNS TXT record (string label returned by TrackOrder)
            public const string MethodHttpFile    = "2";              // HTTP file validation
            public const string MethodEmail       = "3";              // Email validation

            // CERTInext dcvStatus values (per-domain entries in TrackOrder domainVerification)
            public const string StatusPending   = "0";
            public const string StatusValidated = "1";
            public const string StatusRejected  = "2";

            // Default TXT record hostname template; {0} is replaced with the bare domain name.
            // Override via the DcvTxtRecordTemplate connector config field.
            public const string DefaultTxtRecordTemplate = "_emsign-validation.{0}";

            // Defaults for the DCV-during-sync bounds (issue 0002).
            public const int DefaultSyncMaxOrderAgeHours = 24;
            public const int DefaultSyncMaxPerPass = 50;

            // Propagation delay used on the *sync* DCV path (issue 0002). Sync runs frequently
            // and bounds work per pass, so it uses a short delay rather than the full
            // DcvPropagationDelaySeconds (which the Enroll path uses for a one-shot finish).
            // A few seconds is enough for the staged TXT to be visible to CERTInext's resolver;
            // if a verify lands too early, the order simply stays pending and is retried next pass.
            public const int SyncPropagationDelaySeconds = 3;
        }

        // Legacy string revocation reasons — retained so StatusMapper still compiles.
        public static class RevocationReason
        {
            public const string Unspecified = "unspecified";
            public const string KeyCompromise = "keyCompromise";
            public const string CACompromise = "caCompromise";
            public const string AffiliationChanged = "affiliationChanged";
            public const string Superseded = "superseded";
            public const string CessationOfOperation = "cessationOfOperation";
            public const string CertificateHold = "certificateHold";
            public const string RemoveFromCRL = "removeFromCRL";
            public const string PrivilegeWithdrawn = "privilegeWithdrawn";
            public const string AACompromise = "aACompromise";
        }
    }
}
