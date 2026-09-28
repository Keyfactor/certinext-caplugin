// Copyright 2026 Keyfactor
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
            public const string SubmitNonDnsSans = "SubmitNonDnsSans";
            public const string PageSize = "PageSize";

            // Synchronous certificate pickup (parity with the legacy Sectigo connector).
            // After submitting an order, Enroll() polls GetCertificate up to PickupRetries
            // times, PickupDelay seconds apart (after a fixed initial delay), so a fast-issuing
            // order returns the issued certificate in the same enrollment call instead of
            // waiting for the next synchronization. On timeout the order is returned pending and
            // imported by a later sync — behaviour identical to before this feature.
            public const string PickupRetries = "PickupRetries";
            public const string PickupDelay = "PickupDelay";

            public const string RequestorName = "RequestorName";
            public const string RequestorEmail = "RequestorEmail";
            public const string RequestorIsdCode = "RequestorIsdCode";
            public const string RequestorMobileNumber = "RequestorMobileNumber";
            public const string RequestorDesignation = "RequestorDesignation";
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

            // V2 mode only: incremental-sync lookback window for /reports/orders (issues/0022).
            public const string V2SyncLookbackHours = "V2SyncLookbackHours";

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

            // V2 API enrollment parameters
            public const string ProductFamily = "ProductFamily";  // V2: "ssl", "private-pki", or "signature"
            public const string ProductVariant = "ProductVariant"; // V2: "dv", "ov", or "ev"
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

            // V1-ONLY. Default production numeric codes for the CERTInext V1 (legacy) API.
            // These are the standard codes for the CERTInext production environment under V1.
            // Sandbox codes differ — set ProductCode explicitly on the template to override
            // when targeting sandbox.
            //
            // Do NOT reuse this table for V2 dispatch: its numbering does not match the live
            // V2 catalog (issue 0036 — e.g. this table's "842" is OV SSL, but the live V2
            // catalog's "842" is DV SSL, a flat +4 offset across all 10 codes). V2 resolves the
            // product code live from the Catalog response instead — see ProductTypeIdsV2 below
            // and EnrollV2Async/ValidateProductInfo in CERTInextCAPlugin.cs.
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

            // V2-ONLY. Maps each product name (ProductId, as advertised by GetProductIds()) to
            // the CERTInext V2 catalog's stable numeric productTypeID value (spec:
            // docs/reference/specs/CERTInext API v2.postman_collection (1).json, "Get Product
            // Details" field vocabulary). productTypeID is the CA's own documented mechanism
            // for "programmatic routing" (its docs explicitly say productName is "for display"
            // only) — unlike productCode (V1-era table above, wrong numbering for V2) or
            // productName (varies by account/catalog version: the live catalog, the V1 Postman
            // table, and the V2 Postman table each use different spellings/suffixes for the same
            // product — see issue 0036), productTypeID is a small, stable, CERTInext-documented
            // enum. F3 independently reached the same conclusion for UCC detection and
            // live-verified 15/18/20/21/22 against the real V2 sandbox catalog
            // (issues/f3-v2-multi-san-limitation.md); the other five (13/14/16/17/19) are
            // spec-documented but not yet independently live-probed.
            //
            // Used by EnrollV2Async/ValidateProductInfo to resolve/validate the real V2 product
            // code from the live catalog when no explicit ProductCode override is configured.
            // Never used for V1.
            public static readonly System.Collections.Generic.Dictionary<string, string> ProductTypeIdsV2 =
                new System.Collections.Generic.Dictionary<string, string>(System.StringComparer.OrdinalIgnoreCase)
                {
                    [DvSsl]             = "13",
                    [DvSslWildcard]     = "14",
                    [DvSslUcc]          = "15",
                    [DvSslWildcardUcc]  = "21",
                    [OvSsl]             = "16",
                    [OvSslWildcard]     = "17",
                    [OvSslUcc]          = "18",
                    [OvSslWildcardUcc]  = "22",
                    [EvSsl]             = "19",
                    [EvSslUcc]          = "20",
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

        public static class Pickup
        {
            // Defaults mirror the legacy Sectigo connector's PickUpEnrolledCertificate:
            // a 5-second initial delay, then up to 5 poll attempts 10 seconds apart, so the
            // maximum time an enrollment call occupies a Command worker thread is
            // InitialDelaySeconds + DefaultRetries * DefaultDelaySeconds = 5 + 5*10 = 55 seconds.
            // Set PickupRetries to 0 to disable the wait entirely (immediate pending return).
            public const int DefaultRetries = 5;
            public const int DefaultDelaySeconds = 10;

            // Small static delay before the first poll — gives a fast order a chance to finish
            // issuing before we poll at all, avoiding a guaranteed-miss first attempt.
            public const int InitialDelaySeconds = 5;

            // Per-factor safety clamps so a single mis-typed value cannot produce a tight busy-loop
            // or an absurd per-attempt delay. These bound each knob independently; the *product*
            // (retries * delay) is bounded separately by MaxTotalWaitSeconds below.
            public const int MaxRetries = 30;
            public const int MaxDelaySeconds = 60;

            // Hard ceiling on total in-call pickup occupancy (initial delay + retries * delay).
            // The per-factor clamps above still permit a ~1805s product at the extremes, which could
            // push Enroll() past Command's enrollment timeout; PickUpEnrolledCertificateAsync caps the
            // effective retry count so the total never exceeds this. Kept comfortably under a typical
            // enrollment timeout while leaving room for the documented ~90s default guidance.
            public const int MaxTotalWaitSeconds = 180;
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

            // Independent bound for a single CleanupValidation (TXT-record removal) call. This is
            // deliberately its own fixed ceiling, not a fraction of DcvTimeoutMinutes and not the
            // ambient DCV-flow cancellation token: cleanup is a best-effort compensating action that
            // must get a real chance to run even when the operation it's cleaning up after was
            // itself cancelled (the ambient token would already be cancelled at that point), but it
            // still must not be allowed to hang the calling gateway request forever if a DNS
            // provider plugin's underlying network call stalls. 60s comfortably covers a single
            // DELETE-shaped call under normal conditions (the reference CloudflareDomainValidator's
            // HttpClient default alone is 100s) without risking an indefinite hang.
            public const int CleanupValidationTimeoutSeconds = 60;

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

        /// <summary>
        /// V2 REST API constants — all paths, status strings, and family slugs for the
        /// <c>/api/certinext/v2/</c> surface. Auth is OAuth2 client_credentials. The plugin sends
        /// an <c>Idempotency-Key</c> header on order-create/revoke, but the spec only documents
        /// this header (as "parsed today, enforced in a future release") on Verify DCV and Domains
        /// endpoints, not order-create/revoke — see issue 0032.
        /// </summary>
        public static class ApiV2
        {
            // Auth / connectivity
            public const string TokenPath         = "/oauth/token";
            public const string AuthMePath        = "/api/certinext/v2/auth/me";

            // Product-family resource paths (appended to base URL)
            public const string SslCertificatesPath        = "/api/certinext/v2/ssl-certificates";
            public const string PrivatePkiCertificatesPath = "/api/certinext/v2/private-pki-certificates";
            public const string SignatureCertificatesPath  = "/api/certinext/v2/signature-certificates";
            public const string CatalogProductsPath        = "/api/certinext/v2/catalog/products";

            // Order status strings (V2 REST — NOT numeric IDs)
            public const string StatusPendingDcv                     = "pending-dcv";
            public const string StatusPendingCsr                     = "pending-csr";
            public const string StatusPendingAgreement               = "pending-agreement";
            public const string StatusPendingOrganizationVerification = "pending-organization-verification";
            public const string StatusPendingDocuments                = "pending-documents";
            public const string StatusPendingApproval                 = "pending-approval";
            public const string StatusIssued                          = "issued";
            public const string StatusCancelled                       = "cancelled";
            public const string StatusRevoked                         = "revoked";
            public const string StatusRejected                        = "rejected";
            public const string StatusExpired                         = "expired";

            // Product-family slugs (used as URL path segments)
            public const string FamilySsl        = "ssl-certificates";
            public const string FamilyPrivatePki = "private-pki-certificates";
            public const string FamilySignature  = "signature-certificates";

            // productVariant values that require an organization block (issue 0028) — every
            // other value (dv and its wildcard/UCC combinations) omits it entirely.
            public const string ProductVariantOv = "ov";
            public const string ProductVariantEv = "ev";

            // Fixed designation sent on technicalPointOfContact.designation (issue 0030). The
            // spec documents this as free text with no enum (examples: "Technical Contact",
            // "IT Administrator", "PKI Manager", "Authorized Signer") and there is no connector
            // config field for it — deliberately out of scope for issue 0027 item 5e's
            // RequestorDesignation fix (Config.RequestorDesignation), which only covers
            // requestor.designation. No existing generic designation/title config field was
            // found to reuse for this one, so this remains a fixed default.
            public const string DefaultTechnicalContactDesignation = "Technical Contact";

            // UCC (multi-SAN) product family detection — from the live Catalog response's
            // productTypeID field: 15=DV SSL UCC, 18=OV SSL UCC, 20=EV SSL UCC,
            // 21=DV SSL Wildcard UCC, 22=OV SSL Wildcard UCC (issues/f3-v2-multi-san-limitation.md).
            // Deliberately NOT derived from Constants.Products.DefaultProductCodes — that table's
            // numbering disagrees with the live/spec numbering (issue 0036).
            public static readonly System.Collections.Generic.HashSet<string> UccProductTypeIds =
                new System.Collections.Generic.HashSet<string> { "15", "18", "20", "21", "22" };

            // Orders report (Synchronize, V2 mode) — GET /api/certinext/v2/reports/orders.
            // Spring-style page envelope: content/page/size/totalPages/totalElements.
            // Paging is 1-based; size is clamped to 100 server-side; page=0 is treated as
            // page 1 (issues/0022 Phase 0 live probe findings).
            public const string OrdersReportPath = "/api/certinext/v2/reports/orders";
            public const int OrdersReportMaxPageSize = 100;

            // Default lookback window (issues/0022): live probing could not determine
            // whether /reports/orders' from/to filter brackets order date or issue date.
            // An incremental sync re-requests from (lastSync - this window) rather than
            // exactly lastSync, so an order created before lastSync but issued after it
            // (e.g. a slow-DCV order) still surfaces. See CERTInextConfig.V2SyncLookbackHours.
            public const int DefaultSyncLookbackHours = 72;
        }

        // V2 config key constants (added here alongside existing Config constants)
        public static class ConfigV2
        {
            public const string UseV2Api      = "UseV2Api";
        }

        // Legacy string revocation reasons — retained so StatusMapper still compiles.
        // V1 never puts these on the wire (RevokeOrderRequest sends a numeric
        // revokeReasonId — see CERTInextClient.RevokeCertificateAsync /
        // MapLegacyReasonStringToCrlCode), so this class is intentionally left
        // untouched by the 0019 V2 kebab-case fix; see RevocationReasonV2 below.
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

        // V2 API revocation reason strings. These must match the CERTInext V2 spec's
        // kebab-case `reason` enum exactly (docs/reference/specs/CERTInext API
        // v2.postman_collection.json, "Revoke Certificate"). Sending camelCase (the
        // pre-fix values, shared with the legacy RevocationReason class above) gets
        // HTTP 400 — see issues/0019. `AACompromise` is accepted on the
        // signature-certificates / private-pki-certificates revoke endpoints per spec,
        // but is not documented on ssl-certificates; kept here as the RFC 5280 code-10
        // mapping for those other families. There is no V2 equivalent of the RFC 5280
        // CRL-only "removeFromCRL" (code 8) reason, so it is intentionally absent here.
        public static class RevocationReasonV2
        {
            public const string Unspecified = "unspecified";
            public const string KeyCompromise = "key-compromise";
            public const string CACompromise = "ca-compromise";
            public const string AffiliationChanged = "affiliation-changed";
            public const string Superseded = "superseded";
            public const string CessationOfOperation = "cessation-of-operation";
            public const string CertificateHold = "certificate-hold";
            public const string PrivilegeWithdrawn = "privilege-withdrawn";
            public const string AACompromise = "aa-compromise";
        }
    }
}
