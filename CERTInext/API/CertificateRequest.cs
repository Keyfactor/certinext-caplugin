// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.API
{
    // ---------------------------------------------------------------------------
    // Meta block — required in every CERTInext API request body.
    // authKey = SHA256(accessKey + ts + txn)  (hex, lowercase)
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Authentication and correlation metadata included in the body of every
    /// CERTInext API request.
    /// </summary>
    public class RequestMeta
    {
        /// <summary>API schema version. Always "1.0".</summary>
        [JsonPropertyName("ver")]
        public string Ver { get; set; } = Constants.Api.MetaVersion;

        /// <summary>ISO 8601 request timestamp, e.g. "2024-04-04T11:36:55+05:30".</summary>
        [JsonPropertyName("ts")]
        public string Ts { get; set; }

        /// <summary>Unique transaction ID (alphanumeric, 10–50 chars).</summary>
        [JsonPropertyName("txn")]
        public string Txn { get; set; }

        /// <summary>CERTInext account number (numeric string).</summary>
        [JsonPropertyName("accountNumber")]
        public string AccountNumber { get; set; }

        /// <summary>
        /// Computed authentication key: SHA256(accessKey + ts + txn) in lowercase hex.
        /// The raw Access Key is never transmitted — only this derived value.
        /// </summary>
        [JsonPropertyName("authKey")]
        public string AuthKey { get; set; }
    }

    // ---------------------------------------------------------------------------
    // ValidateCredentials  — POST {baseURL}ValidateCredentials
    // Used as the health / connectivity probe.
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Request body for POST {baseURL}ValidateCredentials.
    /// Only the meta authentication block is required.
    /// </summary>
    public class ValidateCredentialsRequest
    {
        [JsonPropertyName("meta")]
        public RequestMeta Meta { get; set; }
    }

    // ---------------------------------------------------------------------------
    // GetProductDetails  — POST {baseURL}GetProductDetails
    // Retrieves available product (profile) codes for an account/group.
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Request body for POST {baseURL}GetProductDetails.
    /// </summary>
    public class GetProductDetailsRequest
    {
        [JsonPropertyName("meta")]
        public RequestMeta Meta { get; set; }

        [JsonPropertyName("productDetails")]
        public ProductDetailsFilter ProductDetails { get; set; }
    }

    public class ProductDetailsFilter
    {
        /// <summary>Optional group number to filter products by.</summary>
        [JsonPropertyName("groupNumber")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string GroupNumber { get; set; }
    }

    // ---------------------------------------------------------------------------
    // GenerateOrderSSL  — POST {baseURL}GenerateOrderSSL
    // Used for SSL/TLS DV, OV, EV certificate orders (including wildcard and UCC).
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Request body for POST {baseURL}GenerateOrderSSL.
    /// Covers all SSL/TLS product types (DV, OV, EV, wildcard, UCC).
    /// </summary>
    public class GenerateOrderSslRequest
    {
        [JsonPropertyName("meta")]
        public RequestMeta Meta { get; set; }

        [JsonPropertyName("orderDetails")]
        public SslOrderDetails OrderDetails { get; set; }
    }

    public class SslOrderDetails
    {
        /// <summary>Numeric product code provided by eMudhra/CERTInext.</summary>
        [JsonPropertyName("productCode")]
        public string ProductCode { get; set; }

        /// <summary>"2" = credit-based, "1" = cash model. Default "2".</summary>
        [JsonPropertyName("accountingModel")]
        public string AccountingModel { get; set; } = "2";

        /// <summary>"0" = generate order immediately; "1" = save as draft.</summary>
        [JsonPropertyName("saveAndHold")]
        public string SaveAndHold { get; set; } = "0";

        /// <summary>"1" = send all notifications.</summary>
        [JsonPropertyName("emailNotifications")]
        public string EmailNotifications { get; set; } = "1";

        [JsonPropertyName("requestorInformation")]
        public RequestorInformation RequestorInformation { get; set; }

        [JsonPropertyName("subscriptionDetails")]
        public SubscriptionDetails SubscriptionDetails { get; set; }

        [JsonPropertyName("certificateInformation")]
        public CertificateInformation CertificateInformation { get; set; }

        /// <summary>PEM-encoded PKCS#10 CSR. May be submitted with the order or separately via SubmitCSR.</summary>
        [JsonPropertyName("csr")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string Csr { get; set; }

        [JsonPropertyName("agreementDetails")]
        public AgreementDetails AgreementDetails { get; set; }

        [JsonPropertyName("organizationDetails")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public OrganizationDetails OrganizationDetails { get; set; }

        [JsonPropertyName("additionalInformation")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public AdditionalInformation AdditionalInformation { get; set; }
    }

    public class RequestorInformation
    {
        [JsonPropertyName("requestorName")]
        public string RequestorName { get; set; }

        [JsonPropertyName("requestorIsdCode")]
        public string RequestorIsdCode { get; set; } = "1";

        [JsonPropertyName("requestorMobileNumber")]
        public string RequestorMobileNumber { get; set; }

        [JsonPropertyName("requestorEmail")]
        public string RequestorEmail { get; set; }

        [JsonPropertyName("requestorDesignation")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string RequestorDesignation { get; set; }
    }

    public class SubscriptionDetails
    {
        /// <summary>Validity in years: "1", "2", or "3". Default "1".</summary>
        [JsonPropertyName("validity")]
        public string Validity { get; set; } = "1";

        /// <summary>"1" = allow auto-renewal; "0" = decline.</summary>
        [JsonPropertyName("autoRenew")]
        public string AutoRenew { get; set; } = "1";

        /// <summary>Days before expiry to auto-renew: "30" or "60".</summary>
        [JsonPropertyName("renewCriteria")]
        public string RenewCriteria { get; set; } = "30";
    }

    public class CertificateInformation
    {
        /// <summary>Primary domain name for the certificate.</summary>
        [JsonPropertyName("domainName")]
        public string DomainName { get; set; }

        /// <summary>Additional domain names (SAN) for UCC products.</summary>
        [JsonPropertyName("additionalDomains")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public List<string> AdditionalDomains { get; set; }

        /// <summary>"1" = also secure www variant (default); "0" = disable.</summary>
        [JsonPropertyName("autoSecureWWW")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string AutoSecureWww { get; set; }
    }

    public class AgreementDetails
    {
        [JsonPropertyName("acceptAgreement")]
        public string AcceptAgreement { get; set; } = "1";

        [JsonPropertyName("signerName")]
        public string SignerName { get; set; }

        [JsonPropertyName("signerPlace")]
        public string SignerPlace { get; set; }

        [JsonPropertyName("signerIP")]
        public string SignerIp { get; set; }
    }

    public class OrganizationDetails
    {
        /// <summary>"0" = new org; "1" = use pre-vetted org.</summary>
        [JsonPropertyName("preVetting")]
        public string PreVetting { get; set; } = "0";

        [JsonPropertyName("organizationNumber")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string OrganizationNumber { get; set; }
    }

    public class AdditionalInformation
    {
        [JsonPropertyName("remarks")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string Remarks { get; set; }

        [JsonPropertyName("tags")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public List<string> Tags { get; set; }
    }

    // ---------------------------------------------------------------------------
    // SubmitCSR  — POST {baseURL}SubmitCSR
    // Submits the CSR to an existing order that was created without one.
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Request body for POST {baseURL}SubmitCSR.
    /// </summary>
    public class SubmitCsrRequest
    {
        [JsonPropertyName("meta")]
        public RequestMeta Meta { get; set; }

        [JsonPropertyName("orderDetails")]
        public SubmitCsrOrderDetails OrderDetails { get; set; }
    }

    public class SubmitCsrOrderDetails
    {
        [JsonPropertyName("orderNumber")]
        public string OrderNumber { get; set; }

        [JsonPropertyName("requestorEmail")]
        public string RequestorEmail { get; set; }

        /// <summary>PEM-encoded PKCS#10 CSR.</summary>
        [JsonPropertyName("csr")]
        public string Csr { get; set; }
    }

    // ---------------------------------------------------------------------------
    // TrackOrder  — POST {baseURL}TrackOrder
    // Retrieves the current status of an order/certificate.
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Request body for POST {baseURL}TrackOrder.
    /// </summary>
    public class TrackOrderRequest
    {
        [JsonPropertyName("meta")]
        public RequestMeta Meta { get; set; }

        [JsonPropertyName("orderDetails")]
        public TrackOrderDetails OrderDetails { get; set; }
    }

    public class TrackOrderDetails
    {
        [JsonPropertyName("orderNumber")]
        public string OrderNumber { get; set; }
    }

    // ---------------------------------------------------------------------------
    // GetDcv  — POST {baseURL}GetDcv
    // Retrieves Domain Control Validation token / file content / approver emails
    // for a given (orderNumber, domainName, dcvMethod) tuple.
    //
    // The CERTInext V1 spec defines this body as wrapped in a "dcvDetails" block.
    // Note: the Postman example for GetDcv uses "orderDetails" instead — this is
    // an example typo; the inline spec, the response body, and the VerifyDcv body
    // all use "dcvDetails" consistently.
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Request body for POST {baseURL}GetDcv.
    /// Returns DCV instructions (token / file / approver emails) for one domain
    /// in the given order.
    /// </summary>
    public class GetDcvRequest
    {
        [JsonPropertyName("meta")]
        public RequestMeta Meta { get; set; }

        [JsonPropertyName("dcvDetails")]
        public DcvRequestDetails DcvDetails { get; set; }
    }

    /// <summary>
    /// Common request body for both GetDcv and VerifyDcv — both endpoints take the
    /// same set of identification fields. <see cref="DcvEmail"/> is only set on
    /// VerifyDcv requests when <see cref="DcvMethod"/> = email (3).
    /// </summary>
    public class DcvRequestDetails
    {
        /// <summary>Registered requestor email associated with the order.</summary>
        [JsonPropertyName("requestorEmail")]
        public string RequestorEmail { get; set; }

        /// <summary>Order number returned by GenerateOrderSSL.</summary>
        [JsonPropertyName("orderNumber")]
        public string OrderNumber { get; set; }

        /// <summary>Domain to retrieve / verify DCV for.</summary>
        [JsonPropertyName("domainName")]
        public string DomainName { get; set; }

        /// <summary>
        /// DCV method (numeric string per CERTInext V1 spec):
        /// "1" = DNS TXT record, "2" = HTTP file, "3" = email approver.
        /// See <see cref="Constants.Dcv"/>.
        /// </summary>
        [JsonPropertyName("dcvMethod")]
        public string DcvMethod { get; set; }

        /// <summary>
        /// Approver email address. Required (and only used) on VerifyDcv when
        /// <see cref="DcvMethod"/> is "3" (email). Must be one of the
        /// <c>dcvEmails</c> returned by GetDcv.
        /// </summary>
        [JsonPropertyName("dcvEmail")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string DcvEmail { get; set; }
    }

    // ---------------------------------------------------------------------------
    // VerifyDcv  — POST {baseURL}VerifyDcv
    // Triggers CERTInext to verify the DCV record placed by the customer.
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Request body for POST {baseURL}VerifyDcv.
    /// Tells CERTInext to attempt domain verification using the previously
    /// supplied DCV details. Reuses <see cref="DcvRequestDetails"/>.
    /// </summary>
    public class VerifyDcvRequest
    {
        [JsonPropertyName("meta")]
        public RequestMeta Meta { get; set; }

        [JsonPropertyName("dcvDetails")]
        public DcvRequestDetails DcvDetails { get; set; }
    }

    // ---------------------------------------------------------------------------
    // GetCertificate  — POST {baseURL}GetCertificate
    // Downloads the issued certificate for a fulfilled order.
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Request body for POST {baseURL}GetCertificate.
    /// </summary>
    public class GetCertificateRequest
    {
        [JsonPropertyName("meta")]
        public RequestMeta Meta { get; set; }

        [JsonPropertyName("orderDetails")]
        public GetCertificateOrderDetails OrderDetails { get; set; }
    }

    public class GetCertificateOrderDetails
    {
        [JsonPropertyName("orderNumber")]
        public string OrderNumber { get; set; }

        [JsonPropertyName("requestorEmail")]
        public string RequestorEmail { get; set; }
    }

    // ---------------------------------------------------------------------------
    // RevokeOrder  — POST {baseURL}RevokeOrder
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Request body for POST {baseURL}RevokeOrder.
    /// </summary>
    public class RevokeOrderRequest
    {
        [JsonPropertyName("meta")]
        public RequestMeta Meta { get; set; }

        [JsonPropertyName("revocationDetails")]
        public RevocationDetails RevocationDetails { get; set; }
    }

    public class RevocationDetails
    {
        [JsonPropertyName("orderNumber")]
        public string OrderNumber { get; set; }

        [JsonPropertyName("requestorEmail")]
        public string RequestorEmail { get; set; }

        /// <summary>
        /// CERTInext revocation reason ID:
        /// 1 = KeyCompromise, 3 = AffiliationChanged, 4 = Superseded,
        /// 5 = CessationOfOperation, 9 = PrivilegeWithdrawn.
        /// </summary>
        [JsonPropertyName("revokeReasonId")]
        public string RevokeReasonId { get; set; }

        [JsonPropertyName("revokeRemarks")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string RevokeRemarks { get; set; }
    }

    // ---------------------------------------------------------------------------
    // GetOrderReport  — POST {baseURL}GetOrderReport
    // Paginated order/certificate listing used for synchronization.
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Request body for POST {baseURL}GetOrderReport.
    /// </summary>
    public class GetOrderReportRequest
    {
        [JsonPropertyName("meta")]
        public RequestMeta Meta { get; set; }

        [JsonPropertyName("searchCriteria")]
        public OrderReportSearchCriteria SearchCriteria { get; set; }
    }

    public class OrderReportSearchCriteria
    {
        [JsonPropertyName("productCode")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string ProductCode { get; set; }

        [JsonPropertyName("groupNumber")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string GroupNumber { get; set; }

        /// <summary>Filter: order date from (inclusive), format "YYYY-MM-DD" or ISO 8601.</summary>
        [JsonPropertyName("orderDateFrom")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string OrderDateFrom { get; set; }

        [JsonPropertyName("orderDateTill")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string OrderDateTill { get; set; }

        [JsonPropertyName("domainName")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string DomainName { get; set; }

        [JsonPropertyName("orderNumber")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string OrderNumber { get; set; }

        /// <summary>Filter by orderStatusId (numeric string).</summary>
        [JsonPropertyName("orderStatusId")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string OrderStatusId { get; set; }

        [JsonPropertyName("certExpiryDateFrom")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string CertExpiryDateFrom { get; set; }

        [JsonPropertyName("certExpiryDateTill")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string CertExpiryDateTill { get; set; }

        [JsonPropertyName("requestorEmailId")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string RequestorEmailId { get; set; }

        /// <summary>1-based page number.</summary>
        [JsonPropertyName("pageNumber")]
        public string PageNumber { get; set; } = "1";

        [JsonPropertyName("pageSize")]
        public string PageSize { get; set; } = "100";

        /// <summary>"1" = include full chain; any other value = leaf only.</summary>
        [JsonPropertyName("certificateChain")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string CertificateChain { get; set; }

        /// <summary>"1" = public trust; "2" = private PKI.</summary>
        [JsonPropertyName("certificateTrustType")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string CertificateTrustType { get; set; }
    }

    // ---------------------------------------------------------------------------
    // Legacy request types — retained so the existing ICERTInextClient interface
    // and unit tests continue to compile while the client is incrementally updated.
    // These do not match the real CERTInext wire format.
    // ---------------------------------------------------------------------------

    /// <summary>
    /// LEGACY: used by the inferred REST design. Not present in the real CERTInext API.
    /// Use <see cref="GenerateOrderSslRequest"/> instead.
    /// </summary>
    public class EnrollCertificateRequest
    {
        [JsonPropertyName("profileId")]
        public string ProfileId { get; set; }

        [JsonPropertyName("csr")]
        public string Csr { get; set; }

        [JsonPropertyName("validityDays")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public int? ValidityDays { get; set; }

        [JsonPropertyName("subject")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string Subject { get; set; }

        [JsonPropertyName("sans")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public System.Collections.Generic.List<SanEntry> Sans { get; set; }

        [JsonPropertyName("requesterName")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string RequesterName { get; set; }

        [JsonPropertyName("requesterEmail")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string RequesterEmail { get; set; }

        [JsonPropertyName("comment")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string Comment { get; set; }

        [JsonPropertyName("keyType")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string KeyType { get; set; }

        [JsonPropertyName("customFields")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public System.Collections.Generic.Dictionary<string, string> CustomFields { get; set; }
    }

    /// <summary>Legacy SAN entry type used by <see cref="EnrollCertificateRequest"/>.</summary>
    public class SanEntry
    {
        [JsonPropertyName("type")]
        public string Type { get; set; }

        [JsonPropertyName("value")]
        public string Value { get; set; }
    }

    /// <summary>
    /// LEGACY: used by the inferred REST design. Not present in the real CERTInext API.
    /// Use <see cref="GenerateOrderSslRequest"/> with a new CSR instead.
    /// </summary>
    public class RenewCertificateRequest
    {
        [JsonPropertyName("csr")]
        public string Csr { get; set; }

        [JsonPropertyName("validityDays")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public int? ValidityDays { get; set; }

        [JsonPropertyName("requesterName")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string RequesterName { get; set; }

        [JsonPropertyName("requesterEmail")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string RequesterEmail { get; set; }

        [JsonPropertyName("comment")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string Comment { get; set; }
    }

    /// <summary>
    /// LEGACY: used by the inferred REST design. Not present in the real CERTInext API.
    /// Use <see cref="RevokeOrderRequest"/> instead.
    /// </summary>
    public class RevokeCertificateRequest
    {
        /// <summary>CRL reason string (e.g. "keyCompromise"). Mapped to revokeReasonId in RevokeOrderRequest.</summary>
        [JsonPropertyName("reason")]
        public string Reason { get; set; }

        [JsonPropertyName("comment")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string Comment { get; set; }
    }

    /// <summary>
    /// OAuth2 client-credentials token request form data.
    /// Only applicable when CERTInext account is configured for OAuth auth type.
    /// </summary>
    public class OAuth2TokenRequest
    {
        [JsonPropertyName("grant_type")]
        public string GrantType { get; set; } = "client_credentials";

        [JsonPropertyName("client_id")]
        public string ClientId { get; set; }

        [JsonPropertyName("client_secret")]
        public string ClientSecret { get; set; }
    }
}
