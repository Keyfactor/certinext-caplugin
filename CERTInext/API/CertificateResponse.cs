// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.API
{
    // ---------------------------------------------------------------------------
    // Response meta block — present in every CERTInext API response.
    // status "1" = success, "0" = failure.
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Meta block returned in every CERTInext API response.
    /// </summary>
    public class ResponseMeta
    {
        [JsonPropertyName("ver")]
        public string Ver { get; set; }

        /// <summary>Response timestamp (ISO 8601).</summary>
        [JsonPropertyName("ts")]
        public string Ts { get; set; }

        /// <summary>Echoed transaction ID from the request.</summary>
        [JsonPropertyName("txn")]
        public string Txn { get; set; }

        /// <summary>"1" = success, "0" = failure.</summary>
        [JsonPropertyName("status")]
        public string Status { get; set; }

        [JsonPropertyName("errorCode")]
        public string ErrorCode { get; set; }

        [JsonPropertyName("errorMessage")]
        public string ErrorMessage { get; set; }

        /// <summary>True when the API call succeeded.</summary>
        [JsonIgnore]
        public bool IsSuccess => Status == "1";
    }

    // ---------------------------------------------------------------------------
    // ValidateCredentials response  — POST {baseURL}ValidateCredentials
    // ---------------------------------------------------------------------------

    public class ValidateCredentialsResponse
    {
        [JsonPropertyName("meta")]
        public ResponseMeta Meta { get; set; }
    }

    // ---------------------------------------------------------------------------
    // GenerateOrderSSL / GenerateOrderSMIME / GenerateOrderSignature response
    // POST {baseURL}GenerateOrderSSL  etc.
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Response from GenerateOrderSSL, GenerateOrderSMIME, GenerateOrderSignature,
    /// GenerateOrderPrivatePKI.  The <c>orderNumber</c> is the stable certificate
    /// identifier used in all subsequent operations (TrackOrder, GetCertificate,
    /// RevokeOrder).  This becomes the <c>CARequestID</c> stored in Keyfactor Command.
    /// </summary>
    public class GenerateOrderResponse
    {
        [JsonPropertyName("meta")]
        public ResponseMeta Meta { get; set; }

        [JsonPropertyName("orderDetails")]
        public GenerateOrderResponseDetails OrderDetails { get; set; }
    }

    public class GenerateOrderResponseDetails
    {
        /// <summary>
        /// Unique request ID generated when saveAndHold = "1".
        /// This is only a draft; the order is not placed yet.
        /// </summary>
        [JsonPropertyName("requestNumber")]
        public string RequestNumber { get; set; }

        /// <summary>
        /// Unique order ID — this is the primary certificate identifier used in all
        /// subsequent API calls.  Becomes the <c>CARequestID</c> in Keyfactor Command.
        /// </summary>
        [JsonPropertyName("orderNumber")]
        public string OrderNumber { get; set; }

        [JsonPropertyName("trackingURL")]
        public string TrackingUrl { get; set; }
    }

    // ---------------------------------------------------------------------------
    // TrackOrder response  — POST {baseURL}TrackOrder
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Response from POST {baseURL}TrackOrder.
    /// Contains order status, certificate status, expiry, and revocation details.
    /// </summary>
    public class TrackOrderResponse
    {
        [JsonPropertyName("meta")]
        public ResponseMeta Meta { get; set; }

        [JsonPropertyName("orderDetails")]
        public TrackOrderResponseDetails OrderDetails { get; set; }
    }

    public class TrackOrderResponseDetails
    {
        [JsonPropertyName("trackingUrl")]
        public string TrackingUrl { get; set; }

        /// <summary>
        /// Order status numeric ID:
        /// 1=OrderPlaced, 2=Accepted, 3=InProgress, 4=Rejected, 5=Cancelled,
        /// 6=Fulfilled, 7=OnHold, 8=PendingApproval, 9=PendingAdminApproval.
        /// </summary>
        [JsonPropertyName("orderStatusId")]
        public string OrderStatusId { get; set; }

        [JsonPropertyName("orderStatus")]
        public string OrderStatus { get; set; }

        /// <summary>
        /// Certificate status numeric ID:
        /// 1=SetupPending, 2=PendingApprover, 4=Approved, 5=Rejected,
        /// 9=Downloaded, 12=Expired, 20=CertificateGenerated, 22=Revoked, etc.
        /// See <see cref="Constants.CertificateStatusId"/> for full list.
        /// </summary>
        [JsonPropertyName("certificateStatusId")]
        public string CertificateStatusId { get; set; }

        [JsonPropertyName("certificateStatus")]
        public string CertificateStatus { get; set; }

        /// <summary>Expiry date of the issued end-entity certificate (UTC string).</summary>
        [JsonPropertyName("certificateExpiryDate")]
        public string CertificateExpiryDate { get; set; }

        [JsonPropertyName("requestorInformation")]
        public TrackOrderRequestorInfo RequestorInformation { get; set; }

        [JsonPropertyName("revocationDetails")]
        public TrackOrderRevocationDetails RevocationDetails { get; set; }

        /// <summary>
        /// Per-domain DCV state plus a top-level <c>status</c> field. The wire
        /// shape mixes typed and dynamic keys: <c>{ "&lt;Domain Name&gt;": { ... },
        /// "status": "..." }</c>, so domain entries are surfaced via
        /// <see cref="TrackOrderDomainVerification.DomainEntries"/>.
        /// </summary>
        [JsonPropertyName("domainVerification")]
        public TrackOrderDomainVerification DomainVerification { get; set; }

        [JsonPropertyName("csr")]
        public string Csr { get; set; }
    }

    /// <summary>
    /// <c>domainVerification</c> block from TrackOrder. Wire shape is heterogeneous:
    /// a known <c>status</c> field at the top level alongside one entry per domain
    /// keyed by domain name. The per-domain entries are captured via
    /// <see cref="JsonExtensionDataAttribute"/> and exposed through
    /// <see cref="GetDomainEntries"/>.
    /// </summary>
    public class TrackOrderDomainVerification
    {
        /// <summary>Block-level status. Documented values mirror <see cref="DomainVerificationDetail.Status"/>.</summary>
        [JsonPropertyName("status")]
        public string Status { get; set; }

        /// <summary>
        /// Raw per-domain entries as parsed from the response. Keys are the domain
        /// names exactly as returned by CERTInext. Use <see cref="GetDomainEntries"/>
        /// for typed access.
        /// </summary>
        [JsonExtensionData]
        public Dictionary<string, JsonElement> RawDomainEntries { get; set; }

        /// <summary>
        /// Returns a typed dictionary of domain → <see cref="DomainVerificationDetail"/>,
        /// skipping entries that fail to deserialize (e.g. unexpected scalar values).
        /// Returns an empty dictionary if no per-domain entries were present.
        /// </summary>
        public Dictionary<string, DomainVerificationDetail> GetDomainEntries()
        {
            var result = new Dictionary<string, DomainVerificationDetail>();
            if (RawDomainEntries == null) return result;

            foreach (var kv in RawDomainEntries)
            {
                if (kv.Value.ValueKind != JsonValueKind.Object) continue;
                try
                {
                    var detail = kv.Value.Deserialize<DomainVerificationDetail>();
                    if (detail != null) result[kv.Key] = detail;
                }
                catch (JsonException)
                {
                    // ignore: entry shape unexpected, skip rather than failing the whole TrackOrder
                }
            }

            return result;
        }
    }

    /// <summary>
    /// Per-domain DCV detail inside <see cref="TrackOrderDomainVerification"/>.
    /// </summary>
    public class DomainVerificationDetail
    {
        /// <summary>DCV method used / requested for this domain (typically the human label).</summary>
        [JsonPropertyName("dcvMethod")]
        public string DcvMethod { get; set; }

        /// <summary>
        /// DCV completion status: "0"=Pending, "1"=Validated, "2"=Rejected.
        /// See <see cref="Constants.Dcv"/>.
        /// </summary>
        [JsonPropertyName("dcvStatus")]
        public string DcvStatus { get; set; }

        /// <summary>Domain status: "1"=Active, "2"=Inactive, "3"=Expired.</summary>
        [JsonPropertyName("status")]
        public string Status { get; set; }

        /// <summary>Timestamp at which the domain was successfully verified (when applicable).</summary>
        [JsonPropertyName("verifiedDate")]
        public string VerifiedDate { get; set; }

        /// <summary>
        /// CAA check status: "1"=emSign authorized or no CAA present,
        /// "2"=Authorization required, "3"=Authorization pending.
        /// </summary>
        [JsonPropertyName("caaStatus")]
        public string CaaStatus { get; set; }
    }

    public class TrackOrderRequestorInfo
    {
        [JsonPropertyName("requestorName")]
        public string RequestorName { get; set; }

        [JsonPropertyName("requestorEmail")]
        public string RequestorEmail { get; set; }
    }

    public class TrackOrderRevocationDetails
    {
        /// <summary>
        /// Revocation status:
        /// 1=Initiated, 2=Revoked, 3=Rejected, 4=InitiatedPendingLRA,
        /// 5=RevokedByLRA, 6=RejectedByLRA.
        /// </summary>
        [JsonPropertyName("revokeRequestStatusId")]
        public string RevokeRequestStatusId { get; set; }

        /// <summary>
        /// CERTInext revocation reason ID:
        /// 1=KeyCompromise, 3=AffiliationChanged, 4=Superseded,
        /// 5=CessationOfOperation, 9=PrivilegeWithdrawn.
        /// </summary>
        [JsonPropertyName("revokeReasonId")]
        public string RevokeReasonId { get; set; }

        [JsonPropertyName("revokeProcessedDate")]
        public string RevokeProcessedDate { get; set; }

        [JsonPropertyName("revokeRequestStatus")]
        public string RevokeRequestStatus { get; set; }
    }

    // ---------------------------------------------------------------------------
    // GetDcv response  — POST {baseURL}GetDcv
    //
    // Per the V1 spec the dcvDetails block contains different fields depending
    // on the dcvMethod that was requested:
    //   dcvMethod=1 (DNS TXT) → token populated
    //   dcvMethod=2 (HTTP)    → fileName + fileContent populated
    //   dcvMethod=3 (email)   → dcvEmails populated
    //
    // The TXT record HOSTNAME for dcvMethod=1 is NOT returned by this endpoint.
    // The CERTInext V1 documentation does not specify the convention. The plugin
    // uses Constants.Dcv.DefaultTxtRecordTemplate ("_emsign-validation.{0}") by
    // default, overridable via the DcvTxtRecordTemplate connector config field.
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Response from POST {baseURL}GetDcv.
    /// </summary>
    public class GetDcvResponse
    {
        [JsonPropertyName("meta")]
        public ResponseMeta Meta { get; set; }

        [JsonPropertyName("dcvDetails")]
        public DcvResponseDetails DcvDetails { get; set; }
    }

    /// <summary>
    /// DCV instructions returned by GetDcv. Field population depends on the
    /// requested dcvMethod (see class-level remarks on <see cref="GetDcvResponse"/>).
    /// </summary>
    public class DcvResponseDetails
    {
        /// <summary>
        /// Token / target address value to publish for DNS TXT-based DCV
        /// (dcvMethod = 1). Empty for other methods.
        /// </summary>
        [JsonPropertyName("token")]
        public string Token { get; set; }

        /// <summary>
        /// File name to host under <c>/.well-known/pki-validation/</c> for HTTP
        /// DCV (dcvMethod = 2). Empty for other methods.
        /// </summary>
        [JsonPropertyName("fileName")]
        public string FileName { get; set; }

        /// <summary>
        /// File body to serve at the well-known path for HTTP DCV (dcvMethod = 2).
        /// Empty for other methods.
        /// </summary>
        [JsonPropertyName("fileContent")]
        public string FileContent { get; set; }

        /// <summary>
        /// CA/B Forum approved approver email candidates for email DCV
        /// (dcvMethod = 3). Empty for other methods.
        /// </summary>
        [JsonPropertyName("dcvEmails")]
        public List<string> DcvEmails { get; set; }
    }

    // ---------------------------------------------------------------------------
    // VerifyDcv response  — POST {baseURL}VerifyDcv
    // Body contains only the meta block (success/failure status).
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Response from POST {baseURL}VerifyDcv. Body is meta-only; the actual
    /// per-domain verification status is observed via subsequent TrackOrder
    /// calls (see <see cref="TrackOrderDomainVerification"/>).
    /// </summary>
    public class VerifyDcvResponse
    {
        [JsonPropertyName("meta")]
        public ResponseMeta Meta { get; set; }
    }

    // ---------------------------------------------------------------------------
    // GetCertificate response  — POST {baseURL}GetCertificate
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Response from POST {baseURL}GetCertificate.
    /// Contains the PEM-encoded end-entity certificate and chain.
    /// Note: the serial number field name in the real API has a typo —
    /// "ceritficateSerialNumber" (missing 'i') — which is preserved here.
    /// </summary>
    public class GetCertificateResponse
    {
        [JsonPropertyName("meta")]
        public ResponseMeta Meta { get; set; }

        [JsonPropertyName("certificateDetails")]
        public CertificateDownloadDetails CertificateDetails { get; set; }
    }

    public class CertificateDownloadDetails
    {
        /// <summary>PEM-encoded root CA certificate.</summary>
        [JsonPropertyName("rootCertificate")]
        public string RootCertificate { get; set; }

        /// <summary>PEM-encoded issuing/intermediate CA certificate.</summary>
        [JsonPropertyName("caCertificate")]
        public string CaCertificate { get; set; }

        /// <summary>PEM-encoded end-entity (leaf) certificate.</summary>
        [JsonPropertyName("endEntityCertificate")]
        public string EndEntityCertificate { get; set; }

        /// <summary>Certificate expiry date string.</summary>
        [JsonPropertyName("expiryDate")]
        public string ExpiryDate { get; set; }

        /// <summary>
        /// Certificate serial number.
        /// Note: the field name contains a typo in the real CERTInext API —
        /// "ceritficateSerialNumber" — which is preserved here to match the wire format.
        /// </summary>
        [JsonPropertyName("ceritficateSerialNumber")]
        public string CertificateSerialNumber { get; set; }
    }

    // ---------------------------------------------------------------------------
    // GetOrderReport response  — POST {baseURL}GetOrderReport
    // Used for certificate synchronization.
    //
    // Live API shape (verified 2026-04):
    // {
    //   "orderDetails": {
    //     "noOfPages": 1,
    //     "totalNoOfResults": 1,
    //     "ordersArray": [...],
    //     "pageSize": 1,
    //     "currentPage": "1"
    //   },
    //   "meta": { "status": "1", ... }
    // }
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Response from POST {baseURL}GetOrderReport.
    /// </summary>
    public class GetOrderReportResponse
    {
        [JsonPropertyName("meta")]
        public ResponseMeta Meta { get; set; }

        /// <summary>
        /// Top-level pagination/results wrapper. Field name is "orderDetails" on the wire.
        /// </summary>
        [JsonPropertyName("orderDetails")]
        public OrderReportDetails OrderDetails { get; set; }
    }

    /// <summary>
    /// Pagination envelope inside the GetOrderReport "orderDetails" field.
    /// </summary>
    public class OrderReportDetails
    {
        [JsonPropertyName("noOfPages")]
        public int NoOfPages { get; set; }

        [JsonPropertyName("totalNoOfResults")]
        public int TotalNoOfResults { get; set; }

        /// <summary>The array of order records. Wire field name is "ordersArray".</summary>
        [JsonPropertyName("ordersArray")]
        public List<OrderReportEntry> OrdersArray { get; set; }

        [JsonPropertyName("pageSize")]
        public int PageSize { get; set; }

        /// <summary>1-based current page number (returned as a string by the API).</summary>
        [JsonPropertyName("currentPage")]
        public string CurrentPage { get; set; }
    }

    /// <summary>
    /// A single row from the GetOrderReport "ordersArray".
    /// Field names match the live API exactly (verified 2026-04).
    /// </summary>
    public class OrderReportEntry
    {
        /// <summary>
        /// Order number — the stable identifier assigned after submission.
        /// Blank when the order is in saveAndHold/draft state (use RequestNumber instead).
        /// Becomes CARequestID in Keyfactor Command once the order is placed.
        /// </summary>
        [JsonPropertyName("orderNumber")]
        public string OrderNumber { get; set; }

        /// <summary>
        /// Draft/request ID returned when saveAndHold="1".
        /// Only a transient identifier — not suitable as CARequestID.
        /// </summary>
        [JsonPropertyName("requestNumber")]
        public string RequestNumber { get; set; }

        /// <summary>
        /// Certificate status numeric ID. See <see cref="Constants.CertificateStatusId"/>.
        /// </summary>
        [JsonPropertyName("certificateStatusId")]
        public string CertificateStatusId { get; set; }

        [JsonPropertyName("certificateStatus")]
        public string CertificateStatus { get; set; }

        /// <summary>
        /// Order status numeric ID. See <see cref="Constants.OrderStatusId"/>.
        /// </summary>
        [JsonPropertyName("orderStatusId")]
        public string OrderStatusId { get; set; }

        [JsonPropertyName("orderStatus")]
        public string OrderStatus { get; set; }

        [JsonPropertyName("domainName")]
        public string DomainName { get; set; }

        [JsonPropertyName("organizationName")]
        public string OrganizationName { get; set; }

        [JsonPropertyName("groupNumber")]
        public string GroupNumber { get; set; }

        [JsonPropertyName("productCode")]
        public string ProductCode { get; set; }

        [JsonPropertyName("certificateSerialNumber")]
        public string CertificateSerialNumber { get; set; }

        /// <summary>Certificate expiry date. Wire field name is "certificateExpiryDate".</summary>
        [JsonPropertyName("certificateExpiryDate")]
        public string CertificateExpiryDate { get; set; }

        [JsonPropertyName("issuerCA")]
        public string IssuerCa { get; set; }

        [JsonPropertyName("certificateTrustType")]
        public string CertificateTrustType { get; set; }

        [JsonPropertyName("orderDate")]
        public string OrderDate { get; set; }

        [JsonPropertyName("expiresWithin")]
        public string ExpiresWithin { get; set; }

        [JsonPropertyName("tags")]
        public List<string> Tags { get; set; }

        [JsonPropertyName("customFields")]
        public List<object> CustomFields { get; set; }

        [JsonPropertyName("countryName")]
        public string CountryName { get; set; }
    }

    // ---------------------------------------------------------------------------
    // GetProductDetails response  — POST {baseURL}GetProductDetails
    //
    // Actual wire format (verified 2026-04):
    //   productDetails: [
    //     { categoryName, categoryID, products: [ { productCode, productName, productTypeID,
    //                                               subscriptionPrice?, price? }, ... ] },
    //     ...
    //   ]
    //
    // The response is a list of category envelopes, each containing a nested
    // "products" array.  CERTInextClient.GetProductDetailsAsync flattens this
    // structure into a List<ProductDetail> for callers.
    // ---------------------------------------------------------------------------

    public class GetProductDetailsResponse
    {
        [JsonPropertyName("meta")]
        public ResponseMeta Meta { get; set; }

        /// <summary>
        /// Category envelopes as returned by the API.  Each category contains a
        /// <c>products</c> array.  Call <see cref="FlattenProducts"/> to get a
        /// flat list of all product codes across all categories.
        /// </summary>
        [JsonPropertyName("productDetails")]
        public List<ProductCategory> Categories { get; set; }

        /// <summary>
        /// Returns a flat list of all <see cref="ProductDetail"/> records across
        /// every category in the response.  Returns an empty list when
        /// <see cref="Categories"/> is null or empty.
        /// </summary>
        public List<ProductDetail> FlattenProducts()
        {
            var result = new List<ProductDetail>();
            if (Categories == null) return result;

            foreach (var cat in Categories)
            {
                if (cat.Products == null) continue;
                foreach (var p in cat.Products)
                {
                    result.Add(new ProductDetail
                    {
                        ProductCode = p.ProductCode,
                        ProductName = p.ProductName,
                        ProductType = cat.CategoryName,
                        Active = true  // API does not return an active flag at this level
                    });
                }
            }

            return result;
        }
    }

    /// <summary>
    /// One category envelope inside the GetProductDetails response
    /// (e.g. "SSL/TLS Certificates", "S/MIME Certificates").
    /// </summary>
    public class ProductCategory
    {
        [JsonPropertyName("categoryName")]
        public string CategoryName { get; set; }

        [JsonPropertyName("categoryID")]
        public string CategoryId { get; set; }

        [JsonPropertyName("currencyType")]
        public string CurrencyType { get; set; }

        [JsonPropertyName("products")]
        public List<ProductCategoryEntry> Products { get; set; }
    }

    /// <summary>
    /// A single product entry inside a <see cref="ProductCategory"/>.
    /// </summary>
    public class ProductCategoryEntry
    {
        [JsonPropertyName("productCode")]
        public string ProductCode { get; set; }

        [JsonPropertyName("productName")]
        public string ProductName { get; set; }

        /// <summary>Numeric product type ID (e.g. "13" for DV SSL).</summary>
        [JsonPropertyName("productTypeID")]
        public string ProductTypeId { get; set; }

        /// <summary>
        /// Per-unit price for non-subscription products (e.g. document signing).
        /// </summary>
        [JsonPropertyName("price")]
        public string Price { get; set; }
    }

    /// <summary>
    /// Flattened product record returned by
    /// <see cref="Client.CERTInextClient.GetProductDetailsAsync"/>.
    /// Consumers use this type; the nested category structure from the wire format
    /// is an internal implementation detail of the response model.
    /// </summary>
    public class ProductDetail
    {
        /// <summary>Numeric product code string (e.g. "842").</summary>
        [JsonPropertyName("productCode")]
        public string ProductCode { get; set; }

        [JsonPropertyName("productName")]
        public string ProductName { get; set; }

        /// <summary>
        /// Product type derived from the category name (e.g. "SSL/TLS Certificates").
        /// </summary>
        [JsonPropertyName("productType")]
        public string ProductType { get; set; }

        /// <summary>
        /// Always <c>true</c> for products returned by the API — the API only
        /// returns products that are available on the account.
        /// </summary>
        [JsonPropertyName("active")]
        public bool Active { get; set; }
    }

    // ---------------------------------------------------------------------------
    // OAuth2 token response
    // ---------------------------------------------------------------------------

    public class OAuth2TokenResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; }

        [JsonPropertyName("token_type")]
        public string TokenType { get; set; }

        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }
    }

    // ---------------------------------------------------------------------------
    // Legacy response types — retained so CERTInextCAPlugin and existing tests
    // continue to compile while the client is incrementally updated.
    // These do not match the real CERTInext wire format.
    // ---------------------------------------------------------------------------

    /// <summary>
    /// LEGACY: inferred REST design type.  The real API returns
    /// <see cref="GenerateOrderResponse"/> for enrollment.
    /// </summary>
    public class EnrollCertificateResponse
    {
        /// <summary>Maps to orderNumber from the real API.</summary>
        [JsonPropertyName("id")]
        public string Id { get; set; }

        /// <summary>Maps to certificateStatus from TrackOrder response.</summary>
        [JsonPropertyName("status")]
        public string Status { get; set; }

        /// <summary>Maps to endEntityCertificate from GetCertificate response.</summary>
        [JsonPropertyName("certificate")]
        public string Certificate { get; set; }

        [JsonPropertyName("chain")]
        public string Chain { get; set; }

        /// <summary>Maps to ceritficateSerialNumber (note real API typo) from GetCertificate response.</summary>
        [JsonPropertyName("serialNumber")]
        public string SerialNumber { get; set; }

        [JsonPropertyName("profileId")]
        public string ProfileId { get; set; }

        [JsonPropertyName("message")]
        public string Message { get; set; }

        [JsonPropertyName("issuedAt")]
        public System.DateTime? IssuedAt { get; set; }

        [JsonPropertyName("expiresAt")]
        public System.DateTime? ExpiresAt { get; set; }
    }

    /// <summary>
    /// LEGACY: inferred REST design type.  The real API's
    /// TrackOrder + GetCertificate pair provides equivalent data.
    /// Populated by <see cref="Client.CERTInextClient.GetCertificateAsync"/> which
    /// internally calls TrackOrder + DownloadCertificate and maps the results.
    /// </summary>
    public class LegacyGetCertificateResponse
    {
        /// <summary>Order number — the CARequestID.</summary>
        [JsonPropertyName("id")]
        public string Id { get; set; }

        /// <summary>Legacy status string mapped from certificateStatusId.</summary>
        [JsonPropertyName("status")]
        public string Status { get; set; }

        /// <summary>PEM-encoded end-entity certificate (from GetCertificate response).</summary>
        [JsonPropertyName("certificate")]
        public string Certificate { get; set; }

        [JsonPropertyName("chain")]
        public string Chain { get; set; }

        /// <summary>Maps to ceritficateSerialNumber (note real API typo) from GetCertificate response.</summary>
        [JsonPropertyName("serialNumber")]
        public string SerialNumber { get; set; }

        /// <summary>Primary domain name from the order.</summary>
        [JsonPropertyName("subject")]
        public string Subject { get; set; }

        [JsonPropertyName("sans")]
        public System.Collections.Generic.List<SanEntry> Sans { get; set; }

        /// <summary>Product code from the order.</summary>
        [JsonPropertyName("profileId")]
        public string ProfileId { get; set; }

        [JsonPropertyName("issuedAt")]
        public System.DateTime? IssuedAt { get; set; }

        /// <summary>Certificate expiry date parsed from certificateExpiryDate in TrackOrder response.</summary>
        [JsonPropertyName("expiresAt")]
        public System.DateTime? ExpiresAt { get; set; }

        /// <summary>Revocation date parsed from revokeProcessedDate in TrackOrder revocationDetails.</summary>
        [JsonPropertyName("revokedAt")]
        public System.DateTime? RevokedAt { get; set; }

        /// <summary>
        /// Revocation reason string (legacy format, e.g. "keyCompromise").
        /// Derived from revokeReasonId in TrackOrder revocationDetails.
        /// </summary>
        [JsonPropertyName("revocationReason")]
        public string RevocationReason { get; set; }

        [JsonPropertyName("requesterName")]
        public string RequesterName { get; set; }

        [JsonPropertyName("requesterEmail")]
        public string RequesterEmail { get; set; }

        [JsonPropertyName("csr")]
        public string Csr { get; set; }
    }

    /// <summary>
    /// LEGACY: inferred REST design type. The real API uses
    /// <see cref="GetOrderReportResponse"/> for listing.
    /// </summary>
    public class ListCertificatesResponse
    {
        [JsonPropertyName("data")]
        public System.Collections.Generic.List<LegacyGetCertificateResponse> Data { get; set; }

        [JsonPropertyName("pagination")]
        public PaginationInfo Pagination { get; set; }
    }

    /// <summary>LEGACY pagination envelope from inferred REST design.</summary>
    public class PaginationInfo
    {
        [JsonPropertyName("total")]
        public int Total { get; set; }

        [JsonPropertyName("page")]
        public int Page { get; set; }

        [JsonPropertyName("pageSize")]
        public int PageSize { get; set; }

        [JsonPropertyName("totalPages")]
        public int TotalPages { get; set; }
    }

    /// <summary>
    /// LEGACY: inferred REST design type. The real API uses
    /// <see cref="GetProductDetailsResponse"/>.
    /// </summary>
    public class ListProfilesResponse
    {
        [JsonPropertyName("data")]
        public System.Collections.Generic.List<ProfileInfo> Data { get; set; }
    }

    /// <summary>LEGACY profile type used by <see cref="ListProfilesResponse"/>.</summary>
    public class ProfileInfo
    {
        [JsonPropertyName("id")]
        public string Id { get; set; }

        [JsonPropertyName("name")]
        public string Name { get; set; }

        [JsonPropertyName("description")]
        public string Description { get; set; }

        [JsonPropertyName("active")]
        public bool Active { get; set; }

        [JsonPropertyName("defaultValidityDays")]
        public int? DefaultValidityDays { get; set; }
    }

    /// <summary>
    /// LEGACY: health check response from inferred REST design.
    /// The real API uses <see cref="ValidateCredentialsResponse"/> for connectivity probes.
    /// </summary>
    public class HealthCheckResponse
    {
        [JsonPropertyName("status")]
        public string Status { get; set; }

        [JsonPropertyName("version")]
        public string Version { get; set; }
    }

    /// <summary>Standard error response body from inferred REST design.</summary>
    public class ApiErrorResponse
    {
        [JsonPropertyName("error")]
        public string Error { get; set; }

        [JsonPropertyName("message")]
        public string Message { get; set; }

        [JsonPropertyName("details")]
        public System.Collections.Generic.List<string> Details { get; set; }

        [JsonPropertyName("statusCode")]
        public int StatusCode { get; set; }
    }
}
