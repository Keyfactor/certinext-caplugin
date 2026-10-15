// Copyright 2026 Keyfactor
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.API.V2
{
    // ---------------------------------------------------------------------------
    // V2 REST API — Response DTOs
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Standard OAuth2 client_credentials token response (flat shape — no tokenDetails wrapper).
    /// POST {ApiUrl}/oauth/token with form-encoded body (ApiUrl is the V2 base URL when
    /// UseV2Api=true).
    /// </summary>
    public class V2TokenResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; }

        [JsonPropertyName("token_type")]
        public string TokenType { get; set; }

        /// <summary>Lifetime in seconds. Typically 3600 (1 hour).</summary>
        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; } = 3600;

        [JsonPropertyName("refresh_token")]
        public string RefreshToken { get; set; }
    }

    /// <summary>
    /// HATEOAS link object present in V2 responses.
    /// </summary>
    public class V2Link
    {
        [JsonPropertyName("href")]
        public string Href { get; set; }
    }

    /// <summary>
    /// _links map returned by V2 order responses.
    /// Known keys: self, dcv, csr, agreement, certificate, cancel, revoke.
    /// </summary>
    public class V2Links
    {
        [JsonPropertyName("self")]
        public V2Link Self { get; set; }

        [JsonPropertyName("dcv")]
        public V2Link Dcv { get; set; }

        [JsonPropertyName("csr")]
        public V2Link Csr { get; set; }

        [JsonPropertyName("agreement")]
        public V2Link Agreement { get; set; }

        [JsonPropertyName("certificate")]
        public V2Link Certificate { get; set; }

        [JsonPropertyName("cancel")]
        public V2Link Cancel { get; set; }

        [JsonPropertyName("revoke")]
        public V2Link Revoke { get; set; }
    }

    /// <summary>
    /// Response body for POST /api/certinext/v2/{family}-certificates (201 Created).
    /// </summary>
    public class V2CreateOrderResponse
    {
        [JsonPropertyName("orderId")]
        public string OrderId { get; set; }

        [JsonPropertyName("requestId")]
        public string RequestId { get; set; }

        /// <summary>
        /// Initial order status. Typically "pending-dcv" for SSL DV orders.
        /// </summary>
        [JsonPropertyName("status")]
        public string Status { get; set; }

        [JsonPropertyName("_links")]
        public V2Links Links { get; set; }
    }

    /// <summary>
    /// Response body for GET /api/certinext/v2/{family}-certificates/{orderId}.
    /// Contains lifecycle status only — serial number and validity dates are NOT present;
    /// those are only in the Download Certificate response.
    /// </summary>
    public class V2OrderStatusResponse
    {
        [JsonPropertyName("orderId")]
        public string OrderId { get; set; }

        [JsonPropertyName("requestId")]
        public string RequestId { get; set; }

        /// <summary>Current order status string (e.g. "pending-dcv", "issued", "revoked").</summary>
        [JsonPropertyName("status")]
        public string Status { get; set; }

        [JsonPropertyName("productVariant")]
        public string ProductVariant { get; set; }

        [JsonPropertyName("domain")]
        public string Domain { get; set; }

        [JsonPropertyName("_links")]
        public V2Links Links { get; set; }

        /// <summary>
        /// Populated only when <see cref="Status"/> is "revoked". Absent entirely from the wire —
        /// not present-but-null — when the order has never been revoked, which
        /// <c>System.Text.Json</c> deserializes as a null <see cref="V2RevocationDetails"/>
        /// reference with no special handling required.
        /// </summary>
        [JsonPropertyName("revocation")]
        public V2RevocationDetails Revocation { get; set; }

        /// <summary>ISO 8601 timestamp when the certificate was issued. Present when status = "issued".</summary>
        [JsonPropertyName("issuedAt")]
        public string IssuedAt { get; set; }

        /// <summary>ISO 8601 timestamp when the certificate expires. Present when status = "issued".</summary>
        [JsonPropertyName("expiresAt")]
        public string ExpiresAt { get; set; }

        /// <summary>
        /// Per-domain DCV/CAA verification detail. Present on UCC orders whose
        /// additional SANs each carry their own DCV state. Absent entirely on older/simpler
        /// response shapes — callers must treat
        /// a null <see cref="V2Verifications.Domain"/>/<see cref="V2DomainVerification.Domains"/>
        /// the same as "no per-domain detail available" and fall back to the single top-level
        /// <see cref="Domain"/> field.
        /// </summary>
        [JsonPropertyName("verifications")]
        public V2Verifications Verifications { get; set; }
    }

    /// <summary>
    /// Top-level <c>verifications</c> object on the V2 Track Order response.
    /// Only the <c>domain</c> sub-block is modeled — that is the only one this plugin's DCV
    /// automation drives.
    /// </summary>
    public class V2Verifications
    {
        [JsonPropertyName("domain")]
        public V2DomainVerification Domain { get; set; }
    }

    /// <summary>
    /// <c>verifications.domain</c> block. <see cref="Status"/> is an aggregate that
    /// is NOT reliable for driving DCV decisions — it can stay
    /// "PENDING" even after the parent order was cancelled and every per-domain
    /// <see cref="V2DomainVerificationEntry.DcvStatus"/> had already flipped to REJECTED. Use it
    /// for logging only; always decide per-domain from <see cref="Domains"/>.
    /// </summary>
    public class V2DomainVerification
    {
        /// <summary>Aggregate status (e.g. "PENDING"). Logging only — see class remarks.</summary>
        [JsonPropertyName("status")]
        public string Status { get; set; }

        /// <summary>Per-domain verification entries — one per domain on the order (primary + any
        /// UCC additional SANs).</summary>
        [JsonPropertyName("domains")]
        public List<V2DomainVerificationEntry> Domains { get; set; }
    }

    /// <summary>
    /// A single entry in <c>verifications.domain.domains[]</c>. Example shape:
    /// <c>{"domain":"a.pending....example.com","domainStatus":"ACTIVE","dcvStatus":"PENDING","caaStatus":"SKIPPED"}</c>
    /// for a still-pending SAN, versus
    /// <c>{"domain":"...","domainStatus":"ACTIVE","dcvMethod":"dns-txt","dcvStatus":"VERIFIED","verifiedAt":"...","caaStatus":"PASSED"}</c>
    /// once verified. <see cref="DcvMethod"/> and <see cref="VerifiedAt"/> are absent entirely
    /// (not present-but-null) on a pending entry — both are nullable here for exactly that
    /// reason; a fix must not assume <see cref="DcvMethod"/> is populated before treating an
    /// entry as needing DNS-01 DCV.
    /// </summary>
    public class V2DomainVerificationEntry
    {
        [JsonPropertyName("domain")]
        public string Domain { get; set; }

        [JsonPropertyName("domainStatus")]
        public string DomainStatus { get; set; }

        /// <summary>Absent on the wire until <see cref="DcvStatus"/> reaches VERIFIED — see class
        /// remarks. This plugin only ever drives dns-txt DCV, so a null/absent value here is
        /// treated as "use DNS-01", never as an unknown/unsupported method.</summary>
        [JsonPropertyName("dcvMethod")]
        public string DcvMethod { get; set; }

        /// <summary>PENDING / VERIFIED / REJECTED (see <see cref="Constants.ApiV2"/>
        /// DcvStatus* constants). Drive all per-domain DCV decisions from this field, never from
        /// the aggregate <see cref="V2DomainVerification.Status"/>.</summary>
        [JsonPropertyName("dcvStatus")]
        public string DcvStatus { get; set; }

        /// <summary>ISO 8601 timestamp. Absent until <see cref="DcvStatus"/> reaches VERIFIED.</summary>
        [JsonPropertyName("verifiedAt")]
        public string VerifiedAt { get; set; }

        [JsonPropertyName("caaStatus")]
        public string CaaStatus { get; set; }
    }

    /// <summary>
    /// Nested <c>revocation</c> object on the V2 Track Order response. Example shape, from a
    /// revoked SSL order:
    /// <c>{"status":"Certificate Revoked","reason":"cessation-of-operation","processedAt":"2026-09-24T20:44:41Z"}</c>
    /// </summary>
    public class V2RevocationDetails
    {
        /// <summary>
        /// Human-readable revocation engine status (e.g. "Certificate Revoked"), mirroring the
        /// outer <c>certificateState</c> field on the same response. Not a distinct enum worth
        /// modeling separately from <see cref="Reason"/>.
        /// </summary>
        [JsonPropertyName("status")]
        public string Status { get; set; }

        /// <summary>
        /// RFC 5280 reason name, hyphenated on the wire (e.g. "cessation-of-operation",
        /// "key-compromise") — NOT V1's camelCase convention. See
        /// <see cref="Constants.RevocationReasonV2"/> for the known values and
        /// <c>Models.StatusMapper.V2RevocationReasonToCrlCode</c> for the reverse mapping back
        /// to an RFC 5280 CRL reason code.
        /// </summary>
        [JsonPropertyName("reason")]
        public string Reason { get; set; }

        /// <summary>Effective revocation time (CA-recorded). RFC 3339 / ISO 8601 UTC.</summary>
        [JsonPropertyName("processedAt")]
        public DateTime? ProcessedAt { get; set; }
    }

    /// <summary>
    /// Response body for GET /api/certinext/v2/{family}-certificates/{orderId}/certificate.
    /// Returns the leaf certificate and, when present, intermediate chain PEM strings.
    /// </summary>
    public class V2CertificateDownloadResponse
    {
        [JsonPropertyName("orderId")]
        public string OrderId { get; set; }

        [JsonPropertyName("serialNumber")]
        public string SerialNumber { get; set; }

        [JsonPropertyName("subject")]
        public string Subject { get; set; }

        [JsonPropertyName("issuer")]
        public string Issuer { get; set; }

        [JsonPropertyName("notBefore")]
        public DateTime? NotBefore { get; set; }

        [JsonPropertyName("notAfter")]
        public DateTime? NotAfter { get; set; }

        /// <summary>PEM-encoded leaf certificate.</summary>
        [JsonPropertyName("certificatePem")]
        public string CertificatePem { get; set; }

        /// <summary>
        /// Array of intermediate PEM strings returned alongside the leaf cert.
        /// May be null or empty when the CA does not include chain in the response.
        /// </summary>
        [JsonPropertyName("chainPem")]
        public List<string> ChainPem { get; set; }
    }

    /// <summary>
    /// Response body for GET /api/certinext/v2/ssl-certificates/{orderId}/dcv.
    /// Returns the DCV challenge token needed to publish a DNS TXT record.
    ///
    /// Actual wire shape: exactly two fields —
    /// <c>{"tokenExpiryDate": "...", "token": "..."}</c>. This matches neither the spec's
    /// own worked example for this endpoint (<c>orderNumber</c>/<c>domainName</c>/
    /// <c>dcvMethod</c>/<c>fileNameContent</c>) nor the
    /// spec's prose for the same endpoint (<c>method</c>/<c>txtToken</c>). There is no
    /// <c>orderNumber</c>, <c>domainName</c>, or method field on the wire, so none are
    /// modeled here:
    ///   - order id and domain name are already known from the local order-placement
    ///     context before DCV is ever attempted (see call sites of
    ///     <see cref="CERTInextCAPlugin.PerformDcvV2IfNeededAsync"/>), so they don't need
    ///     to be echoed back by this response.
    ///   - the V2 DCV path only ever performs DNS-TXT validation — the hostname
    ///     (<c>_emudhra-challenge.{domain}</c>) and validator ("dns-01") are both hardcoded
    ///     in <see cref="CERTInextCAPlugin.PerformDcvV2IfNeededAsync"/>, which never reads a
    ///     method from this response — so no method field is needed.
    /// </summary>
    public class V2DcvChallengeResponse
    {
        /// <summary>Value to publish as the DNS TXT record.</summary>
        [JsonPropertyName("token")]
        public string Token { get; set; }

        [JsonPropertyName("tokenExpiryDate")]
        public string TokenExpiryDate { get; set; }
    }

    /// <summary>
    /// Request body for POST /api/certinext/v2/ssl-certificates/{orderId}/dcv/verify.
    /// </summary>
    public class V2DcvVerifyRequest
    {
        [JsonPropertyName("domain")]
        public string Domain { get; set; }

        /// <summary>"dns-txt" for DNS TXT record validation.</summary>
        [JsonPropertyName("method")]
        public string Method { get; set; }
    }

    /// <summary>
    /// Response body for POST /api/certinext/v2/ssl-certificates/{orderId}/dcv/verify.
    /// 200 OK with this body, or 204 No Content, both indicate success.
    /// 422 with overallStatus="FAILED" indicates verification failure.
    /// </summary>
    public class V2DcvVerifyResponse
    {
        /// <summary>"VERIFIED" on success, "FAILED" on failure.</summary>
        [JsonPropertyName("overallStatus")]
        public string OverallStatus { get; set; }

        [JsonPropertyName("method")]
        public string Method { get; set; }

        [JsonPropertyName("verifiedAt")]
        public string VerifiedAt { get; set; }
    }

    /// <summary>
    /// RFC 7807 Problem Details error response from the V2 API.
    /// Content-Type: application/problem+json
    /// </summary>
    public class V2ProblemDetails
    {
        [JsonPropertyName("type")]
        public string Type { get; set; }

        [JsonPropertyName("title")]
        public string Title { get; set; }

        [JsonPropertyName("status")]
        public int Status { get; set; }

        [JsonPropertyName("detail")]
        public string Detail { get; set; }

        [JsonPropertyName("instance")]
        public string Instance { get; set; }

        /// <summary>Field-level validation errors (optional).</summary>
        [JsonPropertyName("errors")]
        public List<V2FieldError> Errors { get; set; }
    }

    /// <summary>
    /// A single field-level validation error from RFC 7807 errors array.
    /// </summary>
    public class V2FieldError
    {
        [JsonPropertyName("field")]
        public string Field { get; set; }

        [JsonPropertyName("message")]
        public string Message { get; set; }
    }

    /// <summary>
    /// Response body for GET /api/certinext/v2/auth/me.
    /// Used as the V2 connectivity/ping check.
    /// </summary>
    public class V2AuthMeResponse
    {
        [JsonPropertyName("accountNumber")]
        public string AccountNumber { get; set; }

        [JsonPropertyName("authType")]
        public string AuthType { get; set; }
    }

    /// <summary>
    /// Spring-style page envelope for GET /api/certinext/v2/reports/orders. The spec's
    /// example body is stale; its field table is what's actually returned.
    /// </summary>
    public class V2OrdersReportResponse
    {
        [JsonPropertyName("content")]
        public List<OrderReportEntryV2> Content { get; set; }

        /// <summary>1-based page index (mirrors the request's page query param).</summary>
        [JsonPropertyName("page")]
        public int Page { get; set; }

        [JsonPropertyName("size")]
        public int Size { get; set; }

        [JsonPropertyName("totalElements")]
        public long TotalElements { get; set; }

        [JsonPropertyName("totalPages")]
        public int TotalPages { get; set; }
    }

    /// <summary>
    /// A single row from the V2 /reports/orders "content" array. Field names match the live
    /// field table (NOT the spec's stale example body, which
    /// uses different field names — state/identifier/account/group/product).
    ///
    /// orderStatus/certificateStatus are human-readable display strings (e.g. "Order Accepted",
    /// "Certificate Downloaded") — NOT the V2 `status` enum used by TrackOrder
    /// (see <see cref="V2OrderStatusResponse.Status"/> and
    /// <c>Keyfactor.Extensions.CAPlugin.CERTInext.Models.StatusMapper.V2StatusToRequestDisposition</c>).
    /// See <c>CERTInextCAPlugin.MapV2ReportStatusToDisposition</c> for how these display strings
    /// are mapped; the vocabulary handled there is not guaranteed exhaustive.
    /// </summary>
    public class OrderReportEntryV2
    {
        [JsonPropertyName("orderNumber")]
        public string OrderNumber { get; set; }

        /// <summary>Most-recent request identifier on the order (reissues create new requests).</summary>
        [JsonPropertyName("requestNumber")]
        public string RequestNumber { get; set; }

        /// <summary>Human-readable order state, e.g. "Order Accepted", "Order Fulfilled".</summary>
        [JsonPropertyName("orderStatus")]
        public string OrderStatus { get; set; }

        /// <summary>Human-readable request/certificate state, e.g. "Pending for Approver", "Certificate Downloaded".</summary>
        [JsonPropertyName("certificateStatus")]
        public string CertificateStatus { get; set; }

        /// <summary>Hex serial assigned by the CA. Empty until issuance.</summary>
        [JsonPropertyName("certificateSerialNumber")]
        public string CertificateSerialNumber { get; set; }

        /// <summary>Certificate notAfter. Empty until issuance. Kept as string — format not guaranteed.</summary>
        [JsonPropertyName("certificateExpiryDate")]
        public string CertificateExpiryDate { get; set; }

        /// <summary>Issuing CA's CN. Empty until issuance.</summary>
        [JsonPropertyName("issuerCA")]
        public string IssuerCa { get; set; }

        /// <summary>
        /// Catalog product code. Often empty on report rows — do not rely on this
        /// for family resolution; use <c>ResolveAndTrackOrderV2WithFamilyAsync</c> instead.
        /// </summary>
        [JsonPropertyName("productCode")]
        public string ProductCode { get; set; }

        /// <summary>Primary CN for SSL/TLS orders. Empty for non-SSL families.</summary>
        [JsonPropertyName("domainName")]
        public string DomainName { get; set; }

        [JsonPropertyName("groupNumber")]
        public string GroupNumber { get; set; }

        /// <summary>Order creation time (UTC). Kept as string and parsed defensively by the caller —
        /// mirrors the V1 <see cref="OrderReportEntry.OrderDate"/> pattern.</summary>
        [JsonPropertyName("orderDate")]
        public string OrderDate { get; set; }

        [JsonPropertyName("organizationName")]
        public string OrganizationName { get; set; }

        [JsonPropertyName("countryName")]
        public string CountryName { get; set; }

        [JsonPropertyName("originator")]
        public string Originator { get; set; }

        [JsonPropertyName("tags")]
        public List<string> Tags { get; set; }

        [JsonPropertyName("customFields")]
        public List<object> CustomFields { get; set; }
    }
}
