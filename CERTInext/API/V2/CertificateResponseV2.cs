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
    /// POST {ApiUrlV2}/oauth/token with form-encoded body.
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

        // These fields are unconfirmed in the V2 spec (OQ-1). They are included as
        // nullable so a live response that does include them deserializes correctly.
        [JsonPropertyName("revocationReason")]
        public string RevocationReason { get; set; }

        [JsonPropertyName("revocationDate")]
        public DateTime? RevocationDate { get; set; }
    }

    /// <summary>
    /// Response body for GET /api/certinext/v2/{family}-certificates/{orderId}/certificate.
    /// Returns the leaf certificate only — no chain or root field exists in the V2 response.
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

        /// <summary>PEM-encoded leaf certificate (no chain).</summary>
        [JsonPropertyName("certificatePem")]
        public string CertificatePem { get; set; }
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
}
