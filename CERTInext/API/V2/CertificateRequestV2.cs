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

using System.Text.Json.Serialization;
using System.Text.Json;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.API.V2
{
    // ---------------------------------------------------------------------------
    // V2 REST API — Request DTOs
    //
    // Auth: POST {ApiUrlV2}/oauth/token (form-encoded client_credentials)
    // Product code: X-Product-Code header (not in body)
    // Idempotency: Idempotency-Key header required on all unsafe POSTs
    // ---------------------------------------------------------------------------

    /// <summary>
    /// Requestor information block sent with every V2 order.
    /// </summary>
    public class V2Requestor
    {
        [JsonPropertyName("name")]
        public string Name { get; set; }

        [JsonPropertyName("email")]
        public string Email { get; set; }

        [JsonPropertyName("phone")]
        public string Phone { get; set; }

        [JsonPropertyName("designation")]
        public string Designation { get; set; }
    }

    /// <summary>
    /// Certificate parameters block for V2 SSL orders.
    /// </summary>
    public class V2CertificateParams
    {
        [JsonPropertyName("domain")]
        public string Domain { get; set; }

        [JsonPropertyName("autoSecureWww")]
        public bool AutoSecureWww { get; set; } = false;
    }

    /// <summary>
    /// Subscription parameters block for V2 orders (validity, auto-renewal).
    /// </summary>
    public class V2SubscriptionParams
    {
        [JsonPropertyName("validityYears")]
        public int ValidityYears { get; set; } = 1;

        [JsonPropertyName("autoRenew")]
        public bool AutoRenew { get; set; } = false;

        [JsonPropertyName("renewBeforeDays")]
        public int RenewBeforeDays { get; set; } = 30;
    }

    /// <summary>
    /// Subscriber agreement block required for V2 SSL orders.
    /// </summary>
    public class V2AgreementParams
    {
        [JsonPropertyName("signerName")]
        public string SignerName { get; set; }

        /// <summary>Optional in V2. Omitted from serialisation when null or empty.</summary>
        [JsonPropertyName("signerIp")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string SignerIp { get; set; }

        /// <summary>Optional in V2. Omitted from serialisation when null or empty.</summary>
        [JsonPropertyName("signerPlace")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string SignerPlace { get; set; }

        [JsonPropertyName("accepted")]
        public bool Accepted { get; set; } = true;
    }

    /// <summary>
    /// Request body for POST /api/certinext/v2/ssl-certificates.
    /// Product code is sent as the X-Product-Code header (not in this body).
    /// </summary>
    public class V2CreateSslOrderRequest
    {
        [JsonPropertyName("productVariant")]
        public string ProductVariant { get; set; } = "dv";

        [JsonPropertyName("emailNotifications")]
        public string EmailNotifications { get; set; } = "all";

        [JsonPropertyName("requestor")]
        public V2Requestor Requestor { get; set; }

        [JsonPropertyName("certificate")]
        public V2CertificateParams Certificate { get; set; }

        [JsonPropertyName("subscription")]
        public V2SubscriptionParams Subscription { get; set; }

        [JsonPropertyName("agreement")]
        public V2AgreementParams Agreement { get; set; }

        [JsonPropertyName("remarks")]
        public string Remarks { get; set; }
    }

    /// <summary>
    /// Request body for PUT /api/certinext/v2/{family}-certificates/{orderId}/csr.
    /// </summary>
    public class V2SubmitCsrRequest
    {
        [JsonPropertyName("csr")]
        public string Csr { get; set; }

        [JsonPropertyName("attested")]
        public bool Attested { get; set; } = false;
    }

    /// <summary>
    /// Request body for POST /api/certinext/v2/{family}-certificates/{orderId}/revoke.
    /// </summary>
    public class V2RevokeRequest
    {
        /// <summary>
        /// RFC 5280 string reason. Valid values: unspecified, keyCompromise,
        /// caCompromise, affiliationChanged, superseded, cessationOfOperation,
        /// privilegeWithdrawn.
        /// </summary>
        [JsonPropertyName("reason")]
        public string Reason { get; set; } = "unspecified";

        [JsonPropertyName("note")]
        public string Note { get; set; }
    }
}
