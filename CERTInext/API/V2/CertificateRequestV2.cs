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
    // Auth: POST {ApiUrl}/oauth/token (form-encoded client_credentials; ApiUrl is the V2 base
    // URL when UseV2Api=true — issues/0022 config consolidation)
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

        /// <summary>
        /// SAN list for UCC (multi-SAN) product variants — DV/OV/EV UCC and DV/OV Wildcard UCC
        /// (Catalog <c>productTypeID</c> 15/18/20/21/22). Each entry must be a valid FQDN
        /// (wildcards allowed only for the Wildcard UCC variants). Per the V2 spec's Submit CSR
        /// guidance, these SANs come from the order, not the CSR — the CSR must carry only the
        /// primary domain in CN for UCC orders. Omitted from the wire body for non-UCC products
        /// (single-domain orders are unaffected). See issues/f3-v2-multi-san-limitation.md.
        /// </summary>
        [JsonPropertyName("additionalDomains")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public System.Collections.Generic.List<string> AdditionalDomains { get; set; }
    }

    /// <summary>
    /// Organization block for V2 SSL orders. Per the V2 spec's field table (SSL/TLS
    /// Certificates folder description), this block is "Conditional — Mandatory for OV / EV"
    /// and every OV/EV create example in the spec sends exactly these three fields. Live-
    /// confirmed (issue 0028): submitting an OV order with no <c>organization</c> block gets
    /// HTTP 422 <c>[EMS-1180] Organization Name cannot be empty</c> — CERTInext resolves the
    /// certificate's organization name server-side from <c>organizationNumber</c>, so an
    /// absent/empty block leaves it with nothing to resolve. There is no separate
    /// "organization name" field to send; supplying a valid, pre-vetted
    /// <c>organizationNumber</c> is what the CA needs.
    /// </summary>
    public class V2OrganizationParams
    {
        [JsonPropertyName("organizationNumber")]
        public string OrganizationNumber { get; set; }

        /// <summary>
        /// Re-uses an existing vetted organization instead of queuing the order for manual
        /// vetting. Mirrors the V1 <c>OrganizationDetails.PreVetting="1"</c> semantics — sent
        /// as JSON <c>true</c> whenever <c>OrganizationNumber</c> is configured.
        /// </summary>
        [JsonPropertyName("preVetted")]
        public bool PreVetted { get; set; } = true;

        /// <summary>
        /// Optional per spec (re-vetting flow token). Not currently surfaced as plugin config;
        /// omitted from the wire body when null/empty.
        /// </summary>
        [JsonPropertyName("preVettingToken")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string PreVettingToken { get; set; }
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

        /// <summary>
        /// Mandatory for OV/EV, omitted entirely for DV (per spec, "Conditional — Mandatory
        /// for OV / EV"). <see cref="Keyfactor.Extensions.CAPlugin.CERTInext.CERTInextCAPlugin.EnrollV2Async"/>
        /// leaves this null for DV orders rather than sending an empty/placeholder block that
        /// could itself trigger a different validation error.
        /// </summary>
        [JsonPropertyName("organization")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public V2OrganizationParams Organization { get; set; }

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
        /// RFC 5280 string reason, kebab-case per the V2 spec. Valid values: unspecified,
        /// key-compromise, ca-compromise, affiliation-changed, superseded,
        /// cessation-of-operation, certificate-hold, privilege-withdrawn (plus
        /// aa-compromise on the signature-certificates / private-pki-certificates
        /// endpoints). Sending camelCase gets HTTP 400 — see issues/0019.
        /// </summary>
        [JsonPropertyName("reason")]
        public string Reason { get; set; } = "unspecified";

        [JsonPropertyName("note")]
        public string Note { get; set; }
    }
}
