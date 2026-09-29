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
    // Idempotency: Idempotency-Key header sent on order-create/revoke, but the spec doesn't
    // document it for those endpoints and only says "parsed today, enforced in a future release"
    // for the endpoints (Verify DCV, Domains) it does document it on — see issue 0032.
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
    /// Subscription parameters block for V2 orders (validity, auto-renewal). Per the V2 spec,
    /// omitting this block entirely defaults auto-renew to ON (1-year, 30-day window) at the CA,
    /// so <c>EnrollV2Async</c> always sends it, driving <see cref="AutoRenew"/>/
    /// <see cref="RenewBeforeDays"/> from the connector's SubscriptionAutoRenew/
    /// SubscriptionRenewCriteriaDays config (issue 0027 item 2a/2b).
    /// </summary>
    public class V2SubscriptionParams
    {
        [JsonPropertyName("validityYears")]
        public int ValidityYears { get; set; } = 1;

        [JsonPropertyName("autoRenew")]
        public bool AutoRenew { get; set; } = false;

        /// <summary>
        /// Days before expiry CERTInext auto-renews; only meaningful when <see cref="AutoRenew"/>
        /// is true. Null when the connector's SubscriptionRenewCriteriaDays is blank/unset — the
        /// client's global JSON serializer options (<c>CERTInextClient.GetJsonOptions</c>,
        /// <c>DefaultIgnoreCondition = WhenWritingNull</c>) omit the field from the wire in that
        /// case, letting the CA fall back to its documented default of 30.
        /// </summary>
        [JsonPropertyName("renewBeforeDays")]
        public int? RenewBeforeDays { get; set; }
    }

    /// <summary>
    /// Technical point-of-contact block for V2 orders. Per the V2 spec's field table (SSL/TLS
    /// Certificates folder description — confirmed identical for the Document Signer and
    /// Private PKI folders; <see cref="V2CreatePrivatePkiOrderRequest"/> and
    /// <see cref="V2CreateSignatureOrderRequest"/> reuse this type, see issue 0033), all four
    /// subfields are documented Optional. Unlike
    /// V1's <see cref="Keyfactor.Extensions.CAPlugin.CERTInext.API.TechnicalPointOfContact"/>,
    /// which sends ISD code and mobile number as two separate fields
    /// (<c>tpcIsdCode</c>/<c>tpcMobileNumber</c>), the V2 shape has a single <c>phone</c> field —
    /// composed from the connector's ISD-code + mobile-number config pair by
    /// <see cref="Keyfactor.Extensions.CAPlugin.CERTInext.CERTInextCAPlugin.ComposeV2Phone"/>.
    /// Despite being spec-Optional, <c>EnrollV2Async</c> always populates this block (never omits
    /// it), mirroring V1's fallback-to-Requestor* defaulting so a blank connector config never
    /// results in a silently-blank contact. See issues/0030-v2-technical-contact-not-sent.md.
    /// </summary>
    public class V2TechnicalPointOfContact
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

        /// <summary>
        /// "all" = full notification set, "0" = silent, null = omitted (CA defaults to "all").
        /// See <see cref="Keyfactor.Extensions.CAPlugin.CERTInext.CERTInextCAPlugin.EnrollV2Async"/>
        /// for the connector config mapping (issue 0027 item 1a). No default here — relies solely
        /// on the client's global <c>DefaultIgnoreCondition = WhenWritingNull</c> serializer option
        /// to omit the key when null, the same pattern <see cref="V2SubscriptionParams.RenewBeforeDays"/>
        /// uses.
        /// </summary>
        [JsonPropertyName("emailNotifications")]
        public string EmailNotifications { get; set; }

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

        /// <summary>
        /// Optional per spec, but always populated by <c>EnrollV2Async</c> — see
        /// <see cref="V2TechnicalPointOfContact"/> for the fallback/composition rules.
        /// </summary>
        [JsonPropertyName("technicalPointOfContact")]
        public V2TechnicalPointOfContact TechnicalPointOfContact { get; set; }

        [JsonPropertyName("remarks")]
        public string Remarks { get; set; }

        /// <summary>
        /// Optional billing group to attribute this order to. Mirrors V1's
        /// <see cref="Keyfactor.Extensions.CAPlugin.CERTInext.API.DelegationInformation.GroupNumber"/> —
        /// omitted entirely (rather than sent empty) when the connector has no
        /// <c>GroupNumber</c> configured, so the order falls back to the account's default group.
        /// </summary>
        [JsonPropertyName("groupNumber")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string GroupNumber { get; set; }
    }

    /// <summary>
    /// Request body for POST /api/certinext/v2/private-pki-certificates (issue 0033). Modelled
    /// from the V2 spec's "Private PKI Certificates" folder field table ("Field requirements (in
    /// body order)"): <c>variant</c>, <c>requestor.name</c>, <c>requestor.email</c> and
    /// <c>hostname</c> are strictly mandatory ("400 if missing"); everything else is Optional.
    /// Per the spec, "Private PKI has no DCV, no organization block, and no Subscriber
    /// Agreement" — so, unlike <see cref="V2CreateSslOrderRequest"/>, there is no
    /// <c>productVariant</c>, <c>organization</c>, <c>certificate</c> or <c>agreement</c> block
    /// here. SANs go in <see cref="AdditionalHosts"/>, which (unlike SSL's FQDN-only
    /// <c>additionalDomains</c>) accepts IP literals.
    ///
    /// Only the fields <c>EnrollV2Async</c> populates are modelled. Spec-Optional fields the
    /// plugin has no source for (<c>caProfileId</c>, <c>masterProductId</c> — both "derived from
    /// X-Product-Code" — <c>saveAsDraft</c>, <c>requestId</c>, <c>csr</c>, <c>tags</c>,
    /// <c>customFields</c>) are deliberately omitted, matching how the SSL DTO treats its own
    /// unused optional fields. The CSR is submitted by the separate Submit CSR call, per the
    /// spec's Private PKI workflow (Create -> Submit CSR -> Track -> Download).
    /// Product code is sent as the X-Product-Code header (not in this body).
    /// </summary>
    public class V2CreatePrivatePkiOrderRequest
    {
        /// <summary>
        /// Mandatory. Spec enum for create: <c>intranet-ssl</c> / <c>igtf-host</c>
        /// (<see cref="Keyfactor.Extensions.CAPlugin.CERTInext.Constants.ApiV2.PrivatePkiVariants"/>).
        /// </summary>
        [JsonPropertyName("variant")]
        public string Variant { get; set; }

        /// <summary>
        /// Optional (spec default <c>all</c>). Same connector mapping as
        /// <see cref="V2CreateSslOrderRequest.EmailNotifications"/>; null is omitted on the wire.
        /// </summary>
        [JsonPropertyName("emailNotifications")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string EmailNotifications { get; set; }

        /// <summary>Optional. Omitted when the connector has no <c>GroupNumber</c> configured.</summary>
        [JsonPropertyName("groupNumber")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string GroupNumber { get; set; }

        /// <summary>Mandatory (<c>name</c> + <c>email</c> strictly mandatory; phone/designation optional).</summary>
        [JsonPropertyName("requestor")]
        public V2Requestor Requestor { get; set; }

        /// <summary>Mandatory. Spec: "<c>hostname</c> - primary CN".</summary>
        [JsonPropertyName("hostname")]
        public string Hostname { get; set; }

        /// <summary>
        /// Optional. Spec: "<c>additionalHosts[]</c> - SAN list (DNS names or IPv4 / IPv6)".
        /// Omitted from the wire body when null (no additional SANs).
        /// </summary>
        [JsonPropertyName("additionalHosts")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public System.Collections.Generic.List<string> AdditionalHosts { get; set; }

        /// <summary>Optional (autoRenew defaults ON at the CA when omitted — always sent, as for SSL).</summary>
        [JsonPropertyName("subscription")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public V2SubscriptionParams Subscription { get; set; }

        [JsonPropertyName("remarks")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string Remarks { get; set; }

        /// <summary>Optional per spec; populated with the same fallbacks the SSL body uses.</summary>
        [JsonPropertyName("technicalPointOfContact")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public V2TechnicalPointOfContact TechnicalPointOfContact { get; set; }
    }

    /// <summary>
    /// <c>subject</c> block of a V2 Document Signer (signature) order (issue 0033). Modelled from
    /// the V2 spec's "Document Signer Certificates" folder field table. Only <see cref="Email"/>
    /// is strictly mandatory ("400 if missing"); the rest are Optional or Conditional on
    /// <c>subjectType</c>:
    ///  - <c>firstName</c> / <c>lastName</c>: "required for natural-person / legal-person"
    ///  - <c>organizationName</c>: "required for legal-person / legal-entity"
    ///  - <c>organizationIdentificationNumber</c>: "typically required for legal-entity"
    ///  - <c>businessCategory</c>: "legal-entity"
    ///  - <c>countryCode</c>: "Optional (ISO 3166-1 alpha-2)"
    /// Every non-mandatory field is omitted from the wire when null so a legal-entity body never
    /// carries empty person-name keys (and vice versa).
    /// </summary>
    public class V2SignatureSubject
    {
        [JsonPropertyName("firstName")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string FirstName { get; set; }

        [JsonPropertyName("lastName")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string LastName { get; set; }

        /// <summary>Mandatory for every <c>subjectType</c>.</summary>
        [JsonPropertyName("email")]
        public string Email { get; set; }

        [JsonPropertyName("phone")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string Phone { get; set; }

        [JsonPropertyName("designation")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string Designation { get; set; }

        [JsonPropertyName("organizationName")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string OrganizationName { get; set; }

        [JsonPropertyName("organizationUnit")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string OrganizationUnit { get; set; }

        [JsonPropertyName("organizationIdentificationNumber")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string OrganizationIdentificationNumber { get; set; }

        /// <summary>Spec examples: <c>Business Entity</c> | <c>Government</c> | <c>Non-Commercial Entity</c>.</summary>
        [JsonPropertyName("businessCategory")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string BusinessCategory { get; set; }

        /// <summary>Spec examples: <c>passport</c> | <c>driving-license</c> | <c>national-id</c>.</summary>
        [JsonPropertyName("identityDocumentType")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string IdentityDocumentType { get; set; }

        [JsonPropertyName("identificationNumber")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string IdentificationNumber { get; set; }

        [JsonPropertyName("streetAddress1")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string StreetAddress1 { get; set; }

        [JsonPropertyName("streetAddress2")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string StreetAddress2 { get; set; }

        [JsonPropertyName("locality")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string Locality { get; set; }

        [JsonPropertyName("state")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string State { get; set; }

        [JsonPropertyName("postalCode")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string PostalCode { get; set; }

        [JsonPropertyName("countryCode")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string CountryCode { get; set; }
    }

    /// <summary>
    /// Request body for POST /api/certinext/v2/signature-certificates (issue 0033). Modelled from
    /// the V2 spec's "Document Signer Certificates" folder field table. Strictly mandatory ("400
    /// if missing"): <c>subjectType</c>, <c>requestor.name</c>, <c>requestor.email</c>,
    /// <c>subject.email</c>; "The <c>subject.*</c> fields beyond email vary by <c>subjectType</c> -
    /// the backend applies stricter per-type rules."
    ///
    /// <b>Not yet wired into <c>EnrollV2Async</c>.</b> The body shape is fully determined by the
    /// spec, but several of its mandatory/conditional values (<c>subjectType</c>,
    /// <c>subject.email</c>, the per-type <c>subject</c> name/organization fields) have no settled
    /// source in the Command enrollment inputs yet — see issue 0033. Until that is decided,
    /// <c>EnrollV2Async</c> fails a <c>ProductFamily=signature</c> enrollment fast instead of
    /// sending any body. The DTO and its client overload exist so that wiring is a pure
    /// source-mapping change.
    ///
    /// <see cref="Agreement"/> reuses <see cref="V2AgreementParams"/> (the spec's signature and
    /// SSL agreement tables are identical: <c>signerName</c>, <c>signerPlace</c>,
    /// <c>accepted</c>). Leave <see cref="V2AgreementParams.SignerIp"/> null for this family —
    /// the spec's signature Accept Agreement note says "Do not send <c>signerIp</c> in the body -
    /// it will be ignored", and the create field table does not list it.
    /// Product code is sent as the X-Product-Code header (not in this body).
    /// </summary>
    public class V2CreateSignatureOrderRequest
    {
        /// <summary>
        /// Mandatory. Spec enum: <c>natural-person</c> / <c>legal-person</c> / <c>legal-entity</c>
        /// (<see cref="Keyfactor.Extensions.CAPlugin.CERTInext.Constants.ApiV2.SignatureSubjectTypes"/>).
        /// </summary>
        [JsonPropertyName("subjectType")]
        public string SubjectType { get; set; }

        [JsonPropertyName("emailNotifications")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string EmailNotifications { get; set; }

        [JsonPropertyName("groupNumber")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string GroupNumber { get; set; }

        /// <summary>Mandatory (<c>name</c> + <c>email</c> strictly mandatory).</summary>
        [JsonPropertyName("requestor")]
        public V2Requestor Requestor { get; set; }

        /// <summary>Mandatory; see <see cref="V2SignatureSubject"/> for the per-type rules.</summary>
        [JsonPropertyName("subject")]
        public V2SignatureSubject Subject { get; set; }

        [JsonPropertyName("subscription")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public V2SubscriptionParams Subscription { get; set; }

        /// <summary>Spec: "Optional - required before issuance".</summary>
        [JsonPropertyName("agreement")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public V2AgreementParams Agreement { get; set; }

        [JsonPropertyName("remarks")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string Remarks { get; set; }

        [JsonPropertyName("technicalPointOfContact")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public V2TechnicalPointOfContact TechnicalPointOfContact { get; set; }
    }

    /// <summary>
    /// Request body for PUT /api/certinext/v2/{family}-certificates/{orderId}/csr. The spec
    /// documents the identical <c>{ "csr", "attested" }</c> body for the SSL/TLS, Private PKI
    /// and Document Signer families (issue 0033), so one shape serves all three.
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
