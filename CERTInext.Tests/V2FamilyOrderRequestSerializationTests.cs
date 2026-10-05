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

using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using FluentAssertions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Issue 0033: wire-shape tests for the Private PKI and Document Signer create-order DTOs,
    /// checked against the request bodies in the V2 spec
    /// (<c>docs/reference/specs/CERTInext API v2.postman_collection (1).json</c>). Each spec
    /// example body is copied verbatim below (named after its Postman request); the DTO is
    /// populated with the same values, serialized with the client's serializer options, and
    /// compared structurally (key names, nesting, values — not whitespace or key order).
    /// </summary>
    public class V2FamilyOrderRequestSerializationTests
    {
        // Mirrors CERTInextClient.GetJsonOptions() (private).
        private static JsonSerializerOptions ClientEquivalentJsonOptions() => new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        private static string Serialize<T>(T value) => JsonSerializer.Serialize(value, ClientEquivalentJsonOptions());

        /// <summary>Order-insensitive canonical form of a JSON document (object keys sorted).</summary>
        private static string Canonical(string json)
        {
            using var doc = JsonDocument.Parse(json);
            var sb = new StringBuilder();
            WriteCanonical(doc.RootElement, sb);
            return sb.ToString();
        }

        private static void WriteCanonical(JsonElement e, StringBuilder sb)
        {
            switch (e.ValueKind)
            {
                case JsonValueKind.Object:
                    sb.Append('{');
                    bool first = true;
                    foreach (var p in e.EnumerateObject().OrderBy(p => p.Name, System.StringComparer.Ordinal))
                    {
                        if (!first) sb.Append(',');
                        first = false;
                        sb.Append(JsonSerializer.Serialize(p.Name)).Append(':');
                        WriteCanonical(p.Value, sb);
                    }
                    sb.Append('}');
                    break;
                case JsonValueKind.Array:
                    sb.Append('[');
                    bool firstItem = true;
                    foreach (var item in e.EnumerateArray())
                    {
                        if (!firstItem) sb.Append(',');
                        firstItem = false;
                        WriteCanonical(item, sb);
                    }
                    sb.Append(']');
                    break;
                case JsonValueKind.String:
                    sb.Append(JsonSerializer.Serialize(e.GetString()));
                    break;
                default:
                    sb.Append(e.GetRawText());
                    break;
            }
        }

        // ---------------------------------------------------------------------------
        // Private PKI — spec "Private PKI Certificates" -> "Create - Intranet SSL"
        // ---------------------------------------------------------------------------

        private const string SpecCreateIntranetSslBody = """
        {
         "variant": "intranet-ssl",
         "hostname": "intranet.acme.local",
         "additionalHosts": [
         "portal.acme.local",
         "reports.acme.local",
         "10.0.0.50"
         ],
         "emailNotifications": "all",
         "subscription": { "validityYears": 1 },
         "requestor": {
         "name": "DevOps Team",
         "email": "devops@acme.com",
         "phone": "+14155551234",
         "designation": "Platform Engineering"
         }
        }
        """;

        [Fact]
        public void PrivatePki_CreateIntranetSslSpecExample_SerializesToTheSpecBody()
        {
            var request = new V2CreatePrivatePkiOrderRequest
            {
                Variant            = "intranet-ssl",
                Hostname           = "intranet.acme.local",
                AdditionalHosts    = new List<string> { "portal.acme.local", "reports.acme.local", "10.0.0.50" },
                EmailNotifications = "all",
                Subscription       = new V2SubscriptionParams { ValidityYears = 1 },
                Requestor          = new V2Requestor
                {
                    Name = "DevOps Team", Email = "devops@acme.com", Phone = "+14155551234", Designation = "Platform Engineering"
                }
            };

            // The only difference from the spec example is subscription.autoRenew, which the
            // shared V2SubscriptionParams always writes (spec: "Optional (default ON)" — the plugin
            // always sends the connector's explicit choice, exactly as for SSL).
            string expected = SpecCreateIntranetSslBody.Replace(
                "\"subscription\": { \"validityYears\": 1 }",
                "\"subscription\": { \"validityYears\": 1, \"autoRenew\": false }");

            Canonical(Serialize(request)).Should().Be(Canonical(expected));
        }

        [Fact]
        public void PrivatePki_OptionalBlocks_AreOmittedWhenNull()
        {
            var request = new V2CreatePrivatePkiOrderRequest
            {
                Variant   = "igtf-host",
                Hostname  = "compute01.hpc.example.edu",
                Requestor = new V2Requestor { Name = "HPC Operations", Email = "hpc-ops@example.edu" }
            };

            using var doc = JsonDocument.Parse(Serialize(request));
            doc.RootElement.EnumerateObject().Select(p => p.Name).Should().BeEquivalentTo(
                new[] { "variant", "requestor", "hostname" },
                "only the spec's strictly-mandatory fields remain when nothing optional is set");
        }

        // ---------------------------------------------------------------------------
        // Document Signer — spec "Document Signer Certificates" create examples
        // ---------------------------------------------------------------------------

        private const string SpecCreateNaturalPersonBody = """
        {
         "subjectType": "natural-person",
         "emailNotifications": "all",
         "requestor": {
         "name": "Sarah Johnson",
         "email": "sarah.johnson@example.com",
         "phone": "+12025551234",
         "designation": "Document Signer"
         },
         "subject": {
         "firstName": "Sarah",
         "lastName": "Johnson",
         "email": "sarah.johnson@example.com",
         "phone": "+12025551234",
         "identityDocumentType": "passport",
         "identificationNumber": "X12345678",
         "streetAddress1": "1600 Pennsylvania Avenue NW",
         "locality": "Washington",
         "state": "DC",
         "postalCode": "20500",
         "countryCode": "US"
         },
         "subscription": { "validityYears": 1, "autoRenew": false },
         "agreement": {
         "signerName": "Sarah Johnson",
         "signerPlace": "Washington, DC",
         "accepted": true
         },
         "remarks": "Document Signer - Natural Person, US"
        }
        """;

        [Fact]
        public void Signature_CreateNaturalPersonSpecExample_SerializesToExactlyTheSpecBody()
        {
            var request = new V2CreateSignatureOrderRequest
            {
                SubjectType        = "natural-person",
                EmailNotifications = "all",
                Requestor = new V2Requestor
                {
                    Name = "Sarah Johnson", Email = "sarah.johnson@example.com", Phone = "+12025551234", Designation = "Document Signer"
                },
                Subject = new V2SignatureSubject
                {
                    FirstName            = "Sarah",
                    LastName             = "Johnson",
                    Email                = "sarah.johnson@example.com",
                    Phone                = "+12025551234",
                    IdentityDocumentType = "passport",
                    IdentificationNumber = "X12345678",
                    StreetAddress1       = "1600 Pennsylvania Avenue NW",
                    Locality             = "Washington",
                    State                = "DC",
                    PostalCode           = "20500",
                    CountryCode          = "US"
                },
                Subscription = new V2SubscriptionParams { ValidityYears = 1, AutoRenew = false },
                // signerIp deliberately null: not in the signature field table, and the spec's
                // Accept Agreement note says it "will be ignored" if sent.
                Agreement = new V2AgreementParams { SignerName = "Sarah Johnson", SignerPlace = "Washington, DC", Accepted = true },
                Remarks   = "Document Signer - Natural Person, US"
            };

            Canonical(Serialize(request)).Should().Be(Canonical(SpecCreateNaturalPersonBody));
        }

        private const string SpecCreateLegalPersonBody = """
        {
         "subjectType": "legal-person",
         "emailNotifications": "all",
         "requestor": {
         "name": "Michael Chen",
         "email": "michael.chen@acme.com",
         "phone": "+14155551234",
         "designation": "VP Engineering"
         },
         "subject": {
         "firstName": "Michael",
         "lastName": "Chen",
         "email": "michael.chen@acme.com",
         "phone": "+14155551234",
         "designation": "VP Engineering",
         "organizationName": "Acme Corporation",
         "organizationUnit": "Engineering",
         "organizationIdentificationNumber": "EIN-12-3456789",
         "identityDocumentType": "passport",
         "identificationNumber": "P98765432",
         "streetAddress1": "500 Market Street",
         "streetAddress2": "Suite 300",
         "locality": "San Francisco",
         "state": "CA",
         "postalCode": "94105",
         "countryCode": "US"
         },
         "subscription": { "validityYears": 1, "autoRenew": false },
         "agreement": {
         "signerName": "Michael Chen",
         "signerPlace": "San Francisco, CA",
         "accepted": true
         },
         "remarks": "Document Signer - Legal Person, employee of Acme Corp"
        }
        """;

        [Fact]
        public void Signature_CreateLegalPersonSpecExample_SerializesToExactlyTheSpecBody()
        {
            var request = new V2CreateSignatureOrderRequest
            {
                SubjectType        = "legal-person",
                EmailNotifications = "all",
                Requestor = new V2Requestor
                {
                    Name = "Michael Chen", Email = "michael.chen@acme.com", Phone = "+14155551234", Designation = "VP Engineering"
                },
                Subject = new V2SignatureSubject
                {
                    FirstName                        = "Michael",
                    LastName                         = "Chen",
                    Email                            = "michael.chen@acme.com",
                    Phone                            = "+14155551234",
                    Designation                      = "VP Engineering",
                    OrganizationName                 = "Acme Corporation",
                    OrganizationUnit                 = "Engineering",
                    OrganizationIdentificationNumber = "EIN-12-3456789",
                    IdentityDocumentType             = "passport",
                    IdentificationNumber             = "P98765432",
                    StreetAddress1                   = "500 Market Street",
                    StreetAddress2                   = "Suite 300",
                    Locality                         = "San Francisco",
                    State                            = "CA",
                    PostalCode                       = "94105",
                    CountryCode                      = "US"
                },
                Subscription = new V2SubscriptionParams { ValidityYears = 1, AutoRenew = false },
                Agreement    = new V2AgreementParams { SignerName = "Michael Chen", SignerPlace = "San Francisco, CA", Accepted = true },
                Remarks      = "Document Signer - Legal Person, employee of Acme Corp"
            };

            Canonical(Serialize(request)).Should().Be(Canonical(SpecCreateLegalPersonBody));
        }

        private const string SpecCreateLegalEntityBody = """
        {
         "subjectType": "legal-entity",
         "emailNotifications": "all",
         "requestor": {
         "name": "Acme Corporation Compliance",
         "email": "pki-ops@acme.com",
         "phone": "+14155551234",
         "designation": "PKI Operations"
         },
         "subject": {
         "organizationName": "Acme Corporation",
         "organizationUnit": "Compliance",
         "businessCategory": "Business Entity",
         "organizationIdentificationNumber": "EIN-12-3456789",
         "email": "pki-ops@acme.com",
         "phone": "+14155551234",
         "streetAddress1": "500 Market Street",
         "streetAddress2": "Suite 300",
         "locality": "San Francisco",
         "state": "CA",
         "postalCode": "94105",
         "countryCode": "US"
         },
         "subscription": { "validityYears": 1, "autoRenew": false },
         "agreement": {
         "signerName": "Acme Corp PKI Operations",
         "signerPlace": "San Francisco, CA",
         "accepted": true
         },
         "remarks": "Document Signer - Legal Entity (org-only subject)"
        }
        """;

        [Fact]
        public void Signature_CreateLegalEntitySpecExample_SerializesToExactlyTheSpecBody_WithNoPersonNameKeys()
        {
            var request = new V2CreateSignatureOrderRequest
            {
                SubjectType        = "legal-entity",
                EmailNotifications = "all",
                Requestor = new V2Requestor
                {
                    Name = "Acme Corporation Compliance", Email = "pki-ops@acme.com", Phone = "+14155551234", Designation = "PKI Operations"
                },
                Subject = new V2SignatureSubject
                {
                    OrganizationName                 = "Acme Corporation",
                    OrganizationUnit                 = "Compliance",
                    BusinessCategory                 = "Business Entity",
                    OrganizationIdentificationNumber = "EIN-12-3456789",
                    Email                            = "pki-ops@acme.com",
                    Phone                            = "+14155551234",
                    StreetAddress1                   = "500 Market Street",
                    StreetAddress2                   = "Suite 300",
                    Locality                         = "San Francisco",
                    State                            = "CA",
                    PostalCode                       = "94105",
                    CountryCode                      = "US"
                },
                Subscription = new V2SubscriptionParams { ValidityYears = 1, AutoRenew = false },
                Agreement    = new V2AgreementParams { SignerName = "Acme Corp PKI Operations", SignerPlace = "San Francisco, CA", Accepted = true },
                Remarks      = "Document Signer - Legal Entity (org-only subject)"
            };

            string json = Serialize(request);

            Canonical(json).Should().Be(Canonical(SpecCreateLegalEntityBody));
            json.Should().NotContain("firstName").And.NotContain("lastName",
                "subject.firstName/lastName are conditional on natural-/legal-person and must be omitted, not sent null");
        }

        [Fact]
        public void Signature_SubjectEmail_IsAlwaysWritten_EvenWhenOtherSubjectFieldsAreAbsent()
        {
            // subject.email is the one strictly-mandatory subject field ("400 if missing").
            var json = Serialize(new V2SignatureSubject { Email = "signer@example.com" });

            Canonical(json).Should().Be(Canonical("{\"email\":\"signer@example.com\"}"));
        }
    }
}
