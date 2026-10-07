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

using System.Text.Json;
using System.Text.Json.Serialization;
using FluentAssertions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.Extensions.CAPlugin.CERTInext.Models;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Requestor personal data (name, email, phone, org contact fields) must not
    /// appear in gateway logs unless the connector's <c>LogSensitiveRequestData</c> setting is
    /// explicitly turned on. These tests pin <see cref="CERTInextClient.RedactPersonalData"/> and
    /// <see cref="CERTInextClient.ApplyLoggingRedaction"/> against realistic V1 and V2 order
    /// payload JSON, produced by serializing the real request/response models rather than
    /// hand-written strings — so a future rename of a JSON property name (which would silently
    /// stop the redactor from matching it) fails these tests immediately.
    /// </summary>
    public class RedactPersonalDataTests
    {
        // Mirrors CERTInextClient.GetJsonOptions() (private), so serialized payloads in these
        // tests match the real wire shape (case-insensitive property names, nulls omitted).
        private static JsonSerializerOptions ClientEquivalentJsonOptions() => new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        // ---------------------------------------------------------------------------
        // V1 GenerateOrderSSL request — requestorInformation / technicalPointOfContact /
        // agreementDetails all carry personal data; certificateInformation/orderDetails don't.
        // ---------------------------------------------------------------------------

        private static string BuildV1OrderRequestJson()
        {
            var request = new GenerateOrderSslRequest
            {
                Meta = new RequestMeta { Ver = "1.0", Ts = "2026-05-22T10:00:00+00:00", Txn = "1234567890", AccountNumber = "9988776655" },
                OrderDetails = new SslOrderDetails
                {
                    ProductCode = "842",
                    AccountingModel = "2",
                    SaveAndHold = "0",
                    EmailNotifications = "0",
                    RequestorInformation = new RequestorInformation
                    {
                        RequestorName = "Jane Doe",
                        RequestorIsdCode = "1",
                        RequestorMobileNumber = "5551234567",
                        RequestorEmail = "jane.doe@example.com",
                        RequestorDesignation = "IT Administrator"
                    },
                    SubscriptionDetails = new SubscriptionDetails { Validity = "1", AutoRenew = "0", RenewCriteria = "30" },
                    CertificateInformation = new CertificateInformation
                    {
                        DomainName = "example.com",
                        AdditionalDomains = new System.Collections.Generic.List<string> { "alt.example.com", "www.example.com" }
                    },
                    AgreementDetails = new AgreementDetails
                    {
                        AcceptAgreement = "1",
                        SignerName = "John Signer",
                        SignerPlace = "Austin",
                        SignerIp = "203.0.113.10"
                    },
                    TechnicalPointOfContact = new TechnicalPointOfContact
                    {
                        TpcName = "Tech Contact",
                        TpcEmail = "tech.contact@example.com",
                        TpcIsdCode = "1",
                        TpcMobileNumber = "5559876543"
                    }
                }
            };

            return JsonSerializer.Serialize(request, ClientEquivalentJsonOptions());
        }

        [Fact]
        public void RedactPersonalData_V1OrderRequest_RemovesAllPersonFields()
        {
            string input = BuildV1OrderRequestJson();
            string output = CERTInextClient.RedactPersonalData(input);

            output.Should().NotContain("Jane Doe");
            output.Should().NotContain("jane.doe@example.com");
            output.Should().NotContain("5551234567");
            output.Should().NotContain("IT Administrator");
            output.Should().NotContain("John Signer");
            output.Should().NotContain("Austin");
            output.Should().NotContain("203.0.113.10");
            output.Should().NotContain("Tech Contact");
            output.Should().NotContain("tech.contact@example.com");
            output.Should().NotContain("5559876543");
        }

        [Fact]
        public void RedactPersonalData_V1OrderRequest_MasksEmailsKeepingDomain()
        {
            string output = CERTInextClient.RedactPersonalData(BuildV1OrderRequestJson());

            output.Should().Contain("\"requestorEmail\":\"j***@example.com\"");
            output.Should().Contain("\"tpcEmail\":\"t***@example.com\"");
        }

        [Fact]
        public void RedactPersonalData_V1OrderRequest_PreservesNonPersonalFields()
        {
            string output = CERTInextClient.RedactPersonalData(BuildV1OrderRequestJson());

            output.Should().Contain("\"productCode\":\"842\"");
            output.Should().Contain("\"domainName\":\"example.com\"");
            output.Should().Contain("alt.example.com");
            output.Should().Contain("www.example.com");
            output.Should().Contain("\"accountNumber\":\"9988776655\"");
            output.Should().Contain("\"validity\":\"1\"");
        }

        [Fact]
        public void RedactPersonalData_V1OrderRequest_RedactsRequestorNameToPlaceholder()
        {
            string output = CERTInextClient.RedactPersonalData(BuildV1OrderRequestJson());

            output.Should().Contain("\"requestorName\":\"***REDACTED***\"");
            output.Should().Contain("\"requestorMobileNumber\":\"***REDACTED***\"");
            output.Should().Contain("\"requestorDesignation\":\"***REDACTED***\"");
            output.Should().Contain("\"signerName\":\"***REDACTED***\"");
            output.Should().Contain("\"signerPlace\":\"***REDACTED***\"");
            output.Should().Contain("\"signerIP\":\"***REDACTED***\"");
            output.Should().Contain("\"tpcName\":\"***REDACTED***\"");
            output.Should().Contain("\"tpcMobileNumber\":\"***REDACTED***\"");
        }

        // ---------------------------------------------------------------------------
        // V2 order create request — requestor / technicalPointOfContact / agreement all carry
        // bare name/email/phone/designation/signerName keys; certificate/subscription don't.
        // ---------------------------------------------------------------------------

        private static string BuildV2OrderRequestJson()
        {
            var request = new V2CreateSslOrderRequest
            {
                ProductVariant = "ov",
                EmailNotifications = "0",
                Requestor = new V2Requestor
                {
                    Name = "Jane Doe",
                    Email = "jane.doe@example.com",
                    Phone = "+15551234567",
                    Designation = "IT Administrator"
                },
                Organization = new V2OrganizationParams { OrganizationNumber = "1234567", PreVetted = true },
                Certificate = new V2CertificateParams
                {
                    Domain = "example.com",
                    AdditionalDomains = new System.Collections.Generic.List<string> { "alt.example.com" }
                },
                Subscription = new V2SubscriptionParams { ValidityYears = 1, AutoRenew = false },
                Agreement = new V2AgreementParams
                {
                    SignerName = "John Signer",
                    SignerIp = "203.0.113.10",
                    SignerPlace = "Austin"
                },
                TechnicalPointOfContact = new V2TechnicalPointOfContact
                {
                    Name = "Tech Contact",
                    Email = "tech.contact@example.com",
                    Phone = "+15559876543",
                    Designation = "PKI Manager"
                },
                GroupNumber = "2345678901"
            };

            return JsonSerializer.Serialize(request, ClientEquivalentJsonOptions());
        }

        [Fact]
        public void RedactPersonalData_V2OrderRequest_RemovesAllPersonFields()
        {
            string output = CERTInextClient.RedactPersonalData(BuildV2OrderRequestJson());

            output.Should().NotContain("Jane Doe");
            output.Should().NotContain("jane.doe@example.com");
            output.Should().NotContain("+15551234567");
            output.Should().NotContain("IT Administrator");
            output.Should().NotContain("John Signer");
            output.Should().NotContain("Austin");
            output.Should().NotContain("203.0.113.10");
            output.Should().NotContain("Tech Contact");
            output.Should().NotContain("tech.contact@example.com");
            output.Should().NotContain("+15559876543");
            output.Should().NotContain("PKI Manager");
        }

        [Fact]
        public void RedactPersonalData_V2OrderRequest_MasksEmailsKeepingDomain()
        {
            string output = CERTInextClient.RedactPersonalData(BuildV2OrderRequestJson());

            // requestor.email ("jane.doe@example.com") and technicalPointOfContact.email
            // ("tech.contact@example.com") both use the same bare "email" key but have distinct
            // local parts — both must be masked independently (domain kept in each).
            output.Should().Contain("\"email\":\"j***@example.com\"");
            output.Should().Contain("\"email\":\"t***@example.com\"");
        }

        [Fact]
        public void RedactPersonalData_V2OrderRequest_PreservesNonPersonalFields()
        {
            string output = CERTInextClient.RedactPersonalData(BuildV2OrderRequestJson());

            output.Should().Contain("\"productVariant\":\"ov\"");
            output.Should().Contain("\"domain\":\"example.com\"");
            output.Should().Contain("alt.example.com");
            output.Should().Contain("\"organizationNumber\":\"1234567\"");
            output.Should().Contain("\"groupNumber\":\"2345678901\"");
            output.Should().Contain("\"validityYears\":1");
        }

        [Fact]
        public void RedactPersonalData_V2OrderRequest_NestedNameFieldsRedactedToPlaceholder()
        {
            string output = CERTInextClient.RedactPersonalData(BuildV2OrderRequestJson());

            // Both requestor.name and technicalPointOfContact.name must be caught even though
            // they are nested inside different objects using the same bare "name" key.
            var nameMatches = System.Text.RegularExpressions.Regex.Matches(output, "\"name\":\"\\*\\*\\*REDACTED\\*\\*\\*\"");
            nameMatches.Count.Should().Be(2, "both requestor.name and technicalPointOfContact.name must be redacted");

            output.Should().Contain("\"phone\":\"***REDACTED***\"");
            output.Should().Contain("\"designation\":\"***REDACTED***\"");
            output.Should().Contain("\"signerName\":\"***REDACTED***\"");
            output.Should().Contain("\"signerIp\":\"***REDACTED***\"");
            output.Should().Contain("\"signerPlace\":\"***REDACTED***\"");
        }

        // V2 place-order response echoes the agreement as subscriberAgreement with the key
        // "signedPlace" (not the request's "signerPlace"), plus an orderedBy contact. Shape taken
        // from a sandbox response; values here are fictitious.
        private const string V2OrderResponseJson =
            "{\"orderId\":\"4898663698\",\"status\":\"pending-approval\",\"productVariant\":\"dv\"," +
            "\"domain\":\"example.com\",\"resolvedProductCode\":\"842\"," +
            "\"requestor\":{\"name\":\"Jane Doe\",\"email\":\"jane.doe@example.com\"}," +
            "\"orderedBy\":{\"name\":\"Account Owner\",\"email\":\"owner@example.com\"}," +
            "\"subscriberAgreement\":{\"signed\":true,\"signerName\":\"John Signer\"," +
            "\"signedAt\":\"2026-09-26T15:58:51Z\",\"signedPlace\":\"Austin\"}}";

        [Fact]
        public void RedactPersonalData_V2OrderResponse_RedactsSubscriberAgreementAndOrderedBy()
        {
            string output = CERTInextClient.RedactPersonalData(V2OrderResponseJson);

            output.Should().NotContain("Austin");
            output.Should().Contain("\"signedPlace\":\"***REDACTED***\"");
            output.Should().NotContain("John Signer");
            output.Should().NotContain("Jane Doe");
            output.Should().NotContain("Account Owner");
            output.Should().Contain("\"email\":\"o***@example.com\"");
            output.Should().Contain("\"orderId\":\"4898663698\"");
            output.Should().Contain("\"domain\":\"example.com\"");
            output.Should().Contain("\"signedAt\":\"2026-09-26T15:58:51Z\"");
        }

        // ---------------------------------------------------------------------------
        // Whitespace tolerance — a pretty-printed body must redact identically to a compact one.
        // ---------------------------------------------------------------------------

        [Fact]
        public void RedactPersonalData_TolerantOfWhitespaceAroundKeyValueSeparator()
        {
            string input = "{\n  \"requestor\" : {\n    \"name\"   :   \"Jane Doe\",\n    \"email\":\"jane.doe@example.com\"\n  }\n}";

            string output = CERTInextClient.RedactPersonalData(input);

            output.Should().NotContain("Jane Doe");
            output.Should().Contain("j***@example.com");
        }

        // ---------------------------------------------------------------------------
        // Edge cases
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void RedactPersonalData_HandlesNullAndEmpty(string input)
        {
            CERTInextClient.RedactPersonalData(input).Should().Be(input);
        }

        [Fact]
        public void RedactPersonalData_LeavesAlreadyBlankFieldsUntouched()
        {
            string input = "{\"requestorName\":\"\",\"requestorEmail\":\"\"}";
            CERTInextClient.RedactPersonalData(input).Should().Be(input,
                "there is nothing to redact in an already-blank field");
        }

        [Fact]
        public void RedactPersonalData_MalformedEmailValue_FallsBackToFullRedaction()
        {
            string input = "{\"requestorEmail\":\"not-an-email\"}";
            string output = CERTInextClient.RedactPersonalData(input);
            output.Should().Be("{\"requestorEmail\":\"***REDACTED***\"}");
        }

        [Fact]
        public void RedactPersonalData_DoesNotTouchUnrelatedNameLikeKeys()
        {
            // domainName / organizationName end in "Name" but are not the exact key "name" —
            // the anchored quote-delimited match must not treat them as substrings of "name".
            string input = "{\"domainName\":\"example.com\",\"organizationName\":\"Acme Corp\"}";
            CERTInextClient.RedactPersonalData(input).Should().Be(input);
        }

        // ---------------------------------------------------------------------------
        // Credentials are always redacted, regardless of RedactPersonalData
        // ---------------------------------------------------------------------------

        [Fact]
        public void RedactPersonalData_DoesNotRedactCredentials_ThatIsRedactCredentialsJob()
        {
            // RedactPersonalData is deliberately scoped to person/contact fields only; credential
            // scrubbing is RedactCredentials's job and is applied unconditionally by
            // ApplyLoggingRedaction regardless of this method.
            string input = "{\"authKey\":\"deadbeef\",\"requestorName\":\"Jane Doe\"}";
            string output = CERTInextClient.RedactPersonalData(input);

            output.Should().Contain("deadbeef", "RedactPersonalData alone does not scrub credentials");
            output.Should().NotContain("Jane Doe");
        }

        // ---------------------------------------------------------------------------
        // ApplyLoggingRedaction — the flag-gated composition used at every log site
        // ---------------------------------------------------------------------------

        [Fact]
        public void ApplyLoggingRedaction_FlagOff_RedactsBothCredentialsAndPersonalData()
        {
            string input = "{\"authKey\":\"deadbeef\",\"requestorName\":\"Jane Doe\",\"requestorEmail\":\"jane.doe@example.com\",\"domainName\":\"example.com\"}";

            string output = CERTInextClient.ApplyLoggingRedaction(input, logSensitiveRequestData: false);

            output.Should().NotContain("deadbeef");
            output.Should().NotContain("Jane Doe");
            output.Should().Contain("j***@example.com");
            output.Should().Contain("\"domainName\":\"example.com\"");
        }

        [Fact]
        public void ApplyLoggingRedaction_FlagOn_RedactsCredentialsOnly_LeavesPersonalDataInFull()
        {
            string input = "{\"authKey\":\"deadbeef\",\"requestorName\":\"Jane Doe\",\"requestorEmail\":\"jane.doe@example.com\",\"domainName\":\"example.com\"}";

            string output = CERTInextClient.ApplyLoggingRedaction(input, logSensitiveRequestData: true);

            output.Should().NotContain("deadbeef", "credentials must always be redacted, even with the flag on");
            output.Should().Contain("Jane Doe", "personal data is left in full when the flag is on");
            output.Should().Contain("jane.doe@example.com", "personal data is left in full when the flag is on");
            output.Should().Contain("\"domainName\":\"example.com\"");
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void ApplyLoggingRedaction_HandlesNullAndEmpty(string input)
        {
            CERTInextClient.ApplyLoggingRedaction(input, logSensitiveRequestData: false).Should().Be(input);
            CERTInextClient.ApplyLoggingRedaction(input, logSensitiveRequestData: true).Should().Be(input);
        }

        // ---------------------------------------------------------------------------
        // V2 Private PKI and Document Signer (signature) order bodies. Built from the
        // real DTOs so a JSON property rename that would silently defeat the redactor fails here.
        // ---------------------------------------------------------------------------

        // Values mirror the spec's "Create - Natural Person" example body.
        private static string BuildV2SignatureOrderRequestJson()
        {
            var request = new V2CreateSignatureOrderRequest
            {
                SubjectType = "natural-person",
                EmailNotifications = "all",
                Requestor = new V2Requestor { Name = "Sarah Johnson", Email = "sarah.johnson@example.com", Phone = "+12025551234", Designation = "Document Signer" },
                Subject = new V2SignatureSubject
                {
                    FirstName = "Sarah",
                    LastName = "Johnson",
                    Email = "sarah.johnson@example.com",
                    Phone = "+12025551234",
                    IdentityDocumentType = "passport",
                    IdentificationNumber = "X12345678",
                    StreetAddress1 = "1600 Pennsylvania Avenue NW",
                    StreetAddress2 = "Apt 7",
                    Locality = "Washington",
                    State = "DC",
                    PostalCode = "20500",
                    CountryCode = "US"
                },
                Subscription = new V2SubscriptionParams { ValidityYears = 1, AutoRenew = false },
                Agreement = new V2AgreementParams { SignerName = "Sarah Johnson", SignerPlace = "Washington, DC", Accepted = true },
                Remarks = "Document Signer - Natural Person, US"
            };
            return JsonSerializer.Serialize(request, ClientEquivalentJsonOptions());
        }

        [Fact]
        public void RedactPersonalData_V2SignatureOrderRequest_RemovesSubjectPersonFields()
        {
            string output = CERTInextClient.RedactPersonalData(BuildV2SignatureOrderRequestJson());

            // Name, identity-document and street-address values must all be gone.
            foreach (var raw in new[]
                     {
                         "Sarah", "Johnson", "+12025551234", "Document Signer\"", "passport", "X12345678",
                         "1600 Pennsylvania Avenue NW", "Apt 7", "\"Washington\"", "20500", "Washington, DC"
                     })
            {
                output.Should().NotContain(raw, $"'{raw}' is subject/requestor personal data");
            }

            // subject.email and requestor.email are masked to their domain, not dropped.
            output.Should().NotContain("sarah.johnson@");
            output.Should().Contain("s***@example.com");
        }

        [Fact]
        public void RedactPersonalData_V2SignatureOrderRequest_PreservesNonPersonalFields()
        {
            string output = CERTInextClient.RedactPersonalData(BuildV2SignatureOrderRequestJson());

            // Deliberately-not-redacted keys: the discriminator, coarse location, and the
            // agreement flag carry no personal identity on their own.
            output.Should().Contain("\"subjectType\":\"natural-person\"");
            output.Should().Contain("\"state\":\"DC\"");
            output.Should().Contain("\"countryCode\":\"US\"");
            output.Should().Contain("\"accepted\":true");
        }

        [Fact]
        public void RedactPersonalData_V2SignatureCreateResponse_RedactsSubjectDisplayName()
        {
            // Spec "Create - Natural Person" response: subjectDisplayName is the full name for a
            // natural / legal person. PlaceOrderV2Async logs this response body at Trace.
            string input = "{\"orderId\":\"ord_sig_1\",\"status\":\"pending-documents\",\"subjectType\":\"natural-person\"," +
                           "\"subjectDisplayName\":\"Sarah Johnson\",\"resolvedProductCode\":\"819\"}";

            string output = CERTInextClient.RedactPersonalData(input);

            output.Should().NotContain("Sarah Johnson");
            output.Should().Contain("\"subjectDisplayName\":\"***REDACTED***\"");
            output.Should().Contain("\"orderId\":\"ord_sig_1\"");
            output.Should().Contain("\"resolvedProductCode\":\"819\"");
        }

        [Fact]
        public void RedactPersonalData_LegalEntitySubject_KeepsOrganizationFields()
        {
            // Organization identity is not personal data, and "organizationName" is also a V1
            // order/report key for an OV organization — deliberately excluded from the key set.
            var request = new V2CreateSignatureOrderRequest
            {
                SubjectType = "legal-entity",
                Requestor = new V2Requestor { Name = "Acme Corporation Compliance", Email = "pki-ops@acme.com" },
                Subject = new V2SignatureSubject
                {
                    OrganizationName = "Acme Corporation",
                    OrganizationUnit = "Compliance",
                    BusinessCategory = "Business Entity",
                    OrganizationIdentificationNumber = "EIN-12-3456789",
                    Email = "pki-ops@acme.com"
                }
            };
            string json = JsonSerializer.Serialize(request, ClientEquivalentJsonOptions());

            string output = CERTInextClient.RedactPersonalData(json);

            output.Should().Contain("\"organizationName\":\"Acme Corporation\"");
            output.Should().Contain("\"organizationIdentificationNumber\":\"EIN-12-3456789\"");
            output.Should().NotContain("Acme Corporation Compliance", "requestor.name is still personal/contact data");
            output.Should().NotContain("pki-ops@");
        }

        [Fact]
        public void ApplyLoggingRedaction_V2SignatureOrderRequest_FlagOn_LeavesSubjectInFull()
        {
            string output = CERTInextClient.ApplyLoggingRedaction(BuildV2SignatureOrderRequestJson(), logSensitiveRequestData: true);

            output.Should().Contain("\"firstName\":\"Sarah\"");
            output.Should().Contain("\"identificationNumber\":\"X12345678\"");
            output.Should().Contain("sarah.johnson@example.com");
        }

        [Fact]
        public void ApplyLoggingRedaction_V2PrivatePkiOrderRequest_FlagOff_RedactsRequestorAndContact_KeepsHosts()
        {
            // Private PKI adds no new personal keys (requestor / technicalPointOfContact reuse the
            // bare name/email/phone/designation keys); hostname / additionalHosts are diagnostic
            // host data and must survive redaction.
            var request = new V2CreatePrivatePkiOrderRequest
            {
                Variant = "intranet-ssl",
                Hostname = "intranet.acme.local",
                AdditionalHosts = new System.Collections.Generic.List<string> { "portal.acme.local", "10.0.0.50" },
                Requestor = new V2Requestor { Name = "DevOps Team", Email = "devops@acme.com", Phone = "+14155551234", Designation = "Platform Engineering" },
                TechnicalPointOfContact = new V2TechnicalPointOfContact { Name = "Tech Person", Email = "tech@acme.com", Phone = "+14155550000", Designation = "Technical Contact" },
                Subscription = new V2SubscriptionParams { ValidityYears = 1 }
            };
            string json = JsonSerializer.Serialize(request, ClientEquivalentJsonOptions());

            string output = CERTInextClient.ApplyLoggingRedaction(json, logSensitiveRequestData: false);

            foreach (var raw in new[] { "DevOps Team", "devops@", "+14155551234", "Platform Engineering", "Tech Person", "tech@", "+14155550000" })
                output.Should().NotContain(raw);
            output.Should().Contain("\"hostname\":\"intranet.acme.local\"");
            output.Should().Contain("portal.acme.local");
            output.Should().Contain("10.0.0.50");
            output.Should().Contain("\"variant\":\"intranet-ssl\"");
        }

        // ---------------------------------------------------------------------------
        // Email SANs inside SAN arrays (V1 additionalDomains carries every
        // SAN type) and V1 TrackOrder domainVerification keys, which the key/value regex can't reach.
        // ---------------------------------------------------------------------------

        private static string BuildV1OrderRequestJsonWithMixedSans(bool indented)
        {
            var request = new GenerateOrderSslRequest
            {
                Meta = new RequestMeta { Ver = "1.0", Ts = "2026-05-22T10:00:00+00:00", Txn = "1234567890", AccountNumber = "9988776655" },
                OrderDetails = new SslOrderDetails
                {
                    ProductCode = "844",
                    RequestorInformation = new RequestorInformation { RequestorName = "Jane Doe", RequestorEmail = "jane.doe@example.com" },
                    CertificateInformation = new CertificateInformation
                    {
                        DomainName = "example.com",
                        AdditionalDomains = new System.Collections.Generic.List<string> { "a.example.com", "alice@example.com", "10.0.0.1" }
                    }
                }
            };
            var options = ClientEquivalentJsonOptions();
            options.WriteIndented = indented;
            return JsonSerializer.Serialize(request, options);
        }

        [Fact]
        public void ApplyLoggingRedaction_V1AdditionalDomains_FlagOff_MasksOnlyEmailElement()
        {
            string output = CERTInextClient.ApplyLoggingRedaction(BuildV1OrderRequestJsonWithMixedSans(indented: false), logSensitiveRequestData: false);

            output.Should().NotContain("alice@");
            output.Should().Contain("\"additionalDomains\":[\"a.example.com\",\"a***@example.com\",\"10.0.0.1\"]");
            output.Should().Contain("\"domainName\":\"example.com\"");
            output.Should().Contain("j***@example.com", "the existing key/value redaction still runs");
        }

        [Fact]
        public void ApplyLoggingRedaction_V1AdditionalDomains_PrettyPrinted_FlagOff_MasksOnlyEmailElement()
        {
            string input = BuildV1OrderRequestJsonWithMixedSans(indented: true);
            input.Should().Contain("\n", "precondition: the body is pretty-printed");

            string output = CERTInextClient.ApplyLoggingRedaction(input, logSensitiveRequestData: false);

            output.Should().NotContain("alice@");
            output.Should().Contain("\"a***@example.com\"");
            output.Should().Contain("\"a.example.com\"");
            output.Should().Contain("\"10.0.0.1\"");
            // Only the email token changes; the layout of the array is preserved.
            string expectedArray = System.Text.RegularExpressions.Regex.Match(input, @"""additionalDomains"":\s*\[[^\]]*\]").Value
                .Replace("\"alice@example.com\"", "\"a***@example.com\"");
            expectedArray.Should().NotBeEmpty();
            output.Should().Contain(expectedArray);
        }

        [Fact]
        public void ApplyLoggingRedaction_V1AdditionalDomains_FlagOn_LeavesArrayVerbatim()
        {
            string input = BuildV1OrderRequestJsonWithMixedSans(indented: false);

            string output = CERTInextClient.ApplyLoggingRedaction(input, logSensitiveRequestData: true);

            output.Should().Be(CERTInextClient.RedactCredentials(input));
            output.Should().Contain("\"additionalDomains\":[\"a.example.com\",\"alice@example.com\",\"10.0.0.1\"]");
        }

        [Fact]
        public void RedactPersonalData_HandWrittenWhitespaceInSanArray_MasksEmailAndKeepsLayout()
        {
            string input = "{ \"additionalDomains\" :\n  [ \"a.example.com\" ,\n    \"alice@example.com\",\"10.0.0.1\" ] }";

            string output = CERTInextClient.RedactPersonalData(input);

            output.Should().Be("{ \"additionalDomains\" :\n  [ \"a.example.com\" ,\n    \"a***@example.com\",\"10.0.0.1\" ] }");
        }

        [Fact]
        public void RedactPersonalData_SanArrayKeyMatch_IsCaseInsensitive()
        {
            CERTInextClient.RedactPersonalData("{\"AdditionalDomains\":[\"alice@example.com\"]}")
                .Should().Be("{\"AdditionalDomains\":[\"a***@example.com\"]}");
        }

        [Fact]
        public void RedactPersonalData_EscapedEmailElement_IsMasked()
        {
            // Elements using JSON unicode escapes (backslash-u0040 for '@', backslash-u0069 for 'i')
            // must still be detected and masked.
            CERTInextClient.RedactPersonalData("{\"additionalDomains\":[\"alice\\u0040example.com\",\"al\\u0069ce@example.com\"]}")
                .Should().Be("{\"additionalDomains\":[\"a***@example.com\",\"a***@example.com\"]}");
        }

        [Fact]
        public void RedactPersonalData_V2SanArrays_MaskEmailElements_DefenceInDepth()
        {
            // V2 filters these to DNS/IP before submission; a mis-typed email must still be masked,
            // and DNS/IP values must be untouched.
            CERTInextClient.RedactPersonalData("{\"certificate\":{\"domain\":\"example.com\",\"additionalDomains\":[\"www.example.com\",\"bob@example.com\"]}}")
                .Should().Be("{\"certificate\":{\"domain\":\"example.com\",\"additionalDomains\":[\"www.example.com\",\"b***@example.com\"]}}");
            CERTInextClient.RedactPersonalData("{\"hostname\":\"h.acme.local\",\"additionalHosts\":[\"10.0.0.50\",\"bob@acme.local\",\"::1\"]}")
                .Should().Be("{\"hostname\":\"h.acme.local\",\"additionalHosts\":[\"10.0.0.50\",\"b***@acme.local\",\"::1\"]}");
        }

        [Fact]
        public void RedactPersonalData_UnrelatedArraysAndValuesWithAt_AreUntouched()
        {
            // Only the named SAN containers are touched. An '@' in any other array, object key or
            // string value is left as it is.
            string input = "{\"notifyList\":[\"alice@example.com\"],\"tags\":[\"x@y\"],\"note\":\"ping bob@example.com\"," +
                           "\"customFields\":{\"owner@example.com\":\"v\"},\"additionalDomains\":[\"a.example.com\"]}";

            CERTInextClient.RedactPersonalData(input).Should().Be(input);
        }

        [Fact]
        public void RedactPersonalData_NestedContainersInsideSanArray_AreNotDescendedInto()
        {
            // Only direct string elements of the array are candidates.
            string input = "{\"additionalDomains\":[[\"alice@example.com\"],{\"k\":\"bob@example.com\"},\"carol@example.com\"]}";

            CERTInextClient.RedactPersonalData(input)
                .Should().Be("{\"additionalDomains\":[[\"alice@example.com\"],{\"k\":\"bob@example.com\"},\"c***@example.com\"]}");
        }

        // V1 TrackOrder wire shape per the spec: domainVerification is keyed by domain name, with a
        // block-level "status". An email SAN submitted in additionalDomains comes back as one of
        // these keys.
        private const string V1TrackOrderResponseWithEmailDomainKey =
            "{\"meta\":{\"status\":\"1\"},\"orderDetails\":{\"orderStatus\":\"Pending\"," +
            "\"domainVerification\":{" +
            "\"example.com\":{\"dcvMethod\":\"DNS\",\"dcvStatus\":\"1\",\"status\":\"1\",\"verifiedDate\":\"2026-09-01\",\"caaStatus\":\"1\"}," +
            "\"san-probe@example.com\":{\"dcvMethod\":\"\",\"dcvStatus\":\"0\",\"status\":\"1\",\"verifiedDate\":\"\",\"caaStatus\":\"1\"}," +
            "\"192.0.2.10\":{\"dcvMethod\":\"\",\"dcvStatus\":\"0\",\"status\":\"1\",\"verifiedDate\":\"\",\"caaStatus\":\"1\"}," +
            "\"status\":\"0\"}," +
            "\"customFields\":{\"owner@example.com\":\"kept\"}}}";

        [Fact]
        public void ApplyLoggingRedaction_V1TrackOrderDomainVerification_FlagOff_MasksEmailKeyOnly()
        {
            string output = CERTInextClient.ApplyLoggingRedaction(V1TrackOrderResponseWithEmailDomainKey, logSensitiveRequestData: false);

            output.Should().Be(V1TrackOrderResponseWithEmailDomainKey.Replace("\"san-probe@example.com\":", "\"s***@example.com\":"));

            // The masked body still deserializes into the real DTO and keeps the DNS/IP entries.
            var parsed = JsonSerializer.Deserialize<TrackOrderResponse>(output, ClientEquivalentJsonOptions());
            var domainVerification = parsed?.OrderDetails?.DomainVerification;
            domainVerification.Should().NotBeNull();
            domainVerification!.GetDomainEntries().Keys.Should().BeEquivalentTo(new[] { "example.com", "s***@example.com", "192.0.2.10" });
            domainVerification.Status.Should().Be("0");
        }

        [Fact]
        public void ApplyLoggingRedaction_V1TrackOrderDomainVerification_FlagOn_Verbatim()
        {
            CERTInextClient.ApplyLoggingRedaction(V1TrackOrderResponseWithEmailDomainKey, logSensitiveRequestData: true)
                .Should().Be(V1TrackOrderResponseWithEmailDomainKey);
        }

        [Fact]
        public void RedactPersonalData_DomainVerificationPrettyPrinted_MasksEmailKey()
        {
            string input = "{\n  \"domainVerification\" : {\n    \"alice@example.com\" : { \"dcvStatus\" : \"0\" },\n    \"status\" : \"0\"\n  }\n}";

            CERTInextClient.RedactPersonalData(input)
                .Should().Be("{\n  \"domainVerification\" : {\n    \"a***@example.com\" : { \"dcvStatus\" : \"0\" },\n    \"status\" : \"0\"\n  }\n}");
        }

        [Theory]
        [InlineData("{\"additionalDomains\":[\"a.example.com\",\"alice@example.com\",\"bob@ex")]
        [InlineData("{\"additionalDomains\":[")]
        [InlineData("{\"additionalDomains\":[\"alice@example.com\"")]
        [InlineData("{\"domainVerification\":{\"alice@example.com\":{\"dcvStatus\":")]
        [InlineData("{\"additionalDomains\":[\"alice@example.com\",,]} trailing @ garbage")]
        [InlineData("{not json at all @ }")]
        [InlineData("[\"@\"")]
        [InlineData("<html><body>contact admin@example.com</body></html>")]
        [InlineData("additionalDomains=alice@example.com&x=1")]
        [InlineData("   ")]
        public void RedactPersonalData_MalformedOrTruncatedBody_DoesNotThrow(string input)
        {
            System.Func<string> act = () => CERTInextClient.RedactPersonalData(input);
            act.Should().NotThrow();
            System.Func<string> act2 = () => CERTInextClient.ApplyLoggingRedaction(input, logSensitiveRequestData: false);
            act2.Should().NotThrow();
        }

        [Fact]
        public void RedactPersonalData_TruncatedBody_MasksElementsSeenBeforeTheFault()
        {
            // A body cut off mid-array keeps the masks for the complete elements before the cut.
            // The partial last element is not a complete token, so it is left as it was.
            CERTInextClient.RedactPersonalData("{\"additionalDomains\":[\"a.example.com\",\"alice@example.com\",\"bob@ex")
                .Should().Be("{\"additionalDomains\":[\"a.example.com\",\"a***@example.com\",\"bob@ex");
        }

        [Fact]
        public void RedactPersonalData_NonJsonBody_IsReturnedUnchanged()
        {
            string input = "additionalDomains=alice@example.com&x=1";
            CERTInextClient.RedactPersonalData(input).Should().Be(input);
        }
    }
}
