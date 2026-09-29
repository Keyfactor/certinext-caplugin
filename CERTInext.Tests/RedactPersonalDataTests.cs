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
    /// Issue 0040: requestor personal data (name, email, phone, org contact fields) must not
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
    }
}
