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
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Issue 0040: requestor personal data (name, email, phone, org contact fields) must not
    /// appear in gateway logs unless the connector's <c>LogSensitiveRequestData</c> setting is
    /// explicitly turned on, and credentials (the <c>meta.authKey</c> digest) must never appear.
    /// These tests pin <see cref="CERTInextClient.RedactPersonalData"/> and
    /// <see cref="CERTInextClient.ApplyLoggingRedaction"/> against realistic V1 order payload JSON,
    /// produced by serializing the real request/response models rather than hand-written strings
    /// — so a future rename of a JSON property name (which would silently stop the redactor from
    /// matching it) fails these tests immediately. All data is synthetic.
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

        private const string SyntheticAuthKey = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

        // ---------------------------------------------------------------------------
        // V1 GenerateOrderSSL request — requestorInformation / technicalPointOfContact /
        // agreementDetails all carry personal data; certificateInformation/orderDetails don't.
        // ---------------------------------------------------------------------------

        private static string BuildV1OrderRequestJson()
        {
            var request = new GenerateOrderSslRequest
            {
                Meta = new RequestMeta
                {
                    Ver = "1.0", Ts = "2026-05-22T10:00:00+00:00", Txn = "1234567890",
                    AccountNumber = "9988776655", AuthKey = SyntheticAuthKey
                },
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
                        PocFirstName = "Terry",
                        PocLastName = "Techcontact",
                        PocEmail = "tech.contact@example.com",
                        PocIsdCode = "44",
                        PocMobileNumber = "5559876543"
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
            output.Should().NotContain("Terry");
            output.Should().NotContain("Techcontact");
            output.Should().NotContain("tech.contact@example.com");
            output.Should().NotContain("5559876543");
            output.Should().NotContain("\"pocIsdCode\":\"44\"");
        }

        [Fact]
        public void RedactPersonalData_V1OrderRequest_MasksEmailsKeepingDomain()
        {
            string output = CERTInextClient.RedactPersonalData(BuildV1OrderRequestJson());

            output.Should().Contain("\"requestorEmail\":\"j***@example.com\"");
            output.Should().Contain("\"pocEmail\":\"t***@example.com\"");
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
            output.Should().Contain("\"pocFirstName\":\"***REDACTED***\"");
            output.Should().Contain("\"pocLastName\":\"***REDACTED***\"");
            output.Should().Contain("\"pocIsdCode\":\"***REDACTED***\"");
            output.Should().Contain("\"pocMobileNumber\":\"***REDACTED***\"");
        }

        // ---------------------------------------------------------------------------
        // The V1 order body's meta.authKey is a replayable credential — always redacted by
        // ApplyLoggingRedaction, whatever LogSensitiveRequestData says.
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void ApplyLoggingRedaction_V1OrderRequest_AuthKeyAlwaysRedacted(bool logSensitiveRequestData)
        {
            string input = BuildV1OrderRequestJson();
            input.Should().Contain(SyntheticAuthKey, "precondition: the serialized body carries meta.authKey");

            string output = CERTInextClient.ApplyLoggingRedaction(input, logSensitiveRequestData);

            output.Should().NotContain(SyntheticAuthKey);
            output.Should().Contain("\"authKey\":\"***REDACTED***\"");
        }

        [Fact]
        public void ApplyLoggingRedaction_V1OrderRequest_FlagOn_KeepsPersonalDataInFull()
        {
            string output = CERTInextClient.ApplyLoggingRedaction(BuildV1OrderRequestJson(), logSensitiveRequestData: true);

            output.Should().Contain("Jane Doe");
            output.Should().Contain("jane.doe@example.com");
            output.Should().Contain("5551234567");
            output.Should().Contain("tech.contact@example.com");
            output.Should().Contain("\"pocFirstName\":\"Terry\"");
            output.Should().Contain("\"pocLastName\":\"Techcontact\"");
            output.Should().Contain("\"pocIsdCode\":\"44\"");
            output.Should().Contain("\"pocMobileNumber\":\"5559876543\"");
            output.Should().Contain("\"authKey\":\"***REDACTED***\"", "credentials stay redacted with the flag on");
            output.Should().NotContain(SyntheticAuthKey);
        }

        [Fact]
        public void ApplyLoggingRedaction_V1OrderRequest_FlagOff_RedactsEveryPocField()
        {
            string output = CERTInextClient.ApplyLoggingRedaction(BuildV1OrderRequestJson(), logSensitiveRequestData: false);

            output.Should().Contain("\"pocFirstName\":\"***REDACTED***\"");
            output.Should().Contain("\"pocLastName\":\"***REDACTED***\"");
            output.Should().Contain("\"pocEmail\":\"t***@example.com\"");
            output.Should().Contain("\"pocIsdCode\":\"***REDACTED***\"");
            output.Should().Contain("\"pocMobileNumber\":\"***REDACTED***\"");
            output.Should().NotContain("tech.contact@example.com");
            output.Should().NotContain(SyntheticAuthKey);
        }

        [Fact]
        public void RedactPersonalData_PrettyPrintedNestedPocBlock_IsRedacted()
        {
            string input = "{\n  \"technicalPointOfContact\" : {\n    \"pocFirstName\" : \"Terry\",\n    \"pocEmail\"   :   \"tech.contact@example.com\",\n    \"pocMobileNumber\":\"5559876543\"\n  }\n}";

            string output = CERTInextClient.RedactPersonalData(input);

            output.Should().NotContain("Terry").And.NotContain("tech.contact@example.com").And.NotContain("5559876543");
            output.Should().Contain("t***@example.com");
        }

        [Fact]
        public void RedactPersonalData_LegacyTpcKeysInResponseBody_AreRedacted_DefenceInDepth()
        {
            // The V1 request no longer emits tpc* (renamed to poc*), but a CA error body may echo
            // the old names, so they stay on the redaction lists.
            string input = "{\"tpcName\":\"Tech Contact\",\"tpcEmail\":\"tech.contact@example.com\",\"tpcIsdCode\":\"1\",\"tpcMobileNumber\":\"5559876543\"}";

            string output = CERTInextClient.RedactPersonalData(input);

            output.Should().Be("{\"tpcName\":\"***REDACTED***\",\"tpcEmail\":\"t***@example.com\",\"tpcIsdCode\":\"***REDACTED***\",\"tpcMobileNumber\":\"***REDACTED***\"}");
        }

        // ---------------------------------------------------------------------------
        // Whitespace tolerance — a pretty-printed body must redact identically to a compact one.
        // ---------------------------------------------------------------------------

        [Fact]
        public void RedactPersonalData_TolerantOfWhitespaceAroundKeyValueSeparator()
        {
            string input = "{\n  \"requestorInformation\" : {\n    \"requestorName\"   :   \"Jane Doe\",\n    \"requestorEmail\":\"jane.doe@example.com\"\n  }\n}";

            string output = CERTInextClient.RedactPersonalData(input);

            output.Should().NotContain("Jane Doe");
            output.Should().Contain("j***@example.com");
        }

        [Fact]
        public void RedactPersonalData_BareContactKeysInResponseBody_AreRedacted_DefenceInDepth()
        {
            // No V1 request uses bare name/email/phone/designation keys, but CA error/response
            // bodies are not contractually fixed — these are redacted as defence in depth.
            string input = "{\"contact\":{\"name\":\"Jane Doe\",\"email\":\"jane.doe@example.com\",\"phone\":\"+15551234567\",\"designation\":\"IT Administrator\"}}";

            string output = CERTInextClient.RedactPersonalData(input);

            output.Should().Be("{\"contact\":{\"name\":\"***REDACTED***\",\"email\":\"j***@example.com\",\"phone\":\"***REDACTED***\",\"designation\":\"***REDACTED***\"}}");
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
        // Email SANs inside SAN arrays (V1 additionalDomains carries every SAN type) and V1
        // TrackOrder domainVerification keys, which the key/value regex can't reach.
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

        // JSON string values can contain escaped quotes and backslashes. A scrubber that stops at the
        // first '"' it sees leaks everything after the escape into the log. Values below are synthetic.
        [Theory]
        [InlineData(
            "{\"requestorName\":\"Jane \\\"JD\\\" Doe\"}",
            "{\"requestorName\":\"***REDACTED***\"}")]
        [InlineData(
            "{\"requestorName\":\"Jane \\\"JD\\\" Doe\",\"requestorDesignation\":\"Eng\"}",
            "{\"requestorName\":\"***REDACTED***\",\"requestorDesignation\":\"***REDACTED***\"}")]
        [InlineData(
            "{\"signerPlace\":\"C:\\\\Users\\\\jdoe\",\"other\":\"keep\"}",
            "{\"signerPlace\":\"***REDACTED***\",\"other\":\"keep\"}")]
        [InlineData(
            "{\"pocLastName\":\"Doe\\\\\",\"other\":\"keep\"}",
            "{\"pocLastName\":\"***REDACTED***\",\"other\":\"keep\"}")]
        [InlineData(
            "{\"pocFirstName\":\"\\\"\",\"other\":\"keep\"}",
            "{\"pocFirstName\":\"***REDACTED***\",\"other\":\"keep\"}")]
        public void RedactPersonalData_RedactsOtherFieldValuesContainingEscapes(string input, string expected)
        {
            CERTInextClient.RedactPersonalData(input).Should().Be(expected);
        }

        [Fact]
        public void RedactPersonalData_EmailValueContainingEscapedQuote_IsMaskedWithoutLeakingTail()
        {
            string actual = CERTInextClient.RedactPersonalData(
                "{\"requestorEmail\":\"jane\\\"TAILSECRET\\\"@example.com\",\"other\":\"keep\"}");
            actual.Should().NotContain("TAILSECRET");
            actual.Should().Contain("\"other\":\"keep\"");
        }

        [Fact]
        public void RedactPersonalData_EmptyValues_AreLeftUntouchedByEscapeAwareMatching()
        {
            string input = "{\"requestorName\":\"\",\"requestorEmail\":\"\"}";
            CERTInextClient.RedactPersonalData(input).Should().Be(input);
        }

        [Fact]
        public void ApplyLoggingRedaction_EscapedQuotesInCredentialAndPii_NeitherLeaks()
        {
            string input = "{\"authKey\":\"ab\\\"AUTHTAIL\",\"requestorName\":\"Jane \\\"JD\\\" PIITAIL\"}";

            CERTInextClient.ApplyLoggingRedaction(input, logSensitiveRequestData: false)
                .Should().Be("{\"authKey\":\"***REDACTED***\",\"requestorName\":\"***REDACTED***\"}");

            // Credentials are scrubbed even when PII logging is opted in; the PII is left as sent.
            string credsOnly = CERTInextClient.ApplyLoggingRedaction(input, logSensitiveRequestData: true);
            credsOnly.Should().NotContain("AUTHTAIL");
            credsOnly.Should().Contain("PIITAIL");
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
