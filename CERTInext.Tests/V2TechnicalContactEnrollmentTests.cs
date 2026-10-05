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
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Moq;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Regression tests for issues/0030-v2-technical-contact-not-sent.md: the V2 SSL order body
    /// never carried a <c>technicalPointOfContact</c> block, while V1's equivalent
    /// (<c>TechnicalPointOfContact</c>) has always populated one from the connector's
    /// <c>TechnicalContact*</c> config fields (falling back to the corresponding
    /// <c>Requestor*</c> value when blank). These tests exercise <c>EnrollV2Async</c> end-to-end
    /// (through <see cref="CERTInextCAPlugin.Enroll"/>) against a Strict
    /// <see cref="ICERTInextClient"/> mock, plus direct DTO serialization checks for the new
    /// <see cref="V2CreateSslOrderRequest.TechnicalPointOfContact"/> property and the new
    /// <see cref="CERTInextCAPlugin.ComposeV2Phone"/> ISD-code + mobile-number composition helper.
    /// </summary>
    public class V2TechnicalContactEnrollmentTests
    {
        private static Mock<ICERTInextClient> NewMock() =>
            new Mock<ICERTInextClient>(MockBehavior.Strict);

        private static CERTInextConfig BaseConfig() => new CERTInextConfig
        {
            UseV2Api          = true,
            ApiUrl            = "https://v2.certinext.io",
            OAuthClientId     = "my-client",
            OAuthClientSecret = "my-secret",
            RequestorName     = "Test User",
            RequestorEmail    = "test@example.com",
            RequestorIsdCode  = "1",
            RequestorMobileNumber = "5550000000",
            SignerIp          = "1.2.3.4",
            SignerPlace       = "New York",
            PickupRetries     = 0
        };

        private static CERTInextCAPlugin BuildV2Plugin(ICERTInextClient client, CERTInextConfig config) =>
            new CERTInextCAPlugin(client, config);

        private static EnrollmentProductInfo MakeV2ProductInfo(string productCode, string productVariant) =>
            new EnrollmentProductInfo
            {
                ProductID = "DV SSL",
                ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ProductCode"]    = productCode,
                    ["ProductFamily"]  = "ssl",
                    ["ProductVariant"] = productVariant,
                    ["DomainName"]     = "example.com"
                }
            };

        private static void StubCatalog(Mock<ICERTInextClient> mock, string productCode, string productTypeId) =>
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = productCode, ProductTypeId = productTypeId, Active = true }
                });

        private static void StubHappyOrderPlacement(Mock<ICERTInextClient> mock, string orderId)
        {
            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), orderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), orderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = orderId, Status = "pending-dcv" });
        }

        private static string GenerateCsrPem(string cn)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            AsymmetricCipherKeyPair kp = keyGen.GenerateKeyPair();

            var csr = new Pkcs10CertificationRequest(
                "SHA256withRSA", new X509Name($"CN={cn}"), kp.Public, null, kp.Private);

            return "-----BEGIN CERTIFICATE REQUEST-----\n"
                 + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                 + "\n-----END CERTIFICATE REQUEST-----";
        }

        private static async Task<V2CreateSslOrderRequest> RunEnrollAndCaptureOrderAsync(
            CERTInextConfig config, string orderId = "ord_tpc_001")
        {
            var mock = NewMock();
            StubCatalog(mock, "842", "13"); // DV SSL (non-UCC)
            StubHappyOrderPlacement(mock, orderId);

            V2CreateSslOrderRequest captured = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>((_, __, req, ___) => captured = req)
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = orderId, Status = "pending-dcv" });

            var plugin = BuildV2Plugin(mock.Object, config);

            var result = await plugin.Enroll(
                csr: GenerateCsrPem("example.com"),
                subject: "CN=example.com",
                san: null,
                productInfo: MakeV2ProductInfo("842", "dv"),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.CARequestID.Should().Be(orderId);
            captured.Should().NotBeNull();
            return captured;
        }

        // ---------------------------------------------------------------------------
        // EnrollV2Async wiring — technicalPointOfContact populated on the order body
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_V2_TechnicalContactConfigured_PopulatesTechnicalPointOfContactOnOrderBody()
        {
            var config = BaseConfig();
            config.TechnicalContactName          = "TPoC Name";
            config.TechnicalContactEmail         = "tpoc@example.com";
            config.TechnicalContactIsdCode       = "44";
            config.TechnicalContactMobileNumber  = "7911123456";

            var captured = await RunEnrollAndCaptureOrderAsync(config);

            captured.TechnicalPointOfContact.Should().NotBeNull(
                "the technicalPointOfContact block must always be populated, even though every " +
                "subfield is spec-Optional");
            captured.TechnicalPointOfContact.Name.Should().Be("TPoC Name");
            captured.TechnicalPointOfContact.Email.Should().Be("tpoc@example.com");
            captured.TechnicalPointOfContact.Phone.Should().Be("+447911123456",
                "the configured TechnicalContactIsdCode and TechnicalContactMobileNumber must be " +
                "combined into a single E.164-style phone value for the V2 shape");
            captured.TechnicalPointOfContact.Designation.Should().Be("Technical Contact");
        }

        [Fact]
        public async Task Enroll_V2_TechnicalContactBlank_FallsBackToRequestorValues()
        {
            var config = BaseConfig();
            // TechnicalContact* fields left at their default (blank) values.

            var captured = await RunEnrollAndCaptureOrderAsync(config, orderId: "ord_tpc_002");

            captured.TechnicalPointOfContact.Should().NotBeNull(
                "V1's fallback-to-Requestor* semantics mean the block is populated, never omitted, " +
                "even when no TechnicalContact* field is configured");
            captured.TechnicalPointOfContact.Name.Should().Be(config.RequestorName,
                "a blank TechnicalContactName must fall back to RequestorName, mirroring V1");
            captured.TechnicalPointOfContact.Email.Should().Be(config.RequestorEmail,
                "a blank TechnicalContactEmail must fall back to RequestorEmail, mirroring V1");
            captured.TechnicalPointOfContact.Phone.Should().Be("+15550000000",
                "a blank TechnicalContactIsdCode/TechnicalContactMobileNumber must fall back to " +
                "RequestorIsdCode/RequestorMobileNumber, mirroring V1, composed into one phone value");
            captured.TechnicalPointOfContact.Designation.Should().Be("Technical Contact");
        }

        [Fact]
        public async Task Enroll_V2_TechnicalContactPartiallyConfigured_FallsBackFieldByField()
        {
            var config = BaseConfig();
            // Only name is overridden; email/isd/mobile stay blank and must each fall back
            // independently to their own Requestor* counterpart (matching V1's per-field, not
            // all-or-nothing, fallback semantics).
            config.TechnicalContactName = "Override Name Only";

            var captured = await RunEnrollAndCaptureOrderAsync(config, orderId: "ord_tpc_003");

            captured.TechnicalPointOfContact.Name.Should().Be("Override Name Only");
            captured.TechnicalPointOfContact.Email.Should().Be(config.RequestorEmail);
            captured.TechnicalPointOfContact.Phone.Should().Be("+15550000000");
        }

        // ---------------------------------------------------------------------------
        // Requestor.Phone — ISD-code + mobile-number composition (issues/0027 item 5b).
        // Before the fix, Requestor.Phone sent the raw RequestorMobileNumber only, with
        // RequestorIsdCode never combined in — unlike TechnicalPointOfContact.Phone above,
        // which already used ComposeV2Phone. Requestor.Phone must compose the same way.
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_V2_RequestorPhone_ComposesIsdAndMobile()
        {
            var config = BaseConfig();
            // BaseConfig: RequestorIsdCode="1", RequestorMobileNumber="5550000000".

            var captured = await RunEnrollAndCaptureOrderAsync(config, orderId: "ord_req_phone_001");

            captured.Requestor.Should().NotBeNull();
            captured.Requestor.Phone.Should().Be("+15550000000",
                "Requestor.Phone must combine RequestorIsdCode and RequestorMobileNumber the same " +
                "way TechnicalPointOfContact.Phone already does, via ComposeV2Phone");
        }

        [Fact]
        public async Task Enroll_V2_RequestorPhone_UsesConfiguredIsdCode_NotDefault()
        {
            var config = BaseConfig();
            config.RequestorIsdCode      = "44";
            config.RequestorMobileNumber = "7911123456";

            var captured = await RunEnrollAndCaptureOrderAsync(config, orderId: "ord_req_phone_002");

            captured.Requestor.Phone.Should().Be("+447911123456",
                "a non-default RequestorIsdCode must be reflected in Requestor.Phone, not just " +
                "the TechnicalPointOfContact fallback path");
        }

        [Fact]
        public async Task Enroll_V2_RequestorPhone_BlankIsdCode_FallsBackToDefault()
        {
            var config = BaseConfig();
            config.RequestorIsdCode      = "";
            config.RequestorMobileNumber = "5550000000";

            var captured = await RunEnrollAndCaptureOrderAsync(config, orderId: "ord_req_phone_003");

            captured.Requestor.Phone.Should().Be("+15550000000",
                "a blank RequestorIsdCode must fall back to the same default ('1') used " +
                "elsewhere in EnrollV2Async, not an unprefixed raw mobile number");
        }

        // ---------------------------------------------------------------------------
        // DTO serialization — technicalPointOfContact key/shape on the wire
        // ---------------------------------------------------------------------------

        [Fact]
        public void V2CreateSslOrderRequest_Serialization_IncludesTechnicalPointOfContact_WhenSet()
        {
            var req = new V2CreateSslOrderRequest
            {
                ProductVariant = "dv",
                Requestor = new V2Requestor { Name = "Jane Doe", Email = "jane@example.com" },
                Certificate = new V2CertificateParams { Domain = "example.com" },
                TechnicalPointOfContact = new V2TechnicalPointOfContact
                {
                    Name = "TPoC Name",
                    Email = "tpoc@example.com",
                    Phone = "+447911123456",
                    Designation = "Technical Contact"
                }
            };

            string json = JsonSerializer.Serialize(req);

            // System.Text.Json escapes '+' as + by default, so the phone value is checked
            // by parsing the JSON rather than substring-matching the raw serialized text (which
            // would never contain a literal '+').
            using var doc = JsonDocument.Parse(json);
            var tpc = doc.RootElement.GetProperty("technicalPointOfContact");
            tpc.GetProperty("name").GetString().Should().Be("TPoC Name");
            tpc.GetProperty("email").GetString().Should().Be("tpoc@example.com");
            tpc.GetProperty("phone").GetString().Should().Be("+447911123456");
            tpc.GetProperty("designation").GetString().Should().Be("Technical Contact");
        }

        // ---------------------------------------------------------------------------
        // ComposeV2Phone — ISD-code + mobile-number composition helper
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData("1", "5550000000", "+15550000000")]
        [InlineData("44", "7911123456", "+447911123456")]
        [InlineData("+1", "5550000000", "+15550000000")]
        [InlineData("", "5550000000", "5550000000")]
        [InlineData(null, "5550000000", "5550000000")]
        [InlineData("1", "", "")]
        [InlineData("1", null, "")]
        [InlineData(null, null, "")]
        public void ComposeV2Phone_ComposesExpectedValue(string isdCode, string mobileNumber, string expected)
        {
            CERTInextCAPlugin.ComposeV2Phone(isdCode, mobileNumber).Should().Be(expected);
        }
    }
}
