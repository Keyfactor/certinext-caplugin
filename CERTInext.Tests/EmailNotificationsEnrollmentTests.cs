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
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
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
    /// Tests that the V2 order body's <c>emailNotifications</c> field honors the connector's
    /// <c>EmailNotifications</c> config rather than a hardcoded <c>"all"</c>. These tests exercise
    /// <c>EnrollV2Async</c> end-to-end (through <see cref="CERTInextCAPlugin.Enroll"/>) against a
    /// Strict <see cref="ICERTInextClient"/> mock, plus a direct DTO serialization check for
    /// <see cref="V2CreateSslOrderRequest.EmailNotifications"/>, following the pattern established
    /// by <c>V2SubscriptionEnrollmentTests.cs</c>.
    ///
    /// Mapping under test: "1" -&gt; "all", "0" -&gt; "0",
    /// blank/whitespace/unset -&gt; null (omitted; CA defaults to "all"), any other value
    /// (including the literal "all") fails the enrollment before any CA call.
    /// </summary>
    public class EmailNotificationsEnrollmentTests
    {
        private static Mock<ICERTInextClient> NewMock() =>
            new Mock<ICERTInextClient>(MockBehavior.Strict);

        // Default here intentionally matches CERTInextConfig's own property default ("0") — NOT
        // a `?? "0"`-style fallback applied to the parameter, which would silently coerce an
        // explicitly-passed null (a real Theory case below) back to "0" and defeat that test case.
        private static CERTInextCAPlugin BuildV2Plugin(
            ICERTInextClient client,
            string emailNotifications = "0") =>
            new CERTInextCAPlugin(client, new CERTInextConfig
            {
                UseV2Api           = true,
                ApiUrl             = "https://v2.certinext.io",
                OAuthClientId      = "my-client",
                OAuthClientSecret  = "my-secret",
                RequestorName      = "Test User",
                RequestorEmail     = "test@example.com",
                SignerIp           = "1.2.3.4",
                SignerPlace        = "New York",
                PickupRetries      = 0,
                EmailNotifications = emailNotifications
            });

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

        private static async Task<(EnrollmentResult Result, V2CreateSslOrderRequest Captured)> RunEnrollAsync(
            Mock<ICERTInextClient> mock, CERTInextCAPlugin plugin, string orderId = "ord_email_001")
        {
            V2CreateSslOrderRequest captured = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>((_, __, req, ___) => captured = req)
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = orderId, Status = "pending-dcv" });

            var result = await plugin.Enroll(
                csr: GenerateCsrPem("example.com"),
                subject: "CN=example.com",
                san: null,
                productInfo: MakeV2ProductInfo("842", "dv"),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            return (result, captured);
        }

        // ---------------------------------------------------------------------------
        // EnrollV2Async wiring — valid mapped values
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_V2_EmailNotifications_1_MapsToAll()
        {
            var mock = NewMock();
            StubCatalog(mock, "842", "13"); // DV SSL (non-UCC)
            StubHappyOrderPlacement(mock, "ord_email_001");

            var plugin = BuildV2Plugin(mock.Object, emailNotifications: "1");

            var (result, captured) = await RunEnrollAsync(mock, plugin, "ord_email_001");

            result.CARequestID.Should().Be("ord_email_001");
            captured.Should().NotBeNull();
            captured!.EmailNotifications.Should().Be("all",
                "EmailNotifications=\"1\" must map to the CA's full notification set (\"all\")");
        }

        [Fact]
        public async Task Enroll_V2_EmailNotifications_0_StaysZero()
        {
            var mock = NewMock();
            StubCatalog(mock, "842", "13");
            StubHappyOrderPlacement(mock, "ord_email_002");

            var plugin = BuildV2Plugin(mock.Object, emailNotifications: "0");

            var (result, captured) = await RunEnrollAsync(mock, plugin, "ord_email_002");

            result.CARequestID.Should().Be("ord_email_002");
            captured!.EmailNotifications.Should().Be("0",
                "EmailNotifications=\"0\" must be forwarded as the literal \"0\", which " +
                "suppresses order-creation emails on V2, the same as V1");
        }

        [Fact]
        public async Task Enroll_V2_EmailNotifications_1_IsTrimmedBeforeMapping()
        {
            var mock = NewMock();
            StubCatalog(mock, "842", "13");
            StubHappyOrderPlacement(mock, "ord_email_003");

            var plugin = BuildV2Plugin(mock.Object, emailNotifications: " 1 ");

            var (result, captured) = await RunEnrollAsync(mock, plugin, "ord_email_003");

            result.CARequestID.Should().Be("ord_email_003");
            captured!.EmailNotifications.Should().Be("all",
                "surrounding whitespace must be trimmed before comparing against \"1\"/\"0\"");
        }

        // ---------------------------------------------------------------------------
        // EnrollV2Async wiring — blank/unset omits the field entirely
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public async Task Enroll_V2_EmailNotifications_Blank_OmitsField(string configValue)
        {
            var mock = NewMock();
            StubCatalog(mock, "842", "13");
            StubHappyOrderPlacement(mock, "ord_email_004");

            var plugin = BuildV2Plugin(mock.Object, emailNotifications: configValue);

            var (result, captured) = await RunEnrollAsync(mock, plugin, "ord_email_004");

            result.CARequestID.Should().Be("ord_email_004");
            captured!.EmailNotifications.Should().BeNull(
                "a blank/unset EmailNotifications must leave the field null so it is omitted on the " +
                "wire and the CA's own default (\"all\") applies");
        }

        [Fact]
        public void V2CreateSslOrderRequest_Serialization_OmitsEmailNotifications_WhenNull()
        {
            var request = new V2CreateSslOrderRequest
            {
                ProductVariant     = "dv",
                EmailNotifications = null,
                Certificate        = new V2CertificateParams { Domain = "example.com" }
            };

            string json = JsonSerializer.Serialize(request, ClientEquivalentJsonOptions());

            json.Should().NotContain("emailNotifications",
                "the emailNotifications key itself must be absent when unset, not present-but-null, " +
                "under the client's actual serializer options");
        }

        [Fact]
        public void V2CreateSslOrderRequest_Serialization_IncludesEmailNotifications_WhenSet()
        {
            var request = new V2CreateSslOrderRequest
            {
                ProductVariant     = "dv",
                EmailNotifications = "0",
                Certificate        = new V2CertificateParams { Domain = "example.com" }
            };

            string json = JsonSerializer.Serialize(request, ClientEquivalentJsonOptions());

            json.Should().Contain("\"emailNotifications\":\"0\"");
        }

        // Mirrors the client's actual GetJsonOptions() (private) — see
        // V2SubscriptionEnrollmentTests.ClientEquivalentJsonOptions for the same rationale: plain
        // JsonSerializer.Serialize(req) without these options would show "emailNotifications":null
        // instead of omitting the key.
        private static JsonSerializerOptions ClientEquivalentJsonOptions() => new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        // ---------------------------------------------------------------------------
        // EnrollV2Async — invalid EmailNotifications fails fast, before any CA call
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData("all")] // deliberately invalid: the user's mapping only accepts "0"/"1"/blank,
                             // even though "all" is the CA's own wire value for "1" — an admin
                             // must not be able to bypass the mapping by writing the CA's literal.
        [InlineData("yes")]
        [InlineData("2")]
        public async Task Enroll_V2_EmailNotifications_Invalid_FailsEnrollment_NoHttpCallMade(string configValue)
        {
            // Strict mock with NO setups at all: if EnrollV2Async made any client call before
            // failing validation, Moq would throw a MockException for the unstubbed invocation
            // and this test would fail — that, plus the explicit Verify(Times.Never) calls below,
            // together confirm zero HTTP requests are sent for an invalid config value.
            var mock = NewMock();

            var plugin = BuildV2Plugin(mock.Object, emailNotifications: configValue);

            var result = await plugin.Enroll(
                csr: GenerateCsrPem("example.com"),
                subject: "CN=example.com",
                san: null,
                productInfo: MakeV2ProductInfo("842", "dv"),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Status.Should().Be((int)EndEntityStatus.FAILED);
            result.StatusMessage.Should().Contain("EmailNotifications",
                "the failure message must name the offending config field");

            mock.Verify(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()), Times.Never);
            mock.Verify(c => c.PlaceOrderV2Async(
                It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }
}
