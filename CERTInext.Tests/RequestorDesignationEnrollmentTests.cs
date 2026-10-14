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
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
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
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Tests that the V2 order body's <c>requestor.designation</c> field is sourced from a
    /// connector config field rather than hardcoded (the V2 spec's own example value for this
    /// Optional free-text field is <c>"IT Administrator"</c>). V1 does not send
    /// <c>requestorDesignation</c> unless configured — the DTO carries the property.
    ///
    /// Covers both paths:
    ///   - V2 (<see cref="CERTInextCAPlugin.Enroll"/> → <c>EnrollV2Async</c>): exercised end-to-end
    ///     against a Strict <see cref="ICERTInextClient"/> mock, mirroring
    ///     <c>V2SubscriptionEnrollmentTests</c> / <c>V2TechnicalContactEnrollmentTests</c>.
    ///   - V1 (<see cref="CERTInextClient.EnrollCertificateAsync"/> /
    ///     <see cref="CERTInextClient.RenewCertificateAsync"/>): exercised against a WireMock HTTP
    ///     stub, mirroring <c>CERTInextClientRequestShapeTests</c>, since the V1 wire shape is built
    ///     by the concrete client rather than behind <see cref="ICERTInextClient"/>.
    /// </summary>
    public class RequestorDesignationEnrollmentTests : IDisposable
    {
        // ---------------------------------------------------------------------------
        // V2 — EnrollV2Async wiring: RequestorDesignation config -> Requestor.Designation
        // ---------------------------------------------------------------------------

        private static Mock<ICERTInextClient> NewMock() =>
            new Mock<ICERTInextClient>(MockBehavior.Strict);

        private static CERTInextConfig BaseV2Config() => new CERTInextConfig
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

        private static async Task<V2CreateSslOrderRequest> RunV2EnrollAndCaptureOrderAsync(
            CERTInextConfig config, string orderId = "ord_desig_001")
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

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public async Task Enroll_V2_RequestorDesignationBlank_SetsDesignationNull(string configValue)
        {
            var config = BaseV2Config();
            config.RequestorDesignation = configValue;

            var captured = await RunV2EnrollAndCaptureOrderAsync(config, orderId: "ord_desig_002");

            captured.Requestor.Should().NotBeNull();
            captured.Requestor.Designation.Should().BeNull(
                "a blank/unset RequestorDesignation must leave Requestor.Designation null so the " +
                "key is omitted from the wire JSON, instead of sending any default designation value");
        }

        [Fact]
        public async Task Enroll_V2_RequestorDesignationSet_SendsTrimmedValue()
        {
            var config = BaseV2Config();
            config.RequestorDesignation = "  PKI Manager  ";

            var captured = await RunV2EnrollAndCaptureOrderAsync(config, orderId: "ord_desig_003");

            captured.Requestor.Designation.Should().Be("PKI Manager",
                "a configured RequestorDesignation must be forwarded trimmed of surrounding whitespace");
        }

        // ---------------------------------------------------------------------------
        // V2 — DTO serialization: requestor.designation key present/absent on the wire
        //
        // V2Requestor.Designation carries no per-property [JsonIgnore(WhenWritingNull)] of its
        // own; it relies solely on the client's global serializer options
        // (CERTInextClient.GetJsonOptions, DefaultIgnoreCondition = WhenWritingNull) to omit it
        // when null. GetJsonOptions() is private, so this test builds an equivalent
        // JsonSerializerOptions inline to verify that global-option omission actually applies to
        // this property, rather than relying on plain JsonSerializer.Serialize (whose default
        // options do NOT ignore nulls and would show "designation":null instead of omitting it).
        // ---------------------------------------------------------------------------

        private static JsonSerializerOptions ClientEquivalentJsonOptions() => new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        [Fact]
        public void V2Requestor_Serialization_OmitsDesignation_WhenNull()
        {
            var requestor = new V2Requestor
            {
                Name        = "Jane Doe",
                Email       = "jane@example.com",
                Phone       = "+15550000000",
                Designation = null
            };

            string json = JsonSerializer.Serialize(requestor, ClientEquivalentJsonOptions());

            json.Should().NotContain("designation",
                "the designation key itself must be absent when unset, not present-but-null, " +
                "under the client's actual serializer options");
        }

        [Fact]
        public void V2Requestor_Serialization_IncludesDesignation_WhenSet()
        {
            var requestor = new V2Requestor
            {
                Name        = "Jane Doe",
                Email       = "jane@example.com",
                Phone       = "+15550000000",
                Designation = "PKI Manager"
            };

            string json = JsonSerializer.Serialize(requestor, ClientEquivalentJsonOptions());

            json.Should().Contain("\"designation\":\"PKI Manager\"");
        }

        // ---------------------------------------------------------------------------
        // V1 — BuildOrderRequestFromLegacyEnrollRequest / RenewCertificateAsync wiring:
        // RequestorDesignation config -> requestorInformation.requestorDesignation
        //
        // Uses a WireMock HTTP stub (mirroring CERTInextClientRequestShapeTests) because the V1
        // wire shape is built inside the concrete CERTInextClient, not behind ICERTInextClient.
        // RequestorInformation.RequestorDesignation already carries its own
        // [JsonIgnore(Condition = WhenWritingNull)] (API/CertificateRequest.cs), so a blank config
        // value is expected to omit the key without needing any client-level options change.
        // ---------------------------------------------------------------------------

        private readonly WireMockServer _server = WireMockServer.Start();

        public void Dispose() => _server.Stop();

        private CERTInextClient BuildV1Client(CERTInextConfig config)
        {
            config.ApiUrl = _server.Urls[0];
            return new CERTInextClient(config);
        }

        private static CERTInextConfig MinimalV1Config() => new CERTInextConfig
        {
            AuthMode = "AccessKey",
            ApiKey = "test-key",
            AccountNumber = "12345",
            RequestorName = "Default Requestor",
            RequestorEmail = "default@example.com",
            RequestorIsdCode = "1",
            RequestorMobileNumber = "5550000000",
            SignerPlace = "Austin",
            SignerIp = "203.0.113.10",
            PageSize = 100
        };

        private void StubHappyEnroll()
        {
            _server.Given(Request.Create().WithPath("/GenerateOrderSSL").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.GenerateOrderSuccessJson(MockCertificateData.OrderNumber1)));

            _server.Given(Request.Create().WithPath("/TrackOrder").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.TrackOrderIssuedJson(MockCertificateData.OrderNumber1)));

            _server.Given(Request.Create().WithPath("/GetCertificate").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.GetCertificateSuccessJson()));
        }

        private JsonElement CapturedGenerateOrderSslBody()
        {
            var generateOrderRequests = _server.LogEntries
                .Where(e => e.RequestMessage.Path == "/GenerateOrderSSL")
                .ToList();
            generateOrderRequests.Should().HaveCount(1,
                "exactly one GenerateOrderSSL POST should have been emitted");
            string body = generateOrderRequests[0].RequestMessage.Body;
            body.Should().NotBeNullOrEmpty();
            return JsonDocument.Parse(body!).RootElement.GetProperty("orderDetails");
        }

        private static EnrollCertificateRequest BasicEnrollRequest() => new EnrollCertificateRequest
        {
            ProfileId = "842",
            Csr = MockCertificateData.FakeCsrPem,
            Subject = "CN=test.example.com",
            Comment = "Unit test"
        };

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public async Task EnrollCertificateAsync_RequestorDesignationBlank_OmitsFieldFromRequestorInformation(string configValue)
        {
            StubHappyEnroll();
            var cfg = MinimalV1Config();
            cfg.RequestorDesignation = configValue;

            await BuildV1Client(cfg).EnrollCertificateAsync(BasicEnrollRequest());

            var requestorInfo = CapturedGenerateOrderSslBody().GetProperty("requestorInformation");
            requestorInfo.TryGetProperty("requestorDesignation", out _).Should().BeFalse(
                "a blank/unset RequestorDesignation must omit requestorDesignation from the wire " +
                "JSON entirely (V1 does not send this field unless configured)");
        }

        [Fact]
        public async Task EnrollCertificateAsync_RequestorDesignationSet_SendsTrimmedValue()
        {
            StubHappyEnroll();
            var cfg = MinimalV1Config();
            cfg.RequestorDesignation = "  IT Administrator  ";

            await BuildV1Client(cfg).EnrollCertificateAsync(BasicEnrollRequest());

            var requestorInfo = CapturedGenerateOrderSslBody().GetProperty("requestorInformation");
            requestorInfo.GetProperty("requestorDesignation").GetString().Should().Be("IT Administrator",
                "a configured RequestorDesignation must be forwarded trimmed of surrounding whitespace");
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public async Task RenewCertificateAsync_RequestorDesignationBlank_OmitsFieldFromRequestorInformation(string configValue)
        {
            StubHappyEnroll();
            var cfg = MinimalV1Config();
            cfg.RequestorDesignation = configValue;

            var renewReq = new RenewCertificateRequest
            {
                Csr = MockCertificateData.FakeCsrPem,
                ProfileId = "842",
                ValidityDays = 365,
                Comment = "Renewal test"
            };

            await BuildV1Client(cfg).RenewCertificateAsync(MockCertificateData.OrderNumber1, renewReq);

            var requestorInfo = CapturedGenerateOrderSslBody().GetProperty("requestorInformation");
            requestorInfo.TryGetProperty("requestorDesignation", out _).Should().BeFalse(
                "a blank/unset RequestorDesignation must omit requestorDesignation from renewal " +
                "orders too, mirroring the new-enrollment path");
        }

        [Fact]
        public async Task RenewCertificateAsync_RequestorDesignationSet_SendsTrimmedValue()
        {
            StubHappyEnroll();
            var cfg = MinimalV1Config();
            cfg.RequestorDesignation = "  PKI Manager  ";

            var renewReq = new RenewCertificateRequest
            {
                Csr = MockCertificateData.FakeCsrPem,
                ProfileId = "842",
                ValidityDays = 365,
                Comment = "Renewal test"
            };

            await BuildV1Client(cfg).RenewCertificateAsync(MockCertificateData.OrderNumber1, renewReq);

            var requestorInfo = CapturedGenerateOrderSslBody().GetProperty("requestorInformation");
            requestorInfo.GetProperty("requestorDesignation").GetString().Should().Be("PKI Manager",
                "a configured RequestorDesignation must be forwarded trimmed of surrounding whitespace " +
                "on renewal orders too");
        }
    }
}
