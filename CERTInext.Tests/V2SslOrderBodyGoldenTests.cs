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
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Golden-body guard: branching <c>EnrollV2Async</c> on product family must not
    /// change a single byte of the SSL/TLS create-order body. Each test drives a full V2 SSL
    /// enrollment against a Strict mock, captures the <see cref="V2CreateSslOrderRequest"/> handed
    /// to the client, serializes it with the client's own serializer options, and compares the
    /// result to a golden JSON string.
    /// </summary>
    public class V2SslOrderBodyGoldenTests
    {
        // Mirrors CERTInextClient.GetJsonOptions() (private) — the options PlaceOrderV2Async
        // uses to produce the actual wire body.
        private static JsonSerializerOptions ClientEquivalentJsonOptions() => new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        private static async Task<(string Json, string FamilySlug, string ProductCode)> CaptureSslBodyAsync(
            CERTInextConfig config,
            EnrollmentProductInfo productInfo,
            string catalogCode,
            string catalogTypeId,
            Dictionary<string, string[]> san,
            string subject)
        {
            const string orderId = "ord_golden_001";
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = catalogCode, ProductTypeId = catalogTypeId, Active = true }
                });

            V2CreateSslOrderRequest captured = null;
            string capturedSlug = null;
            string capturedCode = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>((slug, code, req, _) =>
                {
                    capturedSlug = slug;
                    capturedCode = code;
                    captured = req;
                })
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = orderId, Status = "pending-dcv" });
            mock.Setup(c => c.SubmitCsrV2Async(It.IsAny<string>(), orderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), orderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = orderId, Status = "pending-dcv" });

            var plugin = new CERTInextCAPlugin(mock.Object, config);
            await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: subject,
                san: san,
                productInfo: productInfo,
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            captured.Should().NotBeNull("the SSL enrollment must reach PlaceOrderV2Async");
            return (JsonSerializer.Serialize(captured, ClientEquivalentJsonOptions()), capturedSlug, capturedCode);
        }

        [Fact]
        public async Task SslOvUccOrder_AllOptionalConfigSet_WireBodyMatchesGolden()
        {
            var config = new CERTInextConfig
            {
                UseV2Api                      = true,
                ApiUrl                        = "https://v2.certinext.io",
                OAuthClientId                 = "my-client",
                OAuthClientSecret             = "my-secret",
                RequestorName                 = "Test User",
                RequestorEmail                = "test@example.com",
                RequestorIsdCode              = "1",
                RequestorMobileNumber         = "5551234567",
                RequestorDesignation          = "PKI Admin",
                SignerIp                      = "1.2.3.4",
                SignerPlace                   = "New York",
                OrganizationNumber            = "ORG-001",
                GroupNumber                   = "GRP-9",
                EmailNotifications            = "1",
                SubscriptionAutoRenew         = "1",
                SubscriptionRenewCriteriaDays = "15",
                AutoSecureWww                 = "1",
                TechnicalContactName          = "Tech Person",
                TechnicalContactEmail         = "tech@example.com",
                TechnicalContactIsdCode       = "44",
                TechnicalContactMobileNumber  = "7700900000",
                PickupRetries                 = 0
            };
            var productInfo = new EnrollmentProductInfo
            {
                ProductID = Constants.Products.OvSslUcc,
                ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ProductCode"]    = "848",
                    ["ProductFamily"]  = "ssl",
                    ["ProductVariant"] = "ov",
                    ["DomainName"]     = "example.com",
                    ["ValidityYears"]  = "2"
                }
            };

            var (json, slug, code) = await CaptureSslBodyAsync(
                config, productInfo, "848", "18",
                new Dictionary<string, string[]> { ["dnsname"] = new[] { "example.com", "san1.example.com", "san2.example.com" } },
                "CN=example.com");

            slug.Should().Be(Constants.ApiV2.FamilySsl);
            code.Should().Be("848");
            json.Should().Be(
                "{\"productVariant\":\"ov\",\"emailNotifications\":\"all\"," +
                "\"requestor\":{\"name\":\"Test User\",\"email\":\"test@example.com\",\"phone\":\"\\u002B15551234567\",\"designation\":\"PKI Admin\"}," +
                "\"organization\":{\"organizationNumber\":\"ORG-001\",\"preVetted\":true}," +
                "\"certificate\":{\"domain\":\"example.com\",\"autoSecureWww\":true,\"additionalDomains\":[\"san1.example.com\",\"san2.example.com\"]}," +
                "\"subscription\":{\"validityYears\":2,\"autoRenew\":true,\"renewBeforeDays\":15}," +
                "\"agreement\":{\"signerName\":\"Test User\",\"signerIp\":\"1.2.3.4\",\"signerPlace\":\"New York\",\"accepted\":true}," +
                "\"technicalPointOfContact\":{\"name\":\"Tech Person\",\"email\":\"tech@example.com\",\"phone\":\"\\u002B447700900000\",\"designation\":\"Technical Contact\"}," +
                "\"remarks\":\"Issued via Keyfactor Command AnyCA REST Gateway.\",\"groupNumber\":\"GRP-9\"}");
        }

        [Fact]
        public async Task SslDvOrder_DefaultConfig_WireBodyMatchesGolden()
        {
            var config = new CERTInextConfig
            {
                UseV2Api          = true,
                ApiUrl            = "https://v2.certinext.io",
                OAuthClientId     = "my-client",
                OAuthClientSecret = "my-secret",
                RequestorName     = "Test User",
                RequestorEmail    = "test@example.com",
                // SignerPlace is required for V2 SSL orders (spec: agreement.signerPlace
                // "Conditional - required if `agreement` sent"), so the "default config" fixture sets it
                // and the expected agreement block below carries signerPlace.
                SignerPlace       = "Austin",
                PickupRetries     = 0
            };
            // No ProductFamily / ProductVariant / DomainName: exercises the ssl + dv defaults and
            // the CN-derived domain.
            var productInfo = new EnrollmentProductInfo
            {
                ProductID = Constants.Products.DvSsl,
                ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ProductCode"] = "842"
                }
            };

            var (json, slug, code) = await CaptureSslBodyAsync(
                config, productInfo, "842", "13",
                new Dictionary<string, string[]> { ["dnsname"] = new[] { "example.com" } },
                "CN=example.com");

            slug.Should().Be(Constants.ApiV2.FamilySsl);
            code.Should().Be("842");
            json.Should().Be(
                "{\"productVariant\":\"dv\",\"emailNotifications\":\"0\"," +
                "\"requestor\":{\"name\":\"Test User\",\"email\":\"test@example.com\",\"phone\":\"\"}," +
                "\"certificate\":{\"domain\":\"example.com\",\"autoSecureWww\":false}," +
                "\"subscription\":{\"validityYears\":1,\"autoRenew\":false,\"renewBeforeDays\":30}," +
                "\"agreement\":{\"signerName\":\"Test User\",\"signerPlace\":\"Austin\",\"accepted\":true}," +
                "\"technicalPointOfContact\":{\"name\":\"Test User\",\"email\":\"test@example.com\",\"phone\":\"\",\"designation\":\"Technical Contact\"}," +
                "\"remarks\":\"Issued via Keyfactor Command AnyCA REST Gateway.\"}");
        }
    }
}
