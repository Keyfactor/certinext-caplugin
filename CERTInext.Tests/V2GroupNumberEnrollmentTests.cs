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
    /// Tests that the V2 order body carries the connector's configured <c>GroupNumber</c>
    /// (V1's <c>DelegationInformation.GroupNumber</c> equivalent), so V2 orders bill to the
    /// configured group rather than always the account's default group. These tests exercise
    /// <c>EnrollV2Async</c> end-to-end (through <see cref="CERTInextCAPlugin.Enroll"/>) against a Strict
    /// <see cref="ICERTInextClient"/> mock, plus direct DTO serialization checks for the new
    /// <see cref="V2CreateSslOrderRequest.GroupNumber"/> property.
    /// </summary>
    public class V2GroupNumberEnrollmentTests
    {
        private static Mock<ICERTInextClient> NewMock() =>
            new Mock<ICERTInextClient>(MockBehavior.Strict);

        private static CERTInextCAPlugin BuildV2Plugin(ICERTInextClient client, string groupNumber = "") =>
            new CERTInextCAPlugin(client, new CERTInextConfig
            {
                UseV2Api          = true,
                ApiUrl            = "https://v2.certinext.io",
                OAuthClientId     = "my-client",
                OAuthClientSecret = "my-secret",
                RequestorName     = "Test User",
                RequestorEmail    = "test@example.com",
                SignerIp          = "1.2.3.4",
                SignerPlace       = "New York",
                GroupNumber       = groupNumber,
                PickupRetries     = 0
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

        // ---------------------------------------------------------------------------
        // EnrollV2Async wiring — GroupNumber populated / omitted on the order body
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_V2_GroupNumberConfigured_PopulatesGroupNumberOnOrderBody()
        {
            var mock = NewMock();
            StubCatalog(mock, "842", "13"); // DV SSL (non-UCC)
            StubHappyOrderPlacement(mock, "ord_grp_001");

            V2CreateSslOrderRequest captured = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>((_, __, req, ___) => captured = req)
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = "ord_grp_001", Status = "pending-dcv" });

            var plugin = BuildV2Plugin(mock.Object, groupNumber: "GRP-12345");

            var result = await plugin.Enroll(
                csr: GenerateCsrPem("example.com"),
                subject: "CN=example.com",
                san: null,
                productInfo: MakeV2ProductInfo("842", "dv"),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.CARequestID.Should().Be("ord_grp_001");
            captured.Should().NotBeNull();
            captured!.GroupNumber.Should().Be("GRP-12345",
                "a configured GroupNumber must be forwarded to the V2 order body, mirroring V1's " +
                "DelegationInformation.GroupNumber");
        }

        [Fact]
        public async Task Enroll_V2_GroupNumberBlank_OmitsGroupNumberFromOrderBody()
        {
            var mock = NewMock();
            StubCatalog(mock, "842", "13");
            StubHappyOrderPlacement(mock, "ord_grp_002");

            V2CreateSslOrderRequest captured = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>((_, __, req, ___) => captured = req)
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = "ord_grp_002", Status = "pending-dcv" });

            var plugin = BuildV2Plugin(mock.Object, groupNumber: string.Empty);

            var result = await plugin.Enroll(
                csr: GenerateCsrPem("example.com"),
                subject: "CN=example.com",
                san: null,
                productInfo: MakeV2ProductInfo("842", "dv"),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.CARequestID.Should().Be("ord_grp_002");
            captured.Should().NotBeNull();
            captured!.GroupNumber.Should().BeNull(
                "an unconfigured GroupNumber must be omitted (null), not sent as an empty string — " +
                "the account's default billing group should apply, same as V1's fallback behavior");
        }

        // ---------------------------------------------------------------------------
        // DTO serialization — groupNumber key present/absent on the wire
        // ---------------------------------------------------------------------------

        [Fact]
        public void V2CreateSslOrderRequest_Serialization_OmitsGroupNumber_WhenNull()
        {
            var req = new V2CreateSslOrderRequest
            {
                ProductVariant = "dv",
                Requestor = new V2Requestor { Name = "Jane Doe", Email = "jane@example.com" },
                Certificate = new V2CertificateParams { Domain = "example.com" },
                GroupNumber = null
            };

            string json = JsonSerializer.Serialize(req);

            json.Should().NotContain("groupNumber",
                "the groupNumber key itself must be absent when unset, not present-but-null");
        }

        [Fact]
        public void V2CreateSslOrderRequest_Serialization_IncludesGroupNumber_WhenSet()
        {
            var req = new V2CreateSslOrderRequest
            {
                ProductVariant = "dv",
                Requestor = new V2Requestor { Name = "Jane Doe", Email = "jane@example.com" },
                Certificate = new V2CertificateParams { Domain = "example.com" },
                GroupNumber = "GRP-999"
            };

            string json = JsonSerializer.Serialize(req);

            json.Should().Contain("\"groupNumber\":\"GRP-999\"");
        }
    }
}
