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
    /// Regression tests for issues/0028-v2-organizationnumber-not-sent.md: the V2
    /// <c>organization</c> block was never populated for any product variant, and CERTInext
    /// hard-rejects an OV/EV order that omits it (live-confirmed HTTP 422
    /// <c>[EMS-1180] Organization Name cannot be empty</c>). These tests exercise
    /// <c>EnrollV2Async</c> end-to-end (through <see cref="CERTInextCAPlugin.Enroll"/>) against a
    /// Strict <see cref="ICERTInextClient"/> mock, plus direct DTO serialization checks for the
    /// new <see cref="V2OrganizationParams"/> block on <see cref="V2CreateSslOrderRequest"/>.
    /// </summary>
    public class V2OrganizationEnrollmentTests
    {
        private static Mock<ICERTInextClient> NewMock() =>
            new Mock<ICERTInextClient>(MockBehavior.Strict);

        private static CERTInextCAPlugin BuildV2Plugin(ICERTInextClient client, string organizationNumber = "") =>
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
                OrganizationNumber = organizationNumber,
                PickupRetries     = 0
            });

        private static EnrollmentProductInfo MakeV2ProductInfo(string productCode, string productVariant) =>
            new EnrollmentProductInfo
            {
                ProductID = "OV SSL",
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
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = orderId, Status = "pending-organization-verification" });
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
        // EnrollV2Async wiring — organization block populated / omitted per productVariant
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData("ov")]
        [InlineData("ev")]
        [InlineData("OV")]
        [InlineData("Ev")]
        public async Task Enroll_V2_OvOrEvProduct_PopulatesOrganizationBlockFromConfig(string productVariant)
        {
            var mock = NewMock();
            StubCatalog(mock, "846", "16"); // non-UCC product type ID
            StubHappyOrderPlacement(mock, "ord_org_001");

            V2CreateSslOrderRequest captured = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>((_, __, req, ___) => captured = req)
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = "ord_org_001", Status = "pending-organization-verification" });

            var plugin = BuildV2Plugin(mock.Object, organizationNumber: "ORG-12345");

            var result = await plugin.Enroll(
                csr: GenerateCsrPem("example.com"),
                subject: "CN=example.com",
                san: null,
                productInfo: MakeV2ProductInfo("846", productVariant),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.CARequestID.Should().Be("ord_org_001");
            captured.Should().NotBeNull();
            captured!.Organization.Should().NotBeNull(
                "organization is mandatory for OV/EV orders per the V2 spec's field table");
            captured.Organization.OrganizationNumber.Should().Be("ORG-12345");
            captured.Organization.PreVetted.Should().BeTrue();
        }

        [Fact]
        public async Task Enroll_V2_DvProduct_OmitsOrganizationBlock_EvenWhenOrganizationNumberConfigured()
        {
            var mock = NewMock();
            StubCatalog(mock, "842", "13"); // DV SSL (non-UCC)
            StubHappyOrderPlacement(mock, "ord_dv_001");

            V2CreateSslOrderRequest captured = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>((_, __, req, ___) => captured = req)
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = "ord_dv_001", Status = "pending-dcv" });

            // OrganizationNumber IS configured — a DV order must still omit the block per spec
            // ("organization | Conditional - Mandatory for OV / EV", not DV).
            var plugin = BuildV2Plugin(mock.Object, organizationNumber: "ORG-12345");

            var result = await plugin.Enroll(
                csr: GenerateCsrPem("example.com"),
                subject: "CN=example.com",
                san: null,
                productInfo: MakeV2ProductInfo("842", "dv"),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.CARequestID.Should().Be("ord_dv_001");
            captured.Should().NotBeNull();
            captured!.Organization.Should().BeNull(
                "DV orders must not send an organization block even when OrganizationNumber is configured");
        }

        [Theory]
        [InlineData("ov")]
        [InlineData("ev")]
        public async Task Enroll_V2_OvOrEvProduct_MissingOrganizationNumber_FailsFastWithoutCallingCa(string productVariant)
        {
            // Strict mock with NOTHING stubbed: proves the guard fires before any catalog lookup
            // or order-placement call — mirrors the CSR-SAN-count guard's own Strict-mock test.
            var mock = NewMock();
            var plugin = BuildV2Plugin(mock.Object, organizationNumber: string.Empty);

            var result = await plugin.Enroll(
                csr: GenerateCsrPem("example.com"),
                subject: "CN=example.com",
                san: null,
                productInfo: MakeV2ProductInfo("846", productVariant),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Status.Should().Be((int)EndEntityStatus.FAILED);
            result.StatusMessage.Should().Contain("OrganizationNumber");

            mock.Verify(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()), Times.Never,
                "the OrganizationNumber guard must reject before any catalog lookup is attempted");
            mock.Verify(c => c.PlaceOrderV2Async(
                It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // DTO serialization — organization block shape on the wire
        // ---------------------------------------------------------------------------

        [Fact]
        public void V2CreateSslOrderRequest_Serialization_IncludesOrganizationBlock_ForOvEv()
        {
            var req = new V2CreateSslOrderRequest
            {
                ProductVariant = "ov",
                Requestor = new V2Requestor { Name = "Jane Doe", Email = "jane@example.com" },
                Organization = new V2OrganizationParams
                {
                    OrganizationNumber = "ORG-999",
                    PreVetted = true
                },
                Certificate = new V2CertificateParams { Domain = "example.com" }
            };

            string json = JsonSerializer.Serialize(req);

            json.Should().Contain("\"organization\"");
            json.Should().Contain("\"organizationNumber\":\"ORG-999\"");
            json.Should().Contain("\"preVetted\":true");
            // preVettingToken is optional and unset here — must be omitted, not sent as null.
            json.Should().NotContain("preVettingToken");
        }

        [Fact]
        public void V2CreateSslOrderRequest_Serialization_OmitsOrganizationBlock_ForDv()
        {
            var req = new V2CreateSslOrderRequest
            {
                ProductVariant = "dv",
                Requestor = new V2Requestor { Name = "Jane Doe", Email = "jane@example.com" },
                Organization = null,
                Certificate = new V2CertificateParams { Domain = "example.com" }
            };

            string json = JsonSerializer.Serialize(req);

            json.Should().NotContain("\"organization\"",
                "the organization key itself (not just its sub-fields) must be absent for DV orders, " +
                "not present-but-empty — an empty/placeholder block risks a different CA-side 422");
        }
    }
}
