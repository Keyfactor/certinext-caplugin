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
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Tests for the non-UCC V2 single-domain SAN guard's wildcard-apex exemption:
    /// a wildcard product's CSR/SAN dictionary routinely also carries the bare apex alongside
    /// the wildcard domain itself (e.g. "example.com" alongside "*.example.com"), and the guard
    /// must not reject that apex as an "extra SAN" the way it would for any other non-UCC
    /// product. Only the apex is exempt — any other extra SAN is still rejected, and non-wildcard
    /// products are unaffected.
    ///
    /// NOTE: these tests only confirm the guard's accept/reject decision. What is actually sent
    /// to the CA for the apex (whether additionalDomains needs it, or CERTInext handles it
    /// automatically for a wildcard product) has not been confirmed against the live API — see
    /// the comment in EnrollV2Async above the guard.
    /// </summary>
    public class V2WildcardEnrollmentTests
    {
        private static Mock<ICERTInextClient> NewMock() =>
            new Mock<ICERTInextClient>(MockBehavior.Strict);

        private static CERTInextCAPlugin BuildV2Plugin(ICERTInextClient client, string organizationNumber = null) =>
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

        private static EnrollmentProductInfo MakeWildcardProductInfo(
            string productId, string productCode, string domainName) =>
            new EnrollmentProductInfo
            {
                ProductID = productId,
                ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ProductCode"]    = productCode,
                    ["ProductFamily"]  = "ssl",
                    // No explicit ProductVariant — it is derived from ProductID
                    // ("dv"/"ov"), avoiding a mismatch reject for the OV wildcard test.
                    ["DomainName"]     = domainName
                }
            };

        private static void StubCatalog(Mock<ICERTInextClient> mock, string productCode, string productTypeId) =>
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = productCode, ProductTypeId = productTypeId, Active = true }
                });

        private static void StubHappyOrderPlacement(Mock<ICERTInextClient> mock, string orderId = "ord_wc_001")
        {
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = orderId, Status = "pending-dcv" });

            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), orderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), orderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = orderId, Status = "pending-dcv" });
        }

        [Fact]
        public async Task Enroll_V2_DvWildcard_ApexInSanDictionary_IsNotRejected()
        {
            var mock = NewMock();
            StubCatalog(mock, "839", "14"); // DV SSL Wildcard
            StubHappyOrderPlacement(mock);

            var plugin = BuildV2Plugin(mock.Object);

            var result = await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=*.example.com",
                san: new Dictionary<string, string[]>
                {
                    // Apex alongside the wildcard domain — routine for a wildcard CSR.
                    ["dns"] = new[] { "*.example.com", "example.com" }
                },
                productInfo: MakeWildcardProductInfo(Constants.Products.DvSslWildcard, "839", "*.example.com"),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION,
                "the apex must be exempted from the single-domain guard for a wildcard product, " +
                "not rejected as an extra SAN");
            mock.Verify(c => c.PlaceOrderV2Async(
                It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task Enroll_V2_OvWildcard_ApexInSanDictionary_IsNotRejected()
        {
            var mock = NewMock();
            StubCatalog(mock, "843", "17"); // OV SSL Wildcard
            StubHappyOrderPlacement(mock);

            // OV requires an organization block.
            var plugin = BuildV2Plugin(mock.Object, organizationNumber: "ORG-TEST-001");

            var result = await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=*.example.com",
                san: new Dictionary<string, string[]>
                {
                    ["dns"] = new[] { "*.example.com", "example.com" }
                },
                productInfo: MakeWildcardProductInfo(Constants.Products.OvSslWildcard, "843", "*.example.com"),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            mock.Verify(c => c.PlaceOrderV2Async(
                It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task Enroll_V2_DvWildcard_NonApexExtraSan_StillRejected_WithoutSuggestingUcc()
        {
            var mock = NewMock();
            StubCatalog(mock, "839", "14"); // DV SSL Wildcard

            var plugin = BuildV2Plugin(mock.Object);

            var result = await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=*.example.com",
                san: new Dictionary<string, string[]>
                {
                    // The apex is exempt, but an unrelated extra domain is not.
                    ["dns"] = new[] { "*.example.com", "example.com", "other.example.com" }
                },
                productInfo: MakeWildcardProductInfo(Constants.Products.DvSslWildcard, "839", "*.example.com"),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Status.Should().Be((int)EndEntityStatus.FAILED);
            result.StatusMessage.Should().Contain("1 SAN(s) beyond");
            result.StatusMessage.Should().NotContain("UCC",
                "a wildcard enrollment rejection must not suggest buying a UCC product");

            mock.Verify(c => c.PlaceOrderV2Async(
                It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Enroll_V2_NonWildcardProduct_ApexNotExempt_StillRejected_AndSuggestsUcc()
        {
            // Sanity check that the exemption is wildcard-specific: a non-wildcard, non-UCC
            // product's "extra" SAN set is unaffected by this fix, and its rejection message
            // still offers the UCC suggestion (only wildcard products' wording changes).
            var mock = NewMock();
            StubCatalog(mock, "842", "13"); // DV SSL (non-wildcard, non-UCC)

            var plugin = BuildV2Plugin(mock.Object);

            var result = await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=example.com",
                san: new Dictionary<string, string[]>
                {
                    ["dns"] = new[] { "example.com", "other.example.com" }
                },
                productInfo: MakeWildcardProductInfo(Constants.Products.DvSsl, "842", "example.com"),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Status.Should().Be((int)EndEntityStatus.FAILED);
            result.StatusMessage.Should().Contain("UCC");

            mock.Verify(c => c.PlaceOrderV2Async(
                It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }
}
