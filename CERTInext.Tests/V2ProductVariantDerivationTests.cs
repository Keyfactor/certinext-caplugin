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
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Regression tests for issues/0059-v2-productvariant-not-derived-from-product.md: the V2
    /// SSL create body's <c>productVariant</c> defaulted to "dv" regardless of the selected
    /// product, so an OV/EV template with no explicit <c>ProductVariant</c> enrollment parameter
    /// sent a DV-shaped body — skipping the mandatory OV/EV <c>organization</c> block (issue 0028)
    /// — while an explicit-but-contradictory override (e.g. "dv" configured for "OV SSL") passed
    /// through unchecked. Covers <see cref="CERTInextCAPlugin.ResolveSslProductVariant"/> directly,
    /// end-to-end through <see cref="CERTInextCAPlugin.Enroll"/>, and through
    /// <see cref="CERTInextCAPlugin.ValidateProductInfo"/> (template-save-time rejection).
    /// </summary>
    public class V2ProductVariantDerivationTests
    {
        // ---------------------------------------------------------------------------
        // ResolveSslProductVariant — pure unit tests, no CA calls
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData(Constants.Products.DvSsl, "dv")]
        [InlineData(Constants.Products.DvSslWildcard, "dv")]
        [InlineData(Constants.Products.OvSsl, "ov")]
        [InlineData(Constants.Products.OvSslWildcard, "ov")]
        [InlineData(Constants.Products.EvSsl, "ev")]
        [InlineData(Constants.Products.EvSslUcc, "ev")]
        public void ResolveSslProductVariant_NoExplicitVariant_DerivesFromProduct(string productId, string expectedVariant)
        {
            var ep = new Models.EnrollmentParams(new EnrollmentProductInfo
            {
                ProductID = productId,
                ProductParameters = new Dictionary<string, string>()
            });

            string error = CERTInextCAPlugin.ResolveSslProductVariant(ep, out string resolved);

            error.Should().BeNull();
            resolved.Should().Be(expectedVariant);
        }

        [Theory]
        [InlineData(Constants.Products.OvSsl, "OV", "ov")]
        [InlineData(Constants.Products.EvSsl, "Ev", "ev")]
        [InlineData(Constants.Products.DvSsl, "DV", "dv")]
        public void ResolveSslProductVariant_ExplicitVariant_AgreesWithProduct_ReturnsItLowercased(
            string productId, string explicitVariant, string expectedResolved)
        {
            var ep = new Models.EnrollmentParams(new EnrollmentProductInfo
            {
                ProductID = productId,
                ProductParameters = new Dictionary<string, string> { ["ProductVariant"] = explicitVariant }
            });

            string error = CERTInextCAPlugin.ResolveSslProductVariant(ep, out string resolved);

            error.Should().BeNull();
            resolved.Should().Be(expectedResolved);
        }

        [Fact]
        public void ResolveSslProductVariant_ExplicitVariant_ContradictsProduct_ReturnsActionableError()
        {
            // The exact bug scenario from issue 0059: an OV product with the SSL-only "dv"
            // default explicitly configured.
            var ep = new Models.EnrollmentParams(new EnrollmentProductInfo
            {
                ProductID = Constants.Products.OvSsl,
                ProductParameters = new Dictionary<string, string> { ["ProductVariant"] = "dv" }
            });

            string error = CERTInextCAPlugin.ResolveSslProductVariant(ep, out string resolved);

            resolved.Should().BeNull();
            error.Should().NotBeNull();
            error.Should().Contain(Constants.EnrollmentParam.ProductVariant)
                .And.Contain("'dv'")
                .And.Contain(Constants.Products.OvSsl)
                .And.Contain("'ov'");
        }

        [Fact]
        public void ResolveSslProductVariant_ExplicitVariant_ContradictsProduct_EvVsDv()
        {
            var ep = new Models.EnrollmentParams(new EnrollmentProductInfo
            {
                ProductID = Constants.Products.DvSsl,
                ProductParameters = new Dictionary<string, string> { ["ProductVariant"] = "ev" }
            });

            string error = CERTInextCAPlugin.ResolveSslProductVariant(ep, out string resolved);

            resolved.Should().BeNull();
            error.Should().Contain("'ev'").And.Contain(Constants.Products.DvSsl).And.Contain("'dv'");
        }

        [Fact]
        public void ResolveSslProductVariant_UnmappedProductId_NoExplicitVariant_KeepsCurrentSslDefault()
        {
            // No entry in Constants.Products.ProductVariantsV2 for this ProductId (none of the 10
            // real SSL products are named this) — issue 0059 says: don't invent a mapping, keep
            // pre-fix behavior (the SSL-only "dv" default) rather than guessing.
            var ep = new Models.EnrollmentParams(new EnrollmentProductInfo
            {
                ProductID = "Some Unmapped Product",
                ProductParameters = new Dictionary<string, string>()
            });

            string error = CERTInextCAPlugin.ResolveSslProductVariant(ep, out string resolved);

            error.Should().BeNull();
            resolved.Should().Be("dv");
        }

        [Fact]
        public void ResolveSslProductVariant_UnmappedProductId_ExplicitVariant_NotCrossChecked()
        {
            // Same "don't invent a mapping" rule applied to the explicit-override path: with no
            // authoritative product->variant mapping, an explicit override is passed through
            // rather than rejected against a guess.
            var ep = new Models.EnrollmentParams(new EnrollmentProductInfo
            {
                ProductID = "Some Unmapped Product",
                ProductParameters = new Dictionary<string, string> { ["ProductVariant"] = "ev" }
            });

            string error = CERTInextCAPlugin.ResolveSslProductVariant(ep, out string resolved);

            error.Should().BeNull();
            resolved.Should().Be("ev");
        }

        // ---------------------------------------------------------------------------
        // Enroll_V2 — end-to-end through CERTInextCAPlugin.Enroll
        // ---------------------------------------------------------------------------

        private static Mock<ICERTInextClient> NewMock() =>
            new Mock<ICERTInextClient>(MockBehavior.Strict);

        private static CERTInextCAPlugin BuildV2Plugin(ICERTInextClient client, string organizationNumber = null) =>
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
                OrganizationNumber = organizationNumber,
                PickupRetries      = 0
            });

        private static EnrollmentProductInfo MakeProductInfo(string productId, string productVariant = null) =>
            new EnrollmentProductInfo
            {
                ProductID = productId,
                ProductParameters = productVariant == null
                    ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["ProductFamily"] = "ssl",
                        ["DomainName"]    = "example.com"
                    }
                    : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
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

        private static void StubHappyOrderPlacement(Mock<ICERTInextClient> mock, string orderId, string status = "pending-dcv")
        {
            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), orderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), orderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = orderId, Status = status });
        }

        [Fact]
        public async Task Enroll_V2_OvProduct_NoExplicitProductVariant_SendsOvAndOrganizationBlock()
        {
            var mock = NewMock();
            StubCatalog(mock, "846", "16"); // OV SSL, non-UCC
            StubHappyOrderPlacement(mock, "ord_0059_ov", "pending-organization-verification");

            V2CreateSslOrderRequest captured = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>((_, __, req, ___) => captured = req)
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = "ord_0059_ov", Status = "pending-organization-verification" });

            var plugin = BuildV2Plugin(mock.Object, organizationNumber: "ORG-0059");

            var result = await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=example.com",
                san: new Dictionary<string, string[]>(),
                productInfo: MakeProductInfo(Constants.Products.OvSsl), // no ProductVariant set
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.CARequestID.Should().Be("ord_0059_ov");
            captured.Should().NotBeNull();
            captured!.ProductVariant.Should().Be("ov",
                "with no explicit ProductVariant, the wire value must be derived from ProductID 'OV SSL'");
            captured.Organization.Should().NotBeNull(
                "deriving 'ov' must engage the same OV/EV organization-block requirement as an explicit 'ov'");
            captured.Organization.OrganizationNumber.Should().Be("ORG-0059");
        }

        [Fact]
        public async Task Enroll_V2_EvProduct_NoExplicitProductVariant_SendsEvAndOrganizationBlock()
        {
            var mock = NewMock();
            StubCatalog(mock, "847", "19"); // EV SSL, non-UCC
            StubHappyOrderPlacement(mock, "ord_0059_ev", "pending-organization-verification");

            V2CreateSslOrderRequest captured = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>((_, __, req, ___) => captured = req)
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = "ord_0059_ev", Status = "pending-organization-verification" });

            var plugin = BuildV2Plugin(mock.Object, organizationNumber: "ORG-0059");

            var result = await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=example.com",
                san: new Dictionary<string, string[]>(),
                productInfo: MakeProductInfo(Constants.Products.EvSsl), // no ProductVariant set
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.CARequestID.Should().Be("ord_0059_ev");
            captured!.ProductVariant.Should().Be("ev");
            captured.Organization.Should().NotBeNull();
        }

        [Fact]
        public async Task Enroll_V2_DvProduct_NoExplicitProductVariant_StaysDv_NoOrganizationBlock()
        {
            // Regression guard: the DV default path (the overwhelming majority of existing
            // templates) must be completely unaffected by 0059.
            var mock = NewMock();
            StubCatalog(mock, "842", "13"); // DV SSL, non-UCC
            StubHappyOrderPlacement(mock, "ord_0059_dv");

            V2CreateSslOrderRequest captured = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>((_, __, req, ___) => captured = req)
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = "ord_0059_dv", Status = "pending-dcv" });

            // Deliberately no OrganizationNumber configured — a DV order must not need it.
            var plugin = BuildV2Plugin(mock.Object, organizationNumber: null);

            var result = await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=example.com",
                san: new Dictionary<string, string[]>(),
                productInfo: MakeProductInfo(Constants.Products.DvSsl),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.CARequestID.Should().Be("ord_0059_dv");
            captured!.ProductVariant.Should().Be("dv");
            captured.Organization.Should().BeNull();
        }

        [Theory]
        [InlineData(Constants.Products.OvSsl, "dv")]
        [InlineData(Constants.Products.DvSsl, "ov")]
        [InlineData(Constants.Products.EvSsl, "dv")]
        public async Task Enroll_V2_ExplicitProductVariantContradictsProduct_FailsFastWithoutAnyCaCall(
            string productId, string contradictingVariant)
        {
            // Strict mock with NOTHING stubbed: the mismatch must be rejected before any CA call
            // at all (no catalog lookup, no order placement) — mirrors the private-pki variant
            // guard's own Strict-mock test.
            var mock = NewMock();
            var plugin = BuildV2Plugin(mock.Object, organizationNumber: "ORG-0059");

            var result = await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=example.com",
                san: new Dictionary<string, string[]>(),
                productInfo: MakeProductInfo(productId, contradictingVariant),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Status.Should().Be((int)EndEntityStatus.FAILED);
            result.CARequestID.Should().BeEmpty();
            result.StatusMessage.Should().Contain(Constants.EnrollmentParam.ProductVariant);
            mock.Invocations.Should().BeEmpty("the mismatch must be rejected before any CA call");
        }

        // ---------------------------------------------------------------------------
        // ValidateProductInfo — rejected at template save, before any catalog call
        // ---------------------------------------------------------------------------

        private static void StubToken(WireMockServer server) =>
            server.Given(Request.Create().WithPath("/oauth/token").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2TokenResponseJson()));

        private static void StubCatalogServer(WireMockServer server, string productCode, string productTypeId) =>
            server.Given(Request.Create().WithPath("/api/certinext/v2/catalog/products").UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody($"[{{\"productCode\":\"{productCode}\",\"productName\":\"Test Product\",\"productTypeID\":\"{productTypeId}\"}}]"));

        private static Dictionary<string, object> V2ConnectionInfo(string apiUrl) => new Dictionary<string, object>
        {
            ["UseV2Api"]          = true,
            ["ApiUrl"]            = apiUrl,
            ["OAuthClientId"]     = "my-client",
            ["OAuthClientSecret"] = "my-secret"
        };

        [Fact]
        public async Task ValidateProductInfo_V2_Ssl_NoExplicitProductVariant_Succeeds()
        {
            using var server = WireMockServer.Start();
            StubToken(server);
            StubCatalogServer(server, "846", "16"); // OV SSL

            var productInfo = new EnrollmentProductInfo
            {
                ProductID = Constants.Products.OvSsl,
                ProductParameters = new Dictionary<string, string>()
            };

            Func<Task> act = () => BuildV2Plugin(NewMock().Object)
                .ValidateProductInfo(productInfo, V2ConnectionInfo(server.Urls[0]));

            await act.Should().NotThrowAsync();
        }

        [Fact]
        public async Task ValidateProductInfo_V2_Ssl_ExplicitProductVariantMatchesProduct_Succeeds()
        {
            using var server = WireMockServer.Start();
            StubToken(server);
            StubCatalogServer(server, "846", "16"); // OV SSL

            var productInfo = new EnrollmentProductInfo
            {
                ProductID = Constants.Products.OvSsl,
                ProductParameters = new Dictionary<string, string> { ["ProductVariant"] = "ov" }
            };

            Func<Task> act = () => BuildV2Plugin(NewMock().Object)
                .ValidateProductInfo(productInfo, V2ConnectionInfo(server.Urls[0]));

            await act.Should().NotThrowAsync();
        }

        [Fact]
        public async Task ValidateProductInfo_V2_Ssl_ExplicitProductVariantContradictsProduct_ThrowsBeforeAnyCatalogCall()
        {
            using var server = WireMockServer.Start();
            StubToken(server);
            StubCatalogServer(server, "846", "16"); // OV SSL — never reached

            var productInfo = new EnrollmentProductInfo
            {
                ProductID = Constants.Products.OvSsl,
                ProductParameters = new Dictionary<string, string> { ["ProductVariant"] = "dv" }
            };

            Func<Task> act = () => BuildV2Plugin(NewMock().Object)
                .ValidateProductInfo(productInfo, V2ConnectionInfo(server.Urls[0]));

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage($"*{Constants.EnrollmentParam.ProductVariant}*");
            server.LogEntries.Should().NotContain(e => e.RequestMessage.Path == "/api/certinext/v2/catalog/products",
                "the ProductVariant/ProductId mismatch must be rejected before any catalog call");
        }

        [Fact]
        public async Task ValidateProductInfo_V2_PrivatePki_NotAffectedByThisSslCheck()
        {
            // Sanity: a private-pki template's own ProductVariant (intranet-ssl/igtf-host) must
            // never be run through the SSL cross-check this issue adds — it's checked by
            // ValidatePrivatePkiEnrollmentParams instead, unaffected here.
            using var server = WireMockServer.Start();
            StubToken(server);
            StubCatalogServer(server, "149", Constants.ApiV2.PrivatePkiProductTypeId);

            var productInfo = new EnrollmentProductInfo
            {
                ProductID = Constants.Products.DvSsl,
                ProductParameters = new Dictionary<string, string>
                {
                    ["ProductFamily"]  = "private-pki",
                    ["ProductVariant"] = "intranet-ssl",
                    ["ProductCode"]    = "149"
                }
            };

            Func<Task> act = () => BuildV2Plugin(NewMock().Object)
                .ValidateProductInfo(productInfo, V2ConnectionInfo(server.Urls[0]));

            await act.Should().NotThrowAsync();
        }
    }
}
