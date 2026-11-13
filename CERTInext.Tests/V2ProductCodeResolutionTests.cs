// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// X-Product-Code is the V2 spec's optional override: CERTInext's wrapper picks the catalog
    /// product from the variant, whether <c>certificate.domain</c> starts with <c>*.</c>, and
    /// whether <c>additionalDomains</c> is non-empty. These tests pin that <c>EnrollV2Async</c>
    /// sends a code only when the template sets one, never consults the catalog or the connector's
    /// <c>DefaultProductCode</c> otherwise, decides wildcard/UCC from the request shape, and logs
    /// the response's <c>resolvedProductCode</c>. Driven through <see cref="CERTInextCAPlugin.Enroll"/>
    /// against a Strict <see cref="ICERTInextClient"/> mock (an unexpected catalog call fails the test).
    /// </summary>
    [Collection(LoggingStateCollection.Name)]
    public class V2ProductCodeResolutionTests
    {
        private const string OrderId = "ord_pcr_001";

        private static CERTInextConfig Config(string defaultProductCode = null, string organizationNumber = null) =>
            new CERTInextConfig
            {
                UseV2Api           = true,
                ApiUrl             = "https://v2.certinext.io",
                OAuthClientId      = "my-client",
                OAuthClientSecret  = "my-secret",
                RequestorName      = "Test User",
                RequestorEmail     = "test@example.com",
                SignerPlace        = "New York",
                DefaultProductCode = defaultProductCode,
                OrganizationNumber = organizationNumber,
                PickupRetries      = 0
            };

        private sealed class Captured
        {
            public string ProductCode = "sentinel-not-called";
            public V2CreateSslOrderRequest Request;
            public bool Placed;
        }

        private static (Mock<ICERTInextClient> Mock, Captured Cap) NewSslMock(string resolvedProductCode = null)
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            var cap = new Captured();
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>((_, code, req, __) =>
                {
                    cap.ProductCode = code;
                    cap.Request = req;
                    cap.Placed = true;
                })
                .ReturnsAsync(new V2CreateOrderResponse
                {
                    OrderId = OrderId, Status = "pending-dcv", ResolvedProductCode = resolvedProductCode
                });
            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "pending-dcv" });
            return (mock, cap);
        }

        private static EnrollmentProductInfo ProductInfo(
            string productId, string domainName = "example.com", string productCode = null)
        {
            var p = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ProductFamily"] = "ssl",
                ["DomainName"]    = domainName
            };
            if (productCode != null) p["ProductCode"] = productCode;
            return new EnrollmentProductInfo { ProductID = productId, ProductParameters = p };
        }

        private static Task<EnrollmentResult> EnrollAsync(
            CERTInextCAPlugin plugin, EnrollmentProductInfo info, params string[] dnsSans) =>
            plugin.Enroll(MockCertificateData.FakeCsrPem, $"CN={info.ProductParameters["DomainName"]}",
                new Dictionary<string, string[]> { ["dnsname"] = dnsSans }, info,
                RequestFormat.PKCS10, EnrollmentType.New);

        [Fact]
        public async Task NoExplicitProductCode_SendsNoCode_AndNeverReadsTheCatalog()
        {
            var (mock, cap) = NewSslMock();
            var plugin = new CERTInextCAPlugin(mock.Object, Config(organizationNumber: "ORG-1"));

            var result = await EnrollAsync(plugin, ProductInfo(Constants.Products.OvSsl), "example.com");

            result.CARequestID.Should().Be(OrderId);
            cap.Placed.Should().BeTrue();
            cap.ProductCode.Should().BeNull("an unset template ProductCode means no X-Product-Code override");
            cap.Request.ProductVariant.Should().Be("ov");
            mock.Verify(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()), Times.Never);
        }

        [Theory]
        [InlineData("842")]   // names one of several matching catalog entries
        [InlineData("999")]   // not even in a catalog
        public async Task NoExplicitProductCode_ConnectorDefaultProductCode_NoLongerPinsV2Orders(string defaultProductCode)
        {
            var (mock, cap) = NewSslMock();
            var plugin = new CERTInextCAPlugin(mock.Object, Config(defaultProductCode));

            await EnrollAsync(plugin, ProductInfo(Constants.Products.DvSsl), "example.com");

            cap.ProductCode.Should().BeNull();
            mock.Verify(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task ExplicitProductCode_IsStillSent_AndCatalogStillDecidesUcc()
        {
            var (mock, cap) = NewSslMock();
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = "844", ProductTypeId = "15", Active = true } // DV SSL UCC
                });
            var plugin = new CERTInextCAPlugin(mock.Object, Config(defaultProductCode: "842"));

            // ProductId is a NON-UCC product; the explicit code's catalog entry is UCC, so the
            // catalog (not the ProductId) decides and the extra SAN goes out as additionalDomains.
            await EnrollAsync(plugin, ProductInfo(Constants.Products.DvSsl, productCode: "844"),
                "example.com", "extra.example.com");

            cap.ProductCode.Should().Be("844");
            cap.Request.Certificate.AdditionalDomains.Should().Equal("extra.example.com");
            mock.Verify(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task ExplicitProductCode_NonUccCatalogEntry_StillRejectsExtraSans()
        {
            var (mock, cap) = NewSslMock();
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true }
                });
            var plugin = new CERTInextCAPlugin(mock.Object, Config());

            var result = await EnrollAsync(plugin, ProductInfo(Constants.Products.DvSsl, productCode: "842"),
                "example.com", "extra.example.com");

            result.Status.Should().Be((int)EndEntityStatus.FAILED);
            cap.Placed.Should().BeFalse();
        }

        [Fact]
        public async Task NoExplicitProductCode_WildcardDomain_IsDetectedFromTheDomain_ApexIsNotAnExtraSan()
        {
            var (mock, cap) = NewSslMock();
            var plugin = new CERTInextCAPlugin(mock.Object, Config());

            // The template product is the plain DV SSL, but the domain is a wildcard: the wrapper
            // keys on the "*." shape. The bare apex alongside it is not an extra SAN.
            await EnrollAsync(plugin, ProductInfo(Constants.Products.DvSsl, domainName: "*.example.com"),
                "*.example.com", "example.com");

            cap.ProductCode.Should().BeNull();
            cap.Request.Certificate.Domain.Should().Be("*.example.com");
            cap.Request.Certificate.AdditionalDomains.Should().BeNull(
                "a wildcard plus its apex is not multi-domain, so the wrapper must resolve a wildcard, not a UCC, product");
        }

        [Fact]
        public async Task NoExplicitProductCode_UccTemplateProduct_SendsAdditionalDomains()
        {
            var (mock, cap) = NewSslMock();
            var plugin = new CERTInextCAPlugin(mock.Object, Config());

            await EnrollAsync(plugin, ProductInfo(Constants.Products.DvSslUcc), "example.com", "a.example.com", "b.example.com");

            cap.ProductCode.Should().BeNull();
            cap.Request.Certificate.AdditionalDomains.Should().BeEquivalentTo("a.example.com", "b.example.com");
        }

        [Fact]
        public async Task NoExplicitProductCode_ExtraDnsSansOnANonUccTemplate_BecomeAdditionalDomains_InsteadOfFailing()
        {
            var (mock, cap) = NewSslMock();
            var plugin = new CERTInextCAPlugin(mock.Object, Config());

            // With no explicit code the wrapper chooses a UCC product whenever additionalDomains is
            // non-empty, so the request shape decides; the single-domain guard (explicit non-UCC
            // code only) must not reject it.
            var result = await EnrollAsync(plugin, ProductInfo(Constants.Products.DvSsl), "example.com", "extra.example.com");

            result.CARequestID.Should().Be(OrderId);
            cap.Request.Certificate.AdditionalDomains.Should().Equal("extra.example.com");
        }

        [Fact]
        public async Task NoExplicitProductCode_PrimaryDomainAndWwwVariantOnly_IsNotUcc()
        {
            var (mock, cap) = NewSslMock();
            var plugin = new CERTInextCAPlugin(mock.Object, Config());

            await EnrollAsync(plugin, ProductInfo(Constants.Products.DvSsl), "example.com", "www.example.com");

            cap.Request.Certificate.AdditionalDomains.Should().BeNull();
        }

        [Fact]
        public async Task OrderCreated_LogsResolvedProductCodeFromTheResponse()
        {
            using var capture = new PluginLogCapture();
            var (mock, _) = NewSslMock(resolvedProductCode: "842");
            var plugin = new CERTInextCAPlugin(mock.Object, Config());

            await EnrollAsync(plugin, ProductInfo(Constants.Products.DvSsl), "example.com");

            var lines = capture.Lines(LogLevel.Information, "V2 order placed");
            lines.Should().ContainSingle();
            lines[0].Should().Contain("ResolvedProductCode=842").And.Contain("XProductCodeSent=(none)");
        }

        [Fact]
        public async Task OrderCreated_WithoutResolvedProductCodeInResponse_LogsNotReported()
        {
            using var capture = new PluginLogCapture();
            var (mock, _) = NewSslMock(resolvedProductCode: null);
            var plugin = new CERTInextCAPlugin(mock.Object, Config());

            await EnrollAsync(plugin, ProductInfo(Constants.Products.DvSsl, productCode: "842"), "example.com");

            // (the explicit code path reads the catalog; it is not stubbed here, so the plugin logs a
            // warning and treats the order as single-domain)
            var lines = capture.Lines(LogLevel.Information, "V2 order placed");
            lines.Should().ContainSingle();
            lines[0].Should().Contain("ResolvedProductCode=(not reported)").And.Contain("XProductCodeSent=842");
        }
    }
}
