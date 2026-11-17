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

        // Explicit ProductCode: sent as given, with no product-code pre-check. The catalog is never read;
        // UCC is decided from the request (extra DNS SANs go out in additionalDomains), and CERTInext
        // rejects a code that can't carry them.
        public static IEnumerable<object[]> ExplicitCodeRequests() => new[]
        {
            // label, ProductId, code, DNS SANs, expected additionalDomains
            new object[] { "UCC code, extra SAN", Constants.Products.DvSslUcc, "844",
                new[] { "example.com", "extra.example.com" }, new[] { "extra.example.com" } },
            new object[] { "single-domain code, extra SAN", Constants.Products.DvSsl, "842",
                new[] { "example.com", "extra.example.com" }, new[] { "extra.example.com" } },
            new object[] { "Wildcard UCC code, wildcard SAN on apex CN", Constants.Products.DvSslWildcardUcc, "845",
                new[] { "example.com", "*.example.com" }, new[] { "*.example.com" } },
            new object[] { "code from another CA backend, wildcard SAN", Constants.Products.DvSsl, "1015",
                new[] { "example.com", "*.example.com" }, new[] { "*.example.com" } },
            new object[] { "single domain", Constants.Products.DvSsl, "1011",
                new[] { "example.com" }, new string[0] },
        };

        [Theory]
        [MemberData(nameof(ExplicitCodeRequests))]
        public async Task ExplicitProductCode_IsSentAsGiven_WithoutReadingTheCatalog(
            string label, string productId, string productCode, string[] sans, string[] expectedAdditional)
        {
            var (mock, cap) = NewSslMock();
            var plugin = new CERTInextCAPlugin(mock.Object, Config());

            var result = await EnrollAsync(plugin, ProductInfo(productId, productCode: productCode), sans);

            result.CARequestID.Should().Be(OrderId, label);
            cap.ProductCode.Should().Be(productCode, label);
            cap.Request.Certificate.Domain.Should().Be("example.com", label);
            (cap.Request.Certificate.AdditionalDomains ?? new List<string>()).Should().BeEquivalentTo(expectedAdditional, label);
            mock.Verify(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()), Times.Never, label);
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

        // CN = apex, wildcard only in the SANs. CERTInext's guidance is to send only the variant, so the
        // plugin sends no X-Product-Code and doesn't read the catalog: the wildcard goes out in
        // additionalDomains and CERTInext picks the product.
        [Theory]
        [InlineData("DV SSL", null, "dv")]
        [InlineData("OV SSL", "ORG-1", "ov")]
        public async Task NoExplicitProductCode_WildcardSanOnApexCn_SendsNoCode_WildcardInAdditionalDomains(
            string productId, string organizationNumber, string expectedVariant)
        {
            var (mock, cap) = NewSslMock();
            var plugin = new CERTInextCAPlugin(mock.Object, Config(organizationNumber: organizationNumber));

            var result = await EnrollAsync(plugin, ProductInfo(productId), "example.com", "*.example.com");

            result.CARequestID.Should().Be(OrderId);
            cap.ProductCode.Should().BeNull("the plugin never adds X-Product-Code on its own");
            cap.Request.ProductVariant.Should().Be(expectedVariant);
            cap.Request.Certificate.Domain.Should().Be("example.com", "certificate.domain must stay equal to the CSR CN");
            cap.Request.Certificate.AdditionalDomains.Should().Equal("*.example.com");
            mock.Verify(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task NoExplicitProductCode_WildcardSanOnApexCn_WithAnotherName_SendsNoCode()
        {
            var (mock, cap) = NewSslMock();
            var plugin = new CERTInextCAPlugin(mock.Object, Config());

            await EnrollAsync(plugin, ProductInfo(Constants.Products.DvSsl), "example.com", "*.example.com", "other.example.org");

            cap.ProductCode.Should().BeNull();
            cap.Request.Certificate.AdditionalDomains.Should().BeEquivalentTo("*.example.com", "other.example.org");
            mock.Verify(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()), Times.Never);
        }

        // EV can't be a wildcard, but that's CERTInext's call to make: the request goes out like any other
        // and CERTInext rejects it. No pre-check for either shape.
        [Theory]
        [InlineData("example.com", new[] { "example.com", "*.example.com" })]   // wildcard SAN on an apex CN
        [InlineData("*.example.com", new[] { "*.example.com" })]                // wildcard primary domain
        public async Task NoExplicitProductCode_EvWithWildcard_IsSentToCertinext(string domain, string[] sans)
        {
            var (mock, cap) = NewSslMock();
            var plugin = new CERTInextCAPlugin(mock.Object, Config(organizationNumber: "ORG-1"));

            var result = await EnrollAsync(plugin, ProductInfo(Constants.Products.EvSsl, domainName: domain), sans);

            result.CARequestID.Should().Be(OrderId);
            cap.Request.ProductVariant.Should().Be("ev");
            cap.Request.Certificate.Domain.Should().Be(domain);
            mock.Verify(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()), Times.Never);
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

            var lines = capture.Lines(LogLevel.Information, "V2 order placed");
            lines.Should().ContainSingle();
            lines[0].Should().Contain("ResolvedProductCode=(not reported)").And.Contain("XProductCodeSent=842");
        }
    }
}
