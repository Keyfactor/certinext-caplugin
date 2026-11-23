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
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// V2 SSL requests whose subject has no CN, with the names only in the SANs. The V2 spec requires
    /// <c>certificate.domain</c> but not a CSR CN, so the plugin takes the domain from the SANs: the first
    /// non-wildcard DNS name, else the first wildcard. A plain name whose own wildcard is also in the SANs
    /// becomes the additional domain of a wildcard order, because CERTInext rejects a wildcard in
    /// <c>additionalDomains</c> on a plain domain (EMS-1173).
    /// </summary>
    public class V2NoCnEnrollmentTests
    {
        private static CERTInextCAPlugin BuildV2Plugin(ICERTInextClient client) =>
            new CERTInextCAPlugin(client, new CERTInextConfig
            {
                UseV2Api          = true,
                ApiUrl            = "https://v2.certinext.io",
                OAuthClientId     = "my-client",
                OAuthClientSecret = "my-secret",
                RequestorName     = "Test User",
                RequestorEmail    = "test@example.com",
                SignerPlace       = "New York",
                PickupRetries     = 0
            });

        private static EnrollmentProductInfo DvProductInfo(string productId, string family = "ssl", string variant = null)
        {
            var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["ProductFamily"] = family };
            if (variant != null) parameters["ProductVariant"] = variant;
            return new EnrollmentProductInfo { ProductID = productId, ProductParameters = parameters };
        }

        /// <summary>Runs Enroll with an empty subject and returns the create request sent to CERTInext.</summary>
        private static async Task<V2CreateSslOrderRequest> EnrollWithoutCnAsync(string[] dnsSans, string productId)
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Loose);
            V2CreateSslOrderRequest sent = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>((_, _, r, _) => sent = r)
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = "ord_nocn_001", Status = "pending-dcv" });

            await BuildV2Plugin(mock.Object).Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: string.Empty,
                san: new Dictionary<string, string[]> { ["dnsname"] = dnsSans },
                productInfo: DvProductInfo(productId),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            sent.Should().NotBeNull("the order must be placed");
            return sent;
        }

        [Fact]
        public async Task Enroll_V2_NoCn_WildcardOnlySan_OrdersTheWildcard()
        {
            var sent = await EnrollWithoutCnAsync(new[] { "*.example.com" }, Constants.Products.DvSslWildcard);

            sent.Certificate.Domain.Should().Be("*.example.com");
            sent.Certificate.AdditionalDomains.Should().BeNullOrEmpty();
        }

        [Fact]
        public async Task Enroll_V2_NoCn_WildcardFirstThenApex_OrdersTheWildcardWithTheApexAsExtra()
        {
            var sent = await EnrollWithoutCnAsync(new[] { "*.example.com", "example.com" }, Constants.Products.DvSsl);

            sent.Certificate.Domain.Should().Be("*.example.com",
                "CERTInext reads a plain domain with a wildcard in additionalDomains as a multi-domain order " +
                "without a wildcard and rejects it (EMS-1173); the wildcard must be the domain");
            sent.Certificate.AdditionalDomains.Should().Equal("example.com");
        }

        /// <summary>Runs Enroll with a CN subject and returns the create request sent to CERTInext.</summary>
        private static async Task<V2CreateSslOrderRequest> EnrollWithCnAsync(
            string subject, string[] dnsSans, string domainName = null)
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Loose);
            V2CreateSslOrderRequest sent = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>((_, _, r, _) => sent = r)
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = "ord_cn_001", Status = "pending-dcv" });

            var productInfo = DvProductInfo(Constants.Products.DvSsl);
            if (domainName != null) productInfo.ProductParameters["DomainName"] = domainName;

            await BuildV2Plugin(mock.Object).Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: subject,
                san: new Dictionary<string, string[]> { ["dnsname"] = dnsSans },
                productInfo: productInfo,
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            sent.Should().NotBeNull("the order must be placed");
            return sent;
        }

        [Fact]
        public async Task Enroll_V2_ApexCn_WithItsWildcardSan_KeepsTheApexAsTheDomain()
        {
            var sent = await EnrollWithCnAsync("CN=example.com", new[] { "example.com", "*.example.com" });

            sent.Certificate.Domain.Should().Be("example.com",
                "a wildcard domain that differs from the CSR's CN is rejected (EMS-1056)");
            sent.Certificate.AdditionalDomains.Should().Equal("*.example.com");
        }

        [Fact]
        public async Task Enroll_V2_NoCn_ApexWithWildcardAndOtherName_KeepsEveryNameOnTheOrder()
        {
            var sent = await EnrollWithoutCnAsync(
                new[] { "example.com", "*.example.com", "other.example.com" }, Constants.Products.DvSsl);

            sent.Certificate.Domain.Should().Be("*.example.com");
            sent.Certificate.AdditionalDomains.Should().BeEquivalentTo("example.com", "other.example.com");
        }

        [Fact]
        public async Task Enroll_V2_ApexCn_WithExplicitDomainName_IsNotPromoted()
        {
            var sent = await EnrollWithCnAsync(
                "CN=example.com", new[] { "example.com", "*.example.com" }, domainName: "example.com");

            sent.Certificate.Domain.Should().Be("example.com", "an explicit DomainName is the operator's choice");
            sent.Certificate.AdditionalDomains.Should().Equal("*.example.com");
        }

        [Fact]
        public async Task Enroll_V2_ApexCn_WithAnotherNamesWildcard_IsNotPromoted()
        {
            var sent = await EnrollWithCnAsync("CN=example.com", new[] { "example.com", "*.other.example.org" });

            sent.Certificate.Domain.Should().Be("example.com");
            sent.Certificate.AdditionalDomains.Should().Equal("*.other.example.org");
        }

        [Theory]
        [InlineData("example.com", new[] { "example.com", "*.example.com" }, "*.example.com")]
        [InlineData("Example.COM", new[] { "example.com", "*.EXAMPLE.com" }, "*.Example.COM")]
        [InlineData("example.com", new[] { "example.com" }, "example.com")]
        [InlineData("example.com", new[] { "*.other.com" }, "example.com")]
        [InlineData("*.example.com", new[] { "*.example.com", "example.com" }, "*.example.com")]
        [InlineData("a.example.com", new[] { "*.example.com" }, "a.example.com")]
        public void PromoteWildcardSanToDomain_OnlyPromotesTheDomainsOwnWildcard(
            string domain, string[] dnsSans, string expected)
        {
            CERTInextCAPlugin.PromoteWildcardSanToDomain(
                    domain, new Dictionary<string, string[]> { ["dnsname"] = dnsSans }, MockCertificateData.FakeCsrPem)
                .Should().Be(expected);
        }

        [Fact]
        public async Task Enroll_V2_NoCn_NoDnsSan_Throws()
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Loose);

            Func<Task> act = () => BuildV2Plugin(mock.Object).Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: string.Empty,
                san: new Dictionary<string, string[]>(),
                productInfo: DvProductInfo(Constants.Products.DvSsl),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("Cannot determine primary domain for V2 order*DNS SAN*");
            mock.Verify(c => c.PlaceOrderV2Async(
                It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Enroll_V2_PrivatePki_NoCn_StillRequiresACn()
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Loose);

            Func<Task> act = () => BuildV2Plugin(mock.Object).Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: string.Empty,
                san: new Dictionary<string, string[]> { ["dnsname"] = new[] { "host.example.local" } },
                productInfo: DvProductInfo(Constants.Products.DvSsl, family: "private-pki", variant: "intranet-ssl"),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("Cannot determine the primary hostname for V2 private-pki order*");
        }

        [Theory]
        [InlineData(new[] { "*.example.com" }, "*.example.com")]
        [InlineData(new[] { "*.example.com", "example.com" }, "example.com")]
        [InlineData(new[] { "a.example.com", "b.example.com" }, "a.example.com")]
        public void PrimaryDomainFromSans_PrefersAPlainName(string[] dnsSans, string expected)
        {
            CERTInextCAPlugin.PrimaryDomainFromSans(
                    new Dictionary<string, string[]> { ["dnsname"] = dnsSans }, MockCertificateData.FakeCsrPem)
                .Should().Be(expected);
        }

        [Fact]
        public void PrimaryDomainFromSans_IgnoresNonDnsSans()
        {
            CERTInextCAPlugin.PrimaryDomainFromSans(
                    new Dictionary<string, string[]> { ["ipaddress"] = new[] { "10.0.0.1" } }, MockCertificateData.FakeCsrPem)
                .Should().BeNull();
        }
    }
}
