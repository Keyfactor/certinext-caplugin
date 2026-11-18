// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Issue 0097: the gateway gives a synced record a template only when its <c>ProductID</c> exactly equals a
    /// template's ProductID, a product name from <c>GetProductIds()</c>. Both syncs must name the CERTInext product
    /// code through the account catalog (code -> productTypeID -> name), and keep the code when they can't.
    /// Catalog values are the sandbox's (V1 and V2 identical, 2026-11-16), plus an SSL.com-category catalog.
    /// </summary>
    [Collection(LoggingStateCollection.Name)]
    public class SyncProductIdTests
    {
        private static List<ProductDetail> SandboxCatalog() => new List<ProductDetail>
        {
            new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true },  // DV SSL Certificate
            new ProductDetail { ProductCode = "917", ProductTypeId = "13", Active = true },  // SSL DV 1 month
            new ProductDetail { ProductCode = "847", ProductTypeId = "17", Active = true },  // OV SSL Certificate Wildcard
            new ProductDetail { ProductCode = "845", ProductTypeId = "21", Active = true },  // DV SSL Certificate Wildcard UCC
            new ProductDetail { ProductCode = "149", ProductTypeId = "39", Active = true },  // Intranet SSL (no plugin product)
        };

        // An account issuing through SSL.com: the "SSL.com" catalog category (2026-11-17).
        private static List<ProductDetail> SslComCatalog() => new List<ProductDetail>
        {
            new ProductDetail { ProductCode = "1011", ProductTypeId = "47", Active = true },  // SSL.com DV SSL
            new ProductDetail { ProductCode = "1012", ProductTypeId = "48", Active = true },  // SSL.com DV SSL Wildcard
            new ProductDetail { ProductCode = "1013", ProductTypeId = "49", Active = true },  // SSL.com DV SSL UCC
            new ProductDetail { ProductCode = "1014", ProductTypeId = "50", Active = true },  // SSL.com DV SSL Wildcard UCC
            new ProductDetail { ProductCode = "1015", ProductTypeId = "51", Active = true },  // SSL.com OV SSL
            new ProductDetail { ProductCode = "1020", ProductTypeId = "56", Active = true },  // SSL.com EV SSL UCC
            new ProductDetail { ProductCode = "149", ProductTypeId = "39", Active = true },   // Intranet SSL (no plugin product)
        };

        [Theory]
        [InlineData("13", Constants.Products.DvSsl)]
        [InlineData("17", Constants.Products.OvSslWildcard)]
        [InlineData("21", Constants.Products.DvSslWildcardUcc)]
        [InlineData("20", Constants.Products.EvSslUcc)]
        [InlineData(" 16 ", Constants.Products.OvSsl)]
        [InlineData("47", Constants.Products.DvSsl)]
        [InlineData("48", Constants.Products.DvSslWildcard)]
        [InlineData("49", Constants.Products.DvSslUcc)]
        [InlineData("50", Constants.Products.DvSslWildcardUcc)]
        [InlineData("51", Constants.Products.OvSsl)]
        [InlineData("52", Constants.Products.OvSslWildcard)]
        [InlineData("53", Constants.Products.OvSslUcc)]
        [InlineData("54", Constants.Products.OvSslWildcardUcc)]
        [InlineData("55", Constants.Products.EvSsl)]
        [InlineData("56", Constants.Products.EvSslUcc)]
        [InlineData("39", null)]
        [InlineData("", null)]
        [InlineData(null, null)]
        public void ProductNameForTypeId_MapsPluginProductTypes(string typeId, string expected)
        {
            CERTInextCAPlugin.ProductNameForTypeId(typeId).Should().Be(expected);
        }

        [Fact]
        public void EveryAdvertisedProductHasATypeId_AndMapsBackToItself()
        {
            var plugin = new CERTInextCAPlugin();
            foreach (string name in plugin.GetProductIds())
            {
                Constants.Products.ProductTypeIdsV2.Should().ContainKey(name);
                CERTInextCAPlugin.ProductNameForTypeId(Constants.Products.ProductTypeIdsV2[name]).Should().Be(name);
                Constants.Products.SslComProductTypeIdsV2.Should().ContainKey(name);
                CERTInextCAPlugin.ProductNameForTypeId(Constants.Products.SslComProductTypeIdsV2[name]).Should().Be(name);
            }
        }

        // ---------------------------------------------------------------------------
        // V2 sync
        // ---------------------------------------------------------------------------

        private static async IAsyncEnumerable<OrderReportEntryV2> Rows(params OrderReportEntryV2[] rows)
        {
            foreach (var r in rows) yield return r;
            await Task.CompletedTask;
        }

        private static OrderReportEntryV2 IssuedRow(string id, string productCode) => new OrderReportEntryV2
        {
            OrderNumber = id, OrderStatus = "Order Fulfilled", CertificateStatus = "Certificate Downloaded",
            DomainName = "example.com", ProductCode = productCode, OrderDate = DateTime.UtcNow.AddHours(-2).ToString("o")
        };

        private static (Mock<ICERTInextClient> Mock, CERTInextCAPlugin Plugin) V2(params OrderReportEntryV2[] rows)
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            mock.Setup(c => c.ListOrdersV2Async(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(Rows(rows));
            foreach (var r in rows)
                mock.Setup(c => c.ResolveAndDownloadCertificateV2Async(r.OrderNumber, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new V2CertificateDownloadResponse
                    {
                        OrderId = r.OrderNumber, SerialNumber = "AA", CertificatePem = MockCertificateData.FakePemCertificate
                    });
            var config = new CERTInextConfig { UseV2Api = true, ApiUrl = "https://v2.certinext.io", OAuthClientId = "id", OAuthClientSecret = "s" };
            return (mock, new CERTInextCAPlugin(mock.Object, config));
        }

        [Fact]
        public async Task V2Sync_NamesProductCodesThroughTheCatalog_ReadOnce_KeepsUnknownCodes()
        {
            using var capture = new PluginLogCapture();
            var (mock, plugin) = V2(IssuedRow("a", "842"), IssuedRow("b", "917"), IssuedRow("c", "847"),
                IssuedRow("d", "149"), IssuedRow("e", "999"));
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>())).ReturnsAsync(SandboxCatalog());
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            buffer.ToArray().ToDictionary(r => r.CARequestID, r => r.ProductID).Should().Equal(new Dictionary<string, string>
            {
                ["a"] = Constants.Products.DvSsl,
                ["b"] = Constants.Products.DvSsl,          // a second DV code: the type decides, not a fixed table
                ["c"] = Constants.Products.OvSslWildcard,  // the live 1125823297 case
                ["d"] = "149",                             // Private PKI: no plugin product of that type
                ["e"] = "999",                             // not in the catalog
            });
            mock.Verify(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()), Times.Once);
            capture.Lines(LogLevel.Information, "synchronization complete").Should().ContainSingle()
                .Which.Should().Contain("ProductNames: Resolved=3, Unresolved=2");
            capture.Entries.Where(e => e.Level >= LogLevel.Warning).Should().BeEmpty();
        }

        [Fact]
        public async Task V2Sync_SslComCatalog_NamesSslComProductCodes()
        {
            using var capture = new PluginLogCapture();
            var (mock, plugin) = V2(IssuedRow("a", "1011"), IssuedRow("b", "1012"), IssuedRow("c", "1013"),
                IssuedRow("d", "1020"), IssuedRow("e", "149"));
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>())).ReturnsAsync(SslComCatalog());
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            buffer.ToArray().ToDictionary(r => r.CARequestID, r => r.ProductID).Should().Equal(new Dictionary<string, string>
            {
                ["a"] = Constants.Products.DvSsl,
                ["b"] = Constants.Products.DvSslWildcard,
                ["c"] = Constants.Products.DvSslUcc,
                ["d"] = Constants.Products.EvSslUcc,
                ["e"] = "149",                             // Private PKI: no plugin product of that type
            });
            capture.Lines(LogLevel.Information, "synchronization complete").Should().ContainSingle()
                .Which.Should().Contain("ProductNames: Resolved=4, Unresolved=1");
        }

        [Fact]
        public async Task V2Sync_CatalogFails_KeepsCodes_OneWarning_SyncCompletes()
        {
            using var capture = new PluginLogCapture();
            var (mock, plugin) = V2(IssuedRow("a", "842"), IssuedRow("b", "847"));
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("CERTInext V2 API error during 'V2 catalog'. HTTP 503."));
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            buffer.ToArray().Select(r => r.ProductID).Should().Equal("842", "847");
            mock.Verify(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()), Times.Once,
                "a failed catalog read isn't retried for every row");
            capture.Lines(LogLevel.Warning, "could not read the product catalog").Should().ContainSingle();
            capture.Lines(LogLevel.Information, "synchronization complete").Should().ContainSingle()
                .Which.Should().Contain("Errors=0");
        }

        [Fact]
        public async Task V2Sync_NoProductCodeOnRow_KeepsVariantFallback_NoCatalogRead()
        {
            var (mock, plugin) = V2(IssuedRow("a", ""));
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            buffer.ToArray().Should().ContainSingle().Which.ProductID.Should().BeEmpty();
            mock.Verify(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // V1 sync
        // ---------------------------------------------------------------------------

        private static async IAsyncEnumerable<LegacyGetCertificateResponse> Certs(params LegacyGetCertificateResponse[] certs)
        {
            foreach (var c in certs) yield return c;
            await Task.CompletedTask;
        }

        private static LegacyGetCertificateResponse V1Issued(string id, string profileId)
        {
            var c = MockCertificateData.IssuedCertRecord(id);
            c.ProfileId = profileId;
            return c;
        }

        [Fact]
        public async Task V1Sync_NamesProductCodesThroughTheV1Catalog_KeepsUnknownCodes()
        {
            using var capture = new PluginLogCapture();
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            mock.Setup(c => c.ListCertificatesAsync(null, It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(Certs(V1Issued("ORD-1", "842"), V1Issued("ORD-2", "845"), V1Issued("ORD-3", "810")));
            mock.Setup(c => c.GetProductDetailsAsync(It.IsAny<CancellationToken>())).ReturnsAsync(SandboxCatalog());
            var plugin = new CERTInextCAPlugin(mock.Object, new CERTInextConfig());
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            buffer.ToArray().ToDictionary(r => r.CARequestID, r => r.ProductID).Should().Equal(new Dictionary<string, string>
            {
                ["ORD-1"] = Constants.Products.DvSsl,             // the V1-era table would have said "OV SSL"
                ["ORD-2"] = Constants.Products.DvSslWildcardUcc,
                ["ORD-3"] = "810",                                // not in this catalog
            });
            mock.Verify(c => c.GetProductDetailsAsync(It.IsAny<CancellationToken>()), Times.Once);
            capture.Lines(LogLevel.Information, "synchronization complete").Should().ContainSingle()
                .Which.Should().Contain("ProductNames: Resolved=2, Unresolved=1");
        }
    }
}
