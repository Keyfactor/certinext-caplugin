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
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Issue 0098: a sync skips orders cancelled or rejected at CERTInext, but one the gateway still holds as pending must
    /// be emitted as failed, or it stays pending indefinitely (8 lab rows, 2026-11-16). Every other gateway state keeps the
    /// skip: no row (don't create a row per cancelled order), already terminal, issued or revoked (never downgraded), and a
    /// failed lookup.
    /// </summary>
    [Collection(LoggingStateCollection.Name)]
    public class SyncTerminalFailurePropagationTests
    {
        private const string HeldPending = "1212784622";   // a lab row: cancelled at CERTInext, pending in the gateway
        private const string NoRow = "8394286797";
        private const string HeldFailed = "6932127547F001";
        private const string HeldIssued = "7000000001";
        private const string LookupError = "7000000002";

        private static Mock<ICertificateDataReader> GatewayReader()
        {
            var reader = new Mock<ICertificateDataReader>(MockBehavior.Strict);
            reader.Setup(r => r.GetStatusByRequestID(HeldPending)).ReturnsAsync((int)EndEntityStatus.EXTERNALVALIDATION);
            reader.Setup(r => r.GetStatusByRequestID(NoRow)).ThrowsAsync(new ArgumentException($"No matching '{NoRow}' found."));
            reader.Setup(r => r.GetStatusByRequestID(HeldFailed)).ReturnsAsync((int)EndEntityStatus.FAILED);
            reader.Setup(r => r.GetStatusByRequestID(HeldIssued)).ReturnsAsync((int)EndEntityStatus.GENERATED);
            reader.Setup(r => r.GetStatusByRequestID(LookupError)).ThrowsAsync(new InvalidOperationException("db unavailable"));
            return reader;
        }

        private static readonly string[] AllIds = { HeldPending, NoRow, HeldFailed, HeldIssued, LookupError };

        // ---------------------------------------------------------------------------
        // V2
        // ---------------------------------------------------------------------------

        private static async IAsyncEnumerable<OrderReportEntryV2> Rows(IEnumerable<OrderReportEntryV2> rows)
        {
            foreach (var r in rows) yield return r;
            await Task.CompletedTask;
        }

        private static OrderReportEntryV2 CancelledRow(string id) => new OrderReportEntryV2
        {
            OrderNumber = id, OrderStatus = "Order Cancelled", CertificateStatus = "Rejected due to Order Cancellation",
            DomainName = "example.com", ProductCode = "842", OrderDate = DateTime.UtcNow.AddDays(-30).ToString("o")
        };

        [Fact]
        public async Task V2Sync_CancelledOrder_EmittedFailedOnlyWhenGatewayHoldsItPending()
        {
            using var capture = new PluginLogCapture();
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            mock.Setup(c => c.ListOrdersV2Async(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(() => Rows(AllIds.Select(CancelledRow)));
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail> { new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true } });
            var reader = GatewayReader();
            var plugin = new CERTInextCAPlugin(mock.Object,
                new CERTInextConfig { UseV2Api = true, ApiUrl = "https://v2.certinext.io", OAuthClientId = "id", OAuthClientSecret = "s" },
                reader.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            var record = buffer.ToArray().Should().ContainSingle("only the order the gateway holds as pending is emitted").Subject;
            record.CARequestID.Should().Be(HeldPending);
            record.Status.Should().Be((int)EndEntityStatus.FAILED);
            record.Certificate.Should().BeNullOrEmpty();
            record.ProductID.Should().Be(Constants.Products.DvSsl);
            mock.Verify(c => c.ResolveAndTrackOrderV2WithFamilyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never,
                "the report row already says cancelled; no Track Order call is needed");
            capture.Lines(LogLevel.Information, "synchronization complete").Should().ContainSingle()
                .Which.Should().Contain("FailedPropagated=1").And.Contain("Skipped=4").And.Contain("Errors=0");
            capture.Lines(LogLevel.Information, "still holds it as pending").Should().ContainSingle()
                .Which.Should().Contain(HeldPending);
        }

        [Fact]
        public async Task V2Sync_CancelledOrder_NoGatewayReader_SkippedAsBefore()
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            mock.Setup(c => c.ListOrdersV2Async(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(() => Rows(new[] { CancelledRow(HeldPending) }));
            var plugin = new CERTInextCAPlugin(mock.Object,
                new CERTInextConfig { UseV2Api = true, ApiUrl = "https://v2.certinext.io", OAuthClientId = "id", OAuthClientSecret = "s" });
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            buffer.ToArray().Should().BeEmpty();
        }

        // ---------------------------------------------------------------------------
        // V1
        // ---------------------------------------------------------------------------

        private static async IAsyncEnumerable<LegacyGetCertificateResponse> Certs(IEnumerable<LegacyGetCertificateResponse> certs)
        {
            foreach (var c in certs) yield return c;
            await Task.CompletedTask;
        }

        [Fact]
        public async Task V1Sync_CancelledOrder_EmittedFailedOnlyWhenGatewayHoldsItPending()
        {
            using var capture = new PluginLogCapture();
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            mock.Setup(c => c.ListCertificatesAsync(null, It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(() => Certs(AllIds.Select(id => new LegacyGetCertificateResponse
                {
                    Id = id, Status = Constants.CertificateStatus.Cancelled, ProfileId = "842",
                    OrderDate = DateTime.UtcNow.AddDays(-30)
                })));
            mock.Setup(c => c.GetProductDetailsAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail> { new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true } });
            var plugin = new CERTInextCAPlugin(mock.Object, GatewayReader().Object, new CERTInextConfig { UseV2Api = false });
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            var record = buffer.ToArray().Should().ContainSingle().Subject;
            record.CARequestID.Should().Be(HeldPending);
            record.Status.Should().Be((int)EndEntityStatus.FAILED);
            record.Certificate.Should().BeNullOrEmpty();
            record.ProductID.Should().Be(Constants.Products.DvSsl);
            capture.Lines(LogLevel.Information, "synchronization complete").Should().ContainSingle()
                .Which.Should().Contain("FailedPropagated=1");
        }
    }
}
