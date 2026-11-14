// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// The /reports/orders status text is undocumented (Finding 35): the V2 sync summary names every
    /// orderStatus|certificateStatus pair it couldn't map, with counts, at Information.
    /// </summary>
    [Collection(LoggingStateCollection.Name)]
    public class V2SyncUnmappedStatusSummaryTests
    {
        private static OrderReportEntryV2 Row(string id, string orderStatus, string certificateStatus) =>
            new OrderReportEntryV2
            {
                OrderNumber = id, OrderStatus = orderStatus, CertificateStatus = certificateStatus,
                DomainName = "example.com", ProductCode = "842",
                OrderDate = System.DateTime.UtcNow.AddHours(-1).ToString("o")
            };

        private static async IAsyncEnumerable<OrderReportEntryV2> Rows(params OrderReportEntryV2[] rows)
        {
            foreach (var r in rows) yield return r;
            await Task.CompletedTask;
        }

        [Fact]
        public async Task Summary_ListsEachUnmappedPairWithCount_AndUntrackableCount()
        {
            using var capture = new PluginLogCapture();
            var mock = new Mock<ICERTInextClient>();
            mock.Setup(c => c.ListOrdersV2Async(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(Rows(
                    Row("a1", "On Hold", "Setup Pending"),
                    Row("a2", "On Hold", "Setup Pending"),
                    Row("b1", "Brand New", "Never Seen"),
                    Row("c1", "Order Fulfilled", "Certificate Downloaded")));
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(It.Is<string>(id => id.StartsWith("a")), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new KeyNotFoundException("not found in any product family"));
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync("b1", It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse { OrderId = "b1", Status = "cancelled" }));
            mock.Setup(c => c.ResolveAndDownloadCertificateV2Async("c1", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CertificateDownloadResponse { OrderId = "c1", SerialNumber = "AA", CertificatePem = MockCertificateData.FakePemCertificate });
            var config = new CERTInextConfig { UseV2Api = true, ApiUrl = "https://v2.certinext.io", OAuthClientId = "id", OAuthClientSecret = "s" };
            var plugin = new CERTInextCAPlugin(mock.Object, config);

            await plugin.Synchronize(new BlockingCollection<AnyCAPluginCertificate>(10), null, true, CancellationToken.None);

            var summary = capture.Lines(LogLevel.Information, "synchronization complete").Should().ContainSingle().Subject;
            summary.Should().Contain("UnresolvedStatusFallbacks=3")
                .And.Contain("UnmappedReportStatuses=[Brand New | Never Seen (1); On Hold | Setup Pending (2)]")
                .And.Contain("UntrackableListedOrders=2")
                .And.Contain("Errors=0");
        }
    }
}
