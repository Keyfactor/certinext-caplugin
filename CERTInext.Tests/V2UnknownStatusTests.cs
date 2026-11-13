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
    /// Tests for the `unknown` status: the V2 spec lists `unknown` among its documented order
    /// statuses, and <c>StatusMapper.V2StatusToRequestDisposition</c> maps it to
    /// EXTERNALVALIDATION (not FAILED), since the order may still be live; these tests cover the enroll and single-record callers end to end.
    /// </summary>
    public class V2UnknownStatusTests
    {
        private const string OrderId = "ord_unknown_001";

        private static CERTInextConfig V2Config() => new CERTInextConfig
        {
            UseV2Api          = true,
            ApiUrl            = "https://v2.certinext.io",
            OAuthClientId     = "my-client",
            OAuthClientSecret = "my-secret",
            RequestorName     = "Test User",
            RequestorEmail    = "test@example.com",
            SignerIp          = "1.2.3.4",
            SignerPlace       = "New York",
            PickupRetries     = 0
        };

        [Fact]
        public async Task Enroll_V2_PostCsrStatusUnknown_ReturnsPendingWithOrderId()
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true }
                });
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = OrderId, Status = "pending-csr" });
            mock.Setup(c => c.SubmitCsrV2Async(It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "unknown" });

            var plugin = new CERTInextCAPlugin(mock.Object, V2Config());
            var productInfo = new EnrollmentProductInfo
            {
                ProductID = Constants.Products.DvSsl,
                ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ProductCode"]    = "842",
                    ["ProductFamily"]  = "ssl",
                    ["ProductVariant"] = "dv",
                    ["DomainName"]     = "example.com"
                }
            };

            var result = await plugin.Enroll(
                MockCertificateData.FakeCsrPem, "CN=example.com", new Dictionary<string, string[]>(),
                productInfo, RequestFormat.PKCS10, EnrollmentType.New);

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION,
                "a spec-documented `unknown` order may still be live and must not be reported as FAILED");
            result.CARequestID.Should().Be(OrderId);
        }

        [Fact]
        public async Task GetSingleRecord_V2_StatusUnknown_ReturnsPendingRecord()
        {
            var mock = new Mock<ICERTInextClient>(); // Loose: only the resolve/track result matters
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse { OrderId = OrderId, Status = "unknown" }));

            var plugin = new CERTInextCAPlugin(mock.Object, V2Config());
            var record = await plugin.GetSingleRecord(OrderId);

            record.CARequestID.Should().Be(OrderId);
            record.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            mock.Verify(c => c.ResolveAndDownloadCertificateV2Async(It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Never, "a pending order has no certificate to download");
        }
    }
}
