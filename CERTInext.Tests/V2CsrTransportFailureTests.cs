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
using System.Net.Http;
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
    /// A transport-level failure or timeout from <c>SubmitCsrV2Async</c> does
    /// not tell <see cref="CERTInextCAPlugin.EnrollV2Async"/> whether CERTInext actually received
    /// the CSR — only that no successful response was seen. Cancelling unconditionally (as is done for a *definitive* CA rejection, covered in
    /// <c>V2OrphanedOrderCancelTests</c>) can orphan an order the CA genuinely accepted.
    ///
    /// Covers the three ambiguous-failure branches: still pending-csr after tracking (cancel), progressed past pending-csr (continue the normal flow, no cancel), and tracking
    /// itself failing (return pending without cancelling). Also pins the pure classification logic
    /// in <see cref="CERTInextCAPlugin.IsTransportLevelCsrFailure"/>.
    /// </summary>
    public class V2CsrTransportFailureTests
    {
        private const string OrderId = "ord_transport_001";
        private const string Family = Constants.ApiV2.FamilySsl;

        // Mirrors ThrowOnV2Failure's generic fallback shape for a response that never arrived
        // (RestSharp's ThrowOnAnyError=false swallows the transport failure into a non-successful
        // response with the default HttpStatusCode, which is 0).
        private const string TransportFailureText =
            "CERTInext V2 API error during 'V2 submit CSR'. HTTP 0. See gateway logs for raw response.";

        private static CERTInextConfig BaseConfig() => new CERTInextConfig
        {
            UseV2Api          = true,
            ApiUrl            = "https://v2.certinext.io",
            OAuthClientId     = "my-client",
            OAuthClientSecret = "my-secret",
            RequestorName     = "DevOps Team",
            RequestorEmail    = "devops@acme.com",
            RequestorIsdCode  = "1",
            RequestorMobileNumber = "4155551234",
            SignerIp          = "1.2.3.4",
            SignerPlace       = "New York",
            PickupRetries     = 0
        };

        private static EnrollmentProductInfo SslProductInfo() => new EnrollmentProductInfo
        {
            ProductID = "DV SSL",
            ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ProductCode"]    = "842",
                ["ProductFamily"]  = "ssl",
                ["ProductVariant"] = "dv",
                ["DomainName"]     = "example.com"
            }
        };

        private static Mock<ICERTInextClient> MockPlacingOrder()
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
            return mock;
        }

        private static Task<EnrollmentResult> EnrollAsync(ICERTInextClient client) =>
            new CERTInextCAPlugin(client, BaseConfig()).Enroll(
                csr:            MockCertificateData.FakeCsrPem,
                subject:        "CN=example.com",
                san:            new Dictionary<string, string[]>(),
                productInfo:    SslProductInfo(),
                requestFormat:  RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

        // ---------------------------------------------------------------------------
        // Still pending-csr after tracking -> cancel (same outcome as a definitive rejection).
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task TransportFailure_StillPendingCsrAfterTracking_Cancels_ReturnsFailed()
        {
            var mock = MockPlacingOrder();
            mock.Setup(c => c.SubmitCsrV2Async(Family, OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception(TransportFailureText));
            mock.Setup(c => c.TrackOrderV2Async(Family, OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = Constants.ApiV2.StatusPendingCsr });
            mock.Setup(c => c.CancelOrderV2Async(Family, OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(V2CancelOrderOutcome.Cancelled);

            var result = await EnrollAsync(mock.Object);

            result.Status.Should().Be((int)EndEntityStatus.FAILED);
            result.CARequestID.Should().Be(OrderId);
            result.StatusMessage.Should().Contain("The orphaned order was cancelled.");
            mock.Verify(c => c.TrackOrderV2Async(Family, OrderId, It.IsAny<CancellationToken>()), Times.Once);
            mock.Verify(c => c.CancelOrderV2Async(
                Family, OrderId, CERTInextCAPlugin.OrphanedOrderCancelReason, It.IsAny<CancellationToken>()), Times.Once);
            mock.Verify(c => c.SubmitCsrV2Async(Family, OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Once, "the CSR submit is never retried");
        }

        // ---------------------------------------------------------------------------
        // Progressed past pending-csr -> continue the normal flow, do not cancel a valid order.
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task TransportFailure_ProgressedPastPendingCsr_DoesNotCancel_ContinuesNormalFlow()
        {
            var mock = MockPlacingOrder();
            mock.Setup(c => c.SubmitCsrV2Async(Family, OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception(TransportFailureText));
            // CERTInext actually received the CSR despite the transport error on our side — the
            // order has already moved on to pending-approval.
            mock.Setup(c => c.TrackOrderV2Async(Family, OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = Constants.ApiV2.StatusPendingApproval });

            var result = await EnrollAsync(mock.Object);

            result.Status.Should().NotBe((int)EndEntityStatus.FAILED,
                "the CSR was actually accepted — this must not be reported as a failed enrollment");
            result.CARequestID.Should().Be(OrderId);
            mock.Verify(c => c.CancelOrderV2Async(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            mock.Verify(c => c.TrackOrderV2Async(Family, OrderId, It.IsAny<CancellationToken>()), Times.Once);
            mock.Verify(c => c.SubmitCsrV2Async(Family, OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Once, "the CSR submit is never retried");
        }

        // ---------------------------------------------------------------------------
        // Tracking itself fails -> don't cancel; return pending with the known orderId.
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task TransportFailure_TrackingAlsoFails_DoesNotCancel_ReturnsPendingWithOrderId()
        {
            var mock = MockPlacingOrder();
            mock.Setup(c => c.SubmitCsrV2Async(Family, OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception(TransportFailureText));
            mock.Setup(c => c.TrackOrderV2Async(Family, OrderId, It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("CERTInext V2 API error during 'V2 track order'. HTTP 0. See gateway logs for raw response."));

            var result = await EnrollAsync(mock.Object);

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            result.CARequestID.Should().Be(OrderId);
            result.Certificate.Should().BeNull();
            result.StatusMessage.Should().Contain("sync will resolve");
            mock.Verify(c => c.CancelOrderV2Async(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // Pure classification logic.
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData("CERTInext V2 API error during 'V2 submit CSR'. HTTP 0. See gateway logs for raw response.", true)]
        [InlineData("CERTInext V2 API error during 'V2 submit CSR'. HTTP 503. Service unavailable.", true)]
        [InlineData("Some unrecognized failure shape with no HTTP status at all.", true)]
        [InlineData("CERTInext V2 API error during 'V2 submit CSR'. HTTP 400. CSR rejected.", false)]
        [InlineData("CERTInext V2 API error during 'V2 submit CSR'. HTTP 404. Order not found.", false)]
        [InlineData("CERTInext V2 API error during 'V2 submit CSR'. HTTP 499. Client closed request.", false)]
        public void IsTransportLevelCsrFailure_ClassifiesByParsedHttpStatus(string message, bool expectedTransportLevel)
        {
            CERTInextCAPlugin.IsTransportLevelCsrFailure(new Exception(message)).Should().Be(expectedTransportLevel);
        }

        [Fact]
        public void IsTransportLevelCsrFailure_OperationCanceledException_IsTransportLevel()
        {
            CERTInextCAPlugin.IsTransportLevelCsrFailure(new OperationCanceledException()).Should().BeTrue();
        }

        [Fact]
        public void IsTransportLevelCsrFailure_HttpRequestException_IsTransportLevel()
        {
            CERTInextCAPlugin.IsTransportLevelCsrFailure(new HttpRequestException("connection refused")).Should().BeTrue();
        }

        [Fact]
        public void IsTransportLevelCsrFailure_TimeoutException_IsTransportLevel()
        {
            CERTInextCAPlugin.IsTransportLevelCsrFailure(new TimeoutException()).Should().BeTrue();
        }
    }
}
