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
using System.Linq;
using System.Text.Json;
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
    /// Issue 0039: when <c>SubmitCsrV2Async</c> throws after the V2 order was placed, the order
    /// sits at <c>pending-csr</c> and Command never learns its ID. <c>EnrollV2Async</c> must make
    /// exactly one best-effort <c>CancelOrderV2Async</c> call for that order's family and return
    /// FAILED with the orderId — never throwing, never retrying.
    /// </summary>
    public class V2OrphanedOrderCancelTests
    {
        private const string OrderId = "ord_orphan_001";
        private const string CsrFailureText = "CERTInext V2 API error during 'V2 submit CSR'. HTTP 400. CSR rejected.";

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

        private static EnrollmentProductInfo PrivatePkiProductInfo() => new EnrollmentProductInfo
        {
            ProductID = Constants.Products.DvSsl,
            ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ProductFamily"]  = "private-pki",
                ["ProductVariant"] = "intranet-ssl",
                ["ProductCode"]    = "149",
                ["DomainName"]     = "intranet.acme.local"
            }
        };

        /// <summary>Strict mock that places an order in <paramref name="family"/>.</summary>
        private static Mock<ICERTInextClient> MockPlacingOrder(string family)
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            if (family == Constants.ApiV2.FamilyPrivatePki)
            {
                mock.Setup(c => c.PlaceOrderV2Async(
                        It.IsAny<string>(), It.IsAny<V2CreatePrivatePkiOrderRequest>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new V2CreateOrderResponse { OrderId = OrderId, Status = "pending-csr" });
            }
            else
            {
                mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new List<ProductDetail>
                    {
                        new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true }
                    });
                mock.Setup(c => c.PlaceOrderV2Async(
                        It.IsAny<string>(), It.IsAny<string>(), It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new V2CreateOrderResponse { OrderId = OrderId, Status = "pending-csr" });
            }
            return mock;
        }

        private static void SubmitCsrThrows(Mock<ICERTInextClient> mock, string family) =>
            mock.Setup(c => c.SubmitCsrV2Async(family, OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception(CsrFailureText));

        private static Task<EnrollmentResult> EnrollAsync(ICERTInextClient client, EnrollmentProductInfo productInfo) =>
            new CERTInextCAPlugin(client, BaseConfig()).Enroll(
                csr:            MockCertificateData.FakeCsrPem,
                subject:        "CN=example.com",
                san:            new Dictionary<string, string[]>(),
                productInfo:    productInfo,
                requestFormat:  RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

        // ---------------------------------------------------------------------------
        // Plugin: EnrollV2Async
        // ---------------------------------------------------------------------------

        public static IEnumerable<object[]> Families() => new[]
        {
            new object[] { Constants.ApiV2.FamilySsl },
            new object[] { Constants.ApiV2.FamilyPrivatePki }
        };

        private static EnrollmentProductInfo ProductInfoFor(string family) =>
            family == Constants.ApiV2.FamilyPrivatePki ? PrivatePkiProductInfo() : SslProductInfo();

        [Theory]
        [MemberData(nameof(Families))]
        public async Task Enroll_SubmitCsrThrows_CancelsOnceInSameFamily_ReturnsFailedWithOrderId(string family)
        {
            var mock = MockPlacingOrder(family);
            SubmitCsrThrows(mock, family);
            mock.Setup(c => c.CancelOrderV2Async(family, OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(V2CancelOrderOutcome.Cancelled);

            var result = await EnrollAsync(mock.Object, ProductInfoFor(family));

            result.Status.Should().Be((int)EndEntityStatus.FAILED);
            result.CARequestID.Should().Be(OrderId);
            result.Certificate.Should().BeNull();
            result.StatusMessage.Should().Contain("CSR submission failed")
                .And.Contain("CSR rejected")
                .And.Contain("The orphaned order was cancelled.");

            mock.Verify(c => c.CancelOrderV2Async(
                family, OrderId, CERTInextCAPlugin.OrphanedOrderCancelReason, It.IsAny<CancellationToken>()), Times.Once);
            mock.Verify(c => c.CancelOrderV2Async(
                It.Is<string>(f => f != family), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            mock.Verify(c => c.SubmitCsrV2Async(family, OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Once, "the CSR submit is never retried");
            // Strict mock: no TrackOrderV2Async / DownloadCertificateV2Async setup, so any
            // post-CSR call would have thrown out of Enroll.
        }

        [Fact]
        public void OrphanedOrderCancelReason_IsNonEmpty_AndCarriesNoExceptionDetail()
        {
            CERTInextCAPlugin.OrphanedOrderCancelReason.Should().NotBeNullOrWhiteSpace("an empty reason is rejected with EMS-984");
            CERTInextCAPlugin.OrphanedOrderCancelReason.Should().NotContain("CSR rejected");
        }

        [Fact]
        public async Task Enroll_SubmitCsrThrows_CancelReturns422_StillFailed_SaysNotCancelled()
        {
            var mock = MockPlacingOrder(Constants.ApiV2.FamilySsl);
            SubmitCsrThrows(mock, Constants.ApiV2.FamilySsl);
            mock.Setup(c => c.CancelOrderV2Async(Constants.ApiV2.FamilySsl, OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(V2CancelOrderOutcome.AlreadyTerminal);

            var result = await EnrollAsync(mock.Object, SslProductInfo());

            result.Status.Should().Be((int)EndEntityStatus.FAILED);
            result.CARequestID.Should().Be(OrderId);
            result.StatusMessage.Should().Contain("NOT cancelled").And.Contain("422");
            result.StatusMessage.Should().NotContain("The orphaned order was cancelled.");
            mock.Verify(c => c.CancelOrderV2Async(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
        }

        [Theory]
        [MemberData(nameof(Families))]
        public async Task Enroll_SubmitCsrThrows_CancelThrows_StillFailed_DoesNotThrow_NoRetry(string family)
        {
            var mock = MockPlacingOrder(family);
            SubmitCsrThrows(mock, family);
            mock.Setup(c => c.CancelOrderV2Async(family, OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("CERTInext V2 API error during 'V2 cancel order'. HTTP 500."));

            EnrollmentResult result = null;
            Func<Task> act = async () => result = await EnrollAsync(mock.Object, ProductInfoFor(family));
            await act.Should().NotThrowAsync();

            result.Should().NotBeNull();
            result!.Status.Should().Be((int)EndEntityStatus.FAILED);
            result.CARequestID.Should().Be(OrderId);
            result.StatusMessage.Should().Contain("CSR submission failed")
                .And.Contain("NOT cancelled")
                .And.Contain("Cancel it manually");
            mock.Verify(c => c.CancelOrderV2Async(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Once, "the cancel is best-effort and never retried");
        }

        [Theory]
        [MemberData(nameof(Families))]
        public async Task Enroll_SubmitCsrSucceeds_NeverCancels(string family)
        {
            var mock = MockPlacingOrder(family);
            mock.Setup(c => c.SubmitCsrV2Async(family, OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.TrackOrderV2Async(family, OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "pending-approval" });

            var result = await EnrollAsync(mock.Object, ProductInfoFor(family));

            result.CARequestID.Should().Be(OrderId);
            result.Status.Should().NotBe((int)EndEntityStatus.FAILED);
            mock.Verify(c => c.CancelOrderV2Async(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }

    /// <summary>
    /// WireMock coverage for <see cref="CERTInextClient.CancelOrderV2Async"/> (issue 0039): spec
    /// "Cancel Order" is <c>POST /api/certinext/v2/{family}/:orderId/cancel</c> with body
    /// <c>{ "reason": ... }</c>; 204 = cancelled, 422 = already in a terminal state.
    /// </summary>
    public class CERTInextClientCancelOrderV2Tests : IDisposable
    {
        private const string OrderId = "ord_cancel_001";
        private readonly WireMockServer _server;

        public CERTInextClientCancelOrderV2Tests()
        {
            _server = WireMockServer.Start();
            _server
                .Given(Request.Create().WithPath("/oauth/token").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2TokenResponseJson(3600)));
        }

        public void Dispose() => _server.Stop();

        private CERTInextClient BuildClient() => new CERTInextClient(new CERTInextConfig
        {
            ApiUrl            = _server.Urls[0],
            AuthMode          = "AccessKey",
            ApiKey            = "test-v1-key",
            AccountNumber     = "12345",
            UseV2Api          = true,
            OAuthClientId     = "my-v2-client",
            OAuthClientSecret = "my-v2-secret",
            RequestorName     = "Test User",
            RequestorEmail    = "test@example.com",
            PageSize          = 100,
            GroupNumber       = string.Empty
        });

        [Theory]
        [InlineData(Constants.ApiV2.FamilySsl, Constants.ApiV2.SslCertificatesPath)]
        [InlineData(Constants.ApiV2.FamilyPrivatePki, Constants.ApiV2.PrivatePkiCertificatesPath)]
        [InlineData(Constants.ApiV2.FamilySignature, Constants.ApiV2.SignatureCertificatesPath)]
        public async Task CancelOrderV2Async_204_PostsReasonToFamilyPath_ReturnsCancelled(string family, string familyPath)
        {
            string path = $"{familyPath}/{OrderId}/cancel";
            _server
                .Given(Request.Create().WithPath(path).UsingPost())
                .RespondWith(Response.Create().WithStatusCode(204));

            using var client = BuildClient();
            var outcome = await client.CancelOrderV2Async(family, OrderId, "Keyfactor test reason.");

            outcome.Should().Be(V2CancelOrderOutcome.Cancelled);
            var entry = _server.LogEntries.Single(e => e.RequestMessage.Path == path);
            entry.RequestMessage.Method.Should().Be("POST");
            using var body = JsonDocument.Parse(entry.RequestMessage.Body ?? "{}");
            body.RootElement.GetProperty("reason").GetString().Should().Be("Keyfactor test reason.");
            entry.RequestMessage.Headers.Should().ContainKey("Idempotency-Key");
        }

        [Fact]
        public async Task CancelOrderV2Async_422_ReturnsAlreadyTerminal_DoesNotThrow()
        {
            _server
                .Given(Request.Create().WithPath($"{Constants.ApiV2.SslCertificatesPath}/{OrderId}/cancel").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(422)
                    .WithHeader("Content-Type", "application/problem+json")
                    .WithBody(MockCertificateData.V2ProblemDetailsJson(
                        422, "Unprocessable Entity", "Order is already issued; use POST /{orderId}/revoke instead of /cancel.")));

            using var client = BuildClient();
            var outcome = await client.CancelOrderV2Async(Constants.ApiV2.FamilySsl, OrderId, "reason");

            outcome.Should().Be(V2CancelOrderOutcome.AlreadyTerminal);
        }

        [Fact]
        public async Task CancelOrderV2Async_500_Throws()
        {
            _server
                .Given(Request.Create().WithPath($"{Constants.ApiV2.SslCertificatesPath}/{OrderId}/cancel").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(500));

            using var client = BuildClient();
            await Assert.ThrowsAsync<Exception>(
                () => client.CancelOrderV2Async(Constants.ApiV2.FamilySsl, OrderId, "reason"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public async Task CancelOrderV2Async_BlankReason_ThrowsBeforeAnyHttpCall(string reason)
        {
            using var client = BuildClient();
            await Assert.ThrowsAsync<ArgumentException>(
                () => client.CancelOrderV2Async(Constants.ApiV2.FamilySsl, OrderId, reason));
            _server.LogEntries.Should().BeEmpty();
        }
    }
}
