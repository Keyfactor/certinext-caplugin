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

using System.Collections.Concurrent;
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
    /// Moq-based unit tests that verify V2 dispatch in <see cref="CERTInextCAPlugin"/>.
    /// All V2 client methods are mocked — no network calls are made.
    /// </summary>
    public class CERTInextCAPluginV2Tests
    {
        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

        private static Mock<ICERTInextClient> NewMock() =>
            new Mock<ICERTInextClient>(MockBehavior.Strict);

        private static CERTInextCAPlugin BuildV2Plugin(ICERTInextClient client) =>
            new CERTInextCAPlugin(client, new CERTInextConfig
            {
                UseV2Api        = true,
                ApiUrlV2        = "https://v2.certinext.io",
                ClientId        = "my-client",
                ClientSecret    = "my-secret",
                ApiUrl          = "https://v1.certinext.io",
                AccountNumber   = "12345",
                AuthMode        = "AccessKey",
                ApiKey          = "v1-key",
                RequestorName   = "Test User",
                RequestorEmail  = "test@example.com",
                SignerIp        = "1.2.3.4",
                SignerPlace     = "New York",
                PickupRetries   = 0
            });

        private static EnrollmentProductInfo MakeV2ProductInfo(
            string productCode = "842",
            string productFamily = "ssl",
            string productVariant = "dv",
            string domainName = "example.com")
        {
            return new EnrollmentProductInfo
            {
                ProductID = "DV SSL",
                ProductParameters = new Dictionary<string, string>(System.StringComparer.OrdinalIgnoreCase)
                {
                    ["ProductCode"]    = productCode,
                    ["ProductFamily"]  = productFamily,
                    ["ProductVariant"] = productVariant,
                    ["DomainName"]     = domainName
                }
            };
        }

        // ---------------------------------------------------------------------------
        // Ping routes to V2
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Ping_V2Enabled_CallsPingV2Async()
        {
            var mock = NewMock();
            mock.Setup(c => c.PingV2Async(It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            var plugin = BuildV2Plugin(mock.Object);
            await plugin.Ping();

            mock.Verify(c => c.PingV2Async(It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task Ping_V2Enabled_DoesNotCallV1Ping()
        {
            var mock = new Mock<ICERTInextClient>(); // Loose — verifying absence
            mock.Setup(c => c.PingV2Async(It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            var plugin = BuildV2Plugin(mock.Object);
            await plugin.Ping();

            mock.Verify(c => c.PingAsync(It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // Enroll routes to V2
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_V2Enabled_PlacesV2Order_PendingResult()
        {
            var mock = NewMock();
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CreateOrderResponse
                {
                    OrderId   = MockCertificateData.V2OrderId1,
                    RequestId = "req_001",
                    Status    = "pending-dcv"
                });

            var plugin = BuildV2Plugin(mock.Object);
            var result = await plugin.Enroll(
                MockCertificateData.FakeCsrPem,
                "CN=example.com, O=Acme",
                new Dictionary<string, string[]>(),
                MakeV2ProductInfo(),
                RequestFormat.PKCS10,
                EnrollmentType.New);

            result.CARequestID.Should().Be(MockCertificateData.V2OrderId1);
            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
        }

        [Fact]
        public async Task Enroll_V2Enabled_IssuedImmediately_DownloadsCert()
        {
            var mock = NewMock();
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CreateOrderResponse
                {
                    OrderId = MockCertificateData.V2OrderId1,
                    Status  = "issued"
                });

            mock.Setup(c => c.DownloadCertificateV2Async(
                    It.IsAny<string>(), MockCertificateData.V2OrderId1, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CertificateDownloadResponse
                {
                    OrderId        = MockCertificateData.V2OrderId1,
                    SerialNumber   = "AABBCC",
                    CertificatePem = MockCertificateData.FakePemCertificate
                });

            var plugin = BuildV2Plugin(mock.Object);
            var result = await plugin.Enroll(
                MockCertificateData.FakeCsrPem,
                "CN=example.com, O=Acme",
                new Dictionary<string, string[]>(),
                MakeV2ProductInfo(),
                RequestFormat.PKCS10,
                EnrollmentType.New);

            result.CARequestID.Should().Be(MockCertificateData.V2OrderId1);
            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            result.Certificate.Should().StartWith("-----BEGIN CERTIFICATE-----");
        }

        [Fact]
        public async Task Enroll_V2Enabled_RenewOrReissue_AlsoUsesV2()
        {
            var mock = NewMock();
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CreateOrderResponse
                {
                    OrderId = MockCertificateData.V2OrderId2,
                    Status  = "pending-csr"
                });

            var plugin = BuildV2Plugin(mock.Object);
            var result = await plugin.Enroll(
                MockCertificateData.FakeCsrPem,
                "CN=example.com, O=Acme",
                new Dictionary<string, string[]>(),
                MakeV2ProductInfo(),
                RequestFormat.PKCS10,
                EnrollmentType.RenewOrReissue);

            result.CARequestID.Should().Be(MockCertificateData.V2OrderId2);
            mock.Verify(c => c.PlaceOrderV2Async(
                It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()), Times.Once);
        }

        // ---------------------------------------------------------------------------
        // GetSingleRecord routes to V2
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task GetSingleRecord_V2Enabled_UsesResolveAndTrack()
        {
            var mock = NewMock();
            mock.Setup(c => c.ResolveAndTrackOrderV2Async(
                    MockCertificateData.V2OrderId1, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse
                {
                    OrderId  = MockCertificateData.V2OrderId1,
                    Status   = "issued",
                    ProductVariant = "dv"
                });

            mock.Setup(c => c.ResolveAndDownloadCertificateV2Async(
                    MockCertificateData.V2OrderId1, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CertificateDownloadResponse
                {
                    OrderId        = MockCertificateData.V2OrderId1,
                    SerialNumber   = "AABB",
                    CertificatePem = MockCertificateData.FakePemCertificate
                });

            var plugin = BuildV2Plugin(mock.Object);
            var record = await plugin.GetSingleRecord(MockCertificateData.V2OrderId1);

            record.CARequestID.Should().Be(MockCertificateData.V2OrderId1);
            record.Status.Should().Be((int)EndEntityStatus.GENERATED);
            record.Certificate.Should().StartWith("-----BEGIN CERTIFICATE-----");

            mock.Verify(c => c.ResolveAndTrackOrderV2Async(
                MockCertificateData.V2OrderId1, It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task GetSingleRecord_V2Enabled_DoesNotCallV1GetCertificate()
        {
            var mock = new Mock<ICERTInextClient>(); // Loose
            mock.Setup(c => c.ResolveAndTrackOrderV2Async(
                    It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = "ord_x", Status = "pending-dcv" });

            var plugin = BuildV2Plugin(mock.Object);
            await plugin.GetSingleRecord("ord_x");

            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // Revoke routes to V2
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Revoke_V2Enabled_ResolvesAndRevokes()
        {
            var mock = new Mock<ICERTInextClient>(); // Loose
            mock.Setup(c => c.ResolveAndTrackOrderV2Async(
                    MockCertificateData.V2OrderId1, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse
                {
                    OrderId = MockCertificateData.V2OrderId1,
                    Status  = "issued"
                });

            mock.Setup(c => c.RevokeOrderV2Async(
                    It.IsAny<string>(), MockCertificateData.V2OrderId1,
                    It.IsAny<V2RevokeRequest>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            var plugin = BuildV2Plugin(mock.Object);
            var status = await plugin.Revoke(MockCertificateData.V2OrderId1, "AABB", 4u);

            status.Should().Be((int)EndEntityStatus.REVOKED);
        }

        [Fact]
        public async Task Revoke_V2Enabled_DoesNotCallV1RevokeCertificate()
        {
            var mock = new Mock<ICERTInextClient>();
            mock.Setup(c => c.ResolveAndTrackOrderV2Async(
                    It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { Status = "issued", OrderId = "ord_x" });

            mock.Setup(c => c.RevokeOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2RevokeRequest>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            var plugin = BuildV2Plugin(mock.Object);
            await plugin.Revoke("ord_x", "AA", 1u);

            mock.Verify(c => c.RevokeCertificateAsync(
                It.IsAny<string>(), It.IsAny<RevokeCertificateRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // Synchronize still uses V1
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Synchronize_V2Enabled_StillCallsV1ListCertificatesAsync()
        {
            var mock = new Mock<ICERTInextClient>();

            // V1 sync path uses ListCertificatesAsync (the legacy wrapper)
            mock.Setup(c => c.ListCertificatesAsync(
                    It.IsAny<System.DateTime?>(),
                    It.IsAny<int>(),
                    It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable<LegacyGetCertificateResponse>());

            var plugin = BuildV2Plugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);
            buffer.CompleteAdding();

            // Run sync — should not throw
            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            mock.Verify(c => c.ListCertificatesAsync(
                It.IsAny<System.DateTime?>(),
                It.IsAny<int>(),
                It.IsAny<CancellationToken>()), Times.AtLeastOnce);
        }

        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

        private static async IAsyncEnumerable<T> AsyncEnumerable<T>(params T[] items)
        {
            foreach (var item in items)
                yield return item;
            await Task.CompletedTask;
        }
    }
}
