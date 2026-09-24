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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.Extensions.CAPlugin.CERTInext;
using Keyfactor.PKI.Enums.EJBCA;
using Moq;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
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
                ApiUrl          = "https://v2.certinext.io",
                OAuthClientId     = "my-client",
                OAuthClientSecret = "my-secret",
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

            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), MockCertificateData.V2OrderId1,
                    It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.TrackOrderV2Async(
                    It.IsAny<string>(), MockCertificateData.V2OrderId1, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = MockCertificateData.V2OrderId1, Status = "pending-dcv" });

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

            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), MockCertificateData.V2OrderId1,
                    It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.TrackOrderV2Async(
                    It.IsAny<string>(), MockCertificateData.V2OrderId1, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = MockCertificateData.V2OrderId1, Status = "issued" });

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

            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), MockCertificateData.V2OrderId2,
                    It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.TrackOrderV2Async(
                    It.IsAny<string>(), MockCertificateData.V2OrderId2, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = MockCertificateData.V2OrderId2, Status = "pending-validation" });

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
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                    MockCertificateData.V2OrderId1, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse
                {
                    OrderId  = MockCertificateData.V2OrderId1,
                    Status   = "issued",
                    ProductVariant = "dv"
                }));

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

            mock.Verify(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                MockCertificateData.V2OrderId1, It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task GetSingleRecord_V2Enabled_DoesNotCallV1GetCertificate()
        {
            var mock = new Mock<ICERTInextClient>(); // Loose
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                    It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse { OrderId = "ord_x", Status = "pending-dcv" }));

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
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                    MockCertificateData.V2OrderId1, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse
                {
                    OrderId = MockCertificateData.V2OrderId1,
                    Status  = "issued"
                }));

            mock.Setup(c => c.RevokeOrderV2Async(
                    Constants.ApiV2.FamilySsl, MockCertificateData.V2OrderId1,
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
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                    It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse { Status = "issued", OrderId = "ord_x" }));

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
        // Regression (issues/0019): revoke 404 after the family is already resolved
        // must not be reported as a family miss.
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Revoke_V2Enabled_RevokeReturns404AfterFamilyResolved_ReportsNotRevokable_NotFamilyMiss()
        {
            var mock = new Mock<ICERTInextClient>(); // Loose
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                    MockCertificateData.V2OrderId1, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse
                {
                    OrderId = MockCertificateData.V2OrderId1,
                    Status  = "issued"
                }));

            // Order is confirmed to live in the SSL family (TrackOrder above succeeded),
            // but the revoke call itself 404s — per spec that means "not revokable",
            // not "wrong family". The plugin must not retry other families for it.
            mock.Setup(c => c.RevokeOrderV2Async(
                    Constants.ApiV2.FamilySsl, MockCertificateData.V2OrderId1,
                    It.IsAny<V2RevokeRequest>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new KeyNotFoundException(
                    $"V2 order '{MockCertificateData.V2OrderId1}' in family '{Constants.ApiV2.FamilySsl}' " +
                    "not found or not in a revokable state."));

            var plugin = BuildV2Plugin(mock.Object);
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(
                () => plugin.Revoke(MockCertificateData.V2OrderId1, "AABB", 4u));

            ex.Message.Should().Contain("not found or not in a revokable state");
            ex.Message.Should().NotContain("any product family",
                "a 404 after the family was already resolved must not be mislabeled as a family miss");

            // Must not have probed the other two families.
            mock.Verify(c => c.RevokeOrderV2Async(
                Constants.ApiV2.FamilyPrivatePki, It.IsAny<string>(),
                It.IsAny<V2RevokeRequest>(), It.IsAny<CancellationToken>()), Times.Never);
            mock.Verify(c => c.RevokeOrderV2Async(
                Constants.ApiV2.FamilySignature, It.IsAny<string>(),
                It.IsAny<V2RevokeRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // Synchronize (V2, issues/0022) — uses V2 /reports/orders, not V1 GetOrderReport.
        // ---------------------------------------------------------------------------

        private static OrderReportEntryV2 ReportRow(
            string orderNumber, string orderStatus, string certificateStatus,
            string domainName = "example.com", string productCode = "842") =>
            new OrderReportEntryV2
            {
                OrderNumber       = orderNumber,
                OrderStatus       = orderStatus,
                CertificateStatus = certificateStatus,
                DomainName        = domainName,
                ProductCode       = productCode,
                OrderDate         = System.DateTime.UtcNow.AddHours(-1).ToString("o")
            };

        [Fact]
        public async Task Synchronize_V2Enabled_UsesListOrdersV2Async_NotV1ListCertificates()
        {
            var mock = new Mock<ICERTInextClient>();

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable<OrderReportEntryV2>());

            var plugin = BuildV2Plugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            mock.Verify(c => c.ListOrdersV2Async(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()), Times.AtLeastOnce);
            mock.Verify(c => c.ListCertificatesAsync(
                It.IsAny<System.DateTime?>(), It.IsAny<int>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Synchronize_V2Enabled_IssuedRow_DownloadsCertificateBody()
        {
            var mock = new Mock<ICERTInextClient>();
            var row = ReportRow("ord_v2sync_001", "Order Fulfilled", "Certificate Downloaded");

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            mock.Setup(c => c.ResolveAndDownloadCertificateV2Async("ord_v2sync_001", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CertificateDownloadResponse
                {
                    OrderId        = "ord_v2sync_001",
                    SerialNumber   = "AABBCC",
                    CertificatePem = MockCertificateData.FakePemCertificate
                });

            var plugin = BuildV2Plugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            var records = buffer.ToArray();
            records.Should().ContainSingle();
            records[0].CARequestID.Should().Be("ord_v2sync_001");
            records[0].Status.Should().Be((int)EndEntityStatus.GENERATED);
            records[0].Certificate.Should().StartWith("-----BEGIN CERTIFICATE-----");
            records[0].ProductID.Should().Be("842");

            // Recognised report-status strings must not need a live track fallback.
            mock.Verify(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Synchronize_V2Enabled_UnrecognizedStatus_FallsBackToLiveTrack()
        {
            var mock = new Mock<ICERTInextClient>();
            // "Something New" is deliberately not in the known display-string vocabulary
            // (issues/0022 — the vocabulary is not confirmed exhaustive).
            var row = ReportRow("ord_v2sync_002", "Something New", "Also New");

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync("ord_v2sync_002", It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse
                {
                    OrderId = "ord_v2sync_002", Status = "issued", Domain = "example.com"
                }));

            mock.Setup(c => c.ResolveAndDownloadCertificateV2Async("ord_v2sync_002", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CertificateDownloadResponse
                {
                    OrderId        = "ord_v2sync_002",
                    CertificatePem = MockCertificateData.FakePemCertificate
                });

            var plugin = BuildV2Plugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            var records = buffer.ToArray();
            records.Should().ContainSingle();
            records[0].Status.Should().Be((int)EndEntityStatus.GENERATED,
                "an unrecognised report status must fall back to the authoritative live track " +
                "call rather than being dropped or guessed");

            mock.Verify(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                "ord_v2sync_002", It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task Synchronize_V2Enabled_RevokedRow_EmittedAsRevoked()
        {
            var mock = new Mock<ICERTInextClient>();
            var row = ReportRow("ord_v2sync_003", "Revoked", "Certificate Revoked");

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            var plugin = BuildV2Plugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            var records = buffer.ToArray();
            records.Should().ContainSingle();
            records[0].Status.Should().Be((int)EndEntityStatus.REVOKED);

            // Revoked rows have no body to download.
            mock.Verify(c => c.ResolveAndDownloadCertificateV2Async(
                It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Synchronize_V2Enabled_TerminalStatus_SkippedNotEmitted()
        {
            var mock = new Mock<ICERTInextClient>();
            var row = ReportRow("ord_v2sync_004", "Order Cancelled", null);

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            var plugin = BuildV2Plugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            buffer.ToArray().Should().BeEmpty("terminal/cancelled orders are skipped, not emitted");
        }

        [Fact]
        public async Task Synchronize_V2Enabled_IncrementalSync_RequestsLookbackWindow()
        {
            var mock = new Mock<ICERTInextClient>();
            string capturedFrom = null;
            var lastSync = new System.DateTime(2026, 6, 15, 12, 0, 0, System.DateTimeKind.Utc);

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, int, CancellationToken>((from, to, size, ct) => capturedFrom = from)
                .Returns(AsyncEnumerable<OrderReportEntryV2>());

            var plugin = BuildV2Plugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, lastSync, fullSync: false, CancellationToken.None);

            // Default lookback is 72h (Constants.ApiV2.DefaultSyncLookbackHours) — the requested
            // 'from' must be lastSync minus that window, not lastSync itself (issues/0022: the
            // from/to filter's order-date-vs-issue-date semantics were not confirmed live).
            var expectedFrom = lastSync.AddHours(-Constants.ApiV2.DefaultSyncLookbackHours).ToString("yyyy-MM-dd");
            capturedFrom.Should().Be(expectedFrom);
        }

        [Fact]
        public async Task Synchronize_V2Enabled_FullSync_RequestsNoFromFilter()
        {
            var mock = new Mock<ICERTInextClient>();
            string capturedFrom = "unset";

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, int, CancellationToken>((from, to, size, ct) => capturedFrom = from)
                .Returns(AsyncEnumerable<OrderReportEntryV2>());

            var plugin = BuildV2Plugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, System.DateTime.UtcNow, fullSync: true, CancellationToken.None);

            capturedFrom.Should().BeNull("a full sync requests the entire order history, not a bounded window");
        }

        // ---------------------------------------------------------------------------
        // Chain PEM assembly — Enroll V2 with chainPem
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_V2_WithChainPem_ConcatenatesLeafAndIntermediate()
        {
            var mock = NewMock();

            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CreateOrderResponse
                {
                    OrderId = "ord_chain_test",
                    Status  = "issued"
                });

            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), "ord_chain_test",
                    It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.TrackOrderV2Async(
                    It.IsAny<string>(), "ord_chain_test", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = "ord_chain_test", Status = "issued" });

            // Download response includes a chain PEM entry
            mock.Setup(c => c.DownloadCertificateV2Async(
                    It.IsAny<string>(), "ord_chain_test", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CertificateDownloadResponse
                {
                    OrderId        = "ord_chain_test",
                    SerialNumber   = "AABBCC",
                    CertificatePem = MockCertificateData.FakePemCertificate,
                    ChainPem       = new System.Collections.Generic.List<string>
                    {
                        MockCertificateData.FakeIntermediatePemCertificate
                    }
                });

            mock.Setup(c => c.Dispose());

            mock.Setup(c => c.Dispose());

            var plugin = BuildV2Plugin(mock.Object);
            var result = await plugin.Enroll(
                MockCertificateData.FakeCsrPem,
                "CN=example.com",
                new Dictionary<string, string[]>(),
                MakeV2ProductInfo(productVariant: "dv"),
                RequestFormat.PKCS10,
                EnrollmentType.New);

            result.CARequestID.Should().Be("ord_chain_test");
            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            // Full chain must contain both leaf and intermediate
            result.Certificate.Should().Contain("-----BEGIN CERTIFICATE-----");
            result.Certificate.Should().Contain("INTERMEDIATE",
                because: "chain PEM from the CA should be appended to the leaf");
        }

        [Fact]
        public async Task Enroll_V2_WithoutChainPem_ReturnsCertificatePemOnly()
        {
            var mock = NewMock();

            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = "ord_nochain", Status = "issued" });

            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), "ord_nochain",
                    It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.TrackOrderV2Async(
                    It.IsAny<string>(), "ord_nochain", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = "ord_nochain", Status = "issued" });

            mock.Setup(c => c.DownloadCertificateV2Async(
                    It.IsAny<string>(), "ord_nochain", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CertificateDownloadResponse
                {
                    OrderId        = "ord_nochain",
                    CertificatePem = MockCertificateData.FakePemCertificate,
                    ChainPem       = null
                });

            mock.Setup(c => c.Dispose());

            var plugin = BuildV2Plugin(mock.Object);
            var result = await plugin.Enroll(
                MockCertificateData.FakeCsrPem,
                "CN=example.com",
                new Dictionary<string, string[]>(),
                MakeV2ProductInfo(productVariant: "dv"),
                RequestFormat.PKCS10,
                EnrollmentType.New);

            result.Certificate.Should().Be(MockCertificateData.FakePemCertificate,
                because: "no chainPem means only the leaf cert is returned");
        }

        // ---------------------------------------------------------------------------
        // ValidateCAConnectionInfo — consolidated config (issues/0022).
        //
        // V2 mode: a single ApiUrl (required in both modes) plus OAuthClientId/OAuthClientSecret.
        // V1-only fields (AccountNumber, AuthMode, ApiKey, ...) are NOT required when UseV2Api
        // is true. ApiUrlV2/ClientId/ClientSecret no longer exist.
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task ValidateCAConnectionInfo_V2_Throws_WhenApiUrlMissing()
        {
            var plugin = BuildV2Plugin(NewMock().Object);
            var info = new Dictionary<string, object>
            {
                ["UseV2Api"] = true,
                ["OAuthClientId"] = "my-client",
                ["OAuthClientSecret"] = "my-secret"
                // No ApiUrl
            };

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*ApiUrl*required*");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_V2_Throws_WhenApiUrlIsNotUri()
        {
            var plugin = BuildV2Plugin(NewMock().Object);
            var info = new Dictionary<string, object>
            {
                ["UseV2Api"] = true,
                ["ApiUrl"] = "not-a-url",
                ["OAuthClientId"] = "my-client",
                ["OAuthClientSecret"] = "my-secret"
            };

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*ApiUrl*valid absolute URI*");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_V2_Throws_WhenOAuthClientIdMissing()
        {
            var plugin = BuildV2Plugin(NewMock().Object);
            var info = new Dictionary<string, object>
            {
                ["UseV2Api"] = true,
                ["ApiUrl"] = "https://v2.certinext.io",
                // No OAuthClientId
                ["OAuthClientSecret"] = "my-secret"
            };

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*OAuthClientId*required*");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_V2_Throws_WhenOAuthClientSecretMissing()
        {
            var plugin = BuildV2Plugin(NewMock().Object);
            var info = new Dictionary<string, object>
            {
                ["UseV2Api"] = true,
                ["ApiUrl"] = "https://v2.certinext.io",
                ["OAuthClientId"] = "my-client"
                // No OAuthClientSecret
            };

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*OAuthClientSecret*required*");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_V2_DoesNotRequireV1Credentials()
        {
            // No AccountNumber, AuthMode, or ApiKey at all — V1 credentials must be optional
            // when UseV2Api is true (issues/0022). Uses a real WireMock server so the live V2
            // ping (the only other thing this method does) succeeds.
            using var server = WireMockServer.Start();
            server
                .Given(Request.Create().WithPath("/oauth/token").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2TokenResponseJson()));
            server
                .Given(Request.Create().WithPath("/api/certinext/v2/auth/me").UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2AuthMeJson()));

            var plugin = BuildV2Plugin(NewMock().Object);
            var info = new Dictionary<string, object>
            {
                ["UseV2Api"] = true,
                ["ApiUrl"] = server.Urls[0],
                ["OAuthClientId"] = "my-client",
                ["OAuthClientSecret"] = "my-secret"
                // No AccountNumber / AuthMode / ApiKey at all.
            };

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().NotThrowAsync(
                "V1 credentials (AccountNumber/AuthMode/ApiKey) must not be required when UseV2Api is true");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_V1_UseV2ApiFalse_StillRequiresAccountNumberAndAuthMode()
        {
            // UseV2Api false (the default/legacy path) — V1 requirements are unchanged, and the
            // (now nonexistent) V2-only fields must never appear in the resulting error.
            var plugin = BuildV2Plugin(NewMock().Object);
            var info = new Dictionary<string, object>
            {
                ["ApiUrl"] = "https://v1.certinext.io",
                ["UseV2Api"] = false
                // No AccountNumber, no AuthMode/ApiKey.
            };

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            var ex = await act.Should().ThrowAsync<AnyCAValidationException>();
            ex.Which.Message.Should().Contain("AccountNumber")
                .And.NotContain("ApiUrlV2").And.NotContain("OAuthClientId").And.NotContain("OAuthClientSecret");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_AllV2FieldsPresent_Passes()
        {
            using var server = WireMockServer.Start();
            server
                .Given(Request.Create().WithPath("/oauth/token").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2TokenResponseJson()));
            server
                .Given(Request.Create().WithPath("/api/certinext/v2/auth/me").UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2AuthMeJson()));

            var plugin = BuildV2Plugin(NewMock().Object);
            var info = new Dictionary<string, object>
            {
                ["UseV2Api"] = true,
                ["ApiUrl"] = server.Urls[0],
                ["OAuthClientId"] = "my-client",
                ["OAuthClientSecret"] = "my-secret"
            };

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().NotThrowAsync(
                "ApiUrl and OAuthClientId/OAuthClientSecret are present and valid, and the live V2 ping succeeds");
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
