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
    /// Regression coverage for issue 0051: V2 enrollment had no synchronous certificate-pickup
    /// poll analogous to <c>PickUpEnrolledCertificateAsync</c> (V1). These tests exercise
    /// <c>PickUpEnrolledCertificateV2Async</c> end-to-end through <see cref="CERTInextCAPlugin.Enroll"/>
    /// (V2 path), the same way <c>CERTInextCAPluginTests</c>'s "Synchronous certificate pickup"
    /// section exercises the V1 method. No domain validator factory is configured here, so the
    /// inline DCV block (when compiled) short-circuits immediately (factory null) and never sets
    /// <c>dcvV2Ran</c> — DCV-vs-pickup interaction is covered separately in
    /// <c>CERTInextCAPluginV2DcvTests</c>.
    /// </summary>
    public class CERTInextCAPluginV2PickupTests
    {
        private static Mock<ICERTInextClient> NewMock() =>
            new Mock<ICERTInextClient>(MockBehavior.Strict);

        // PickupDelay is clamped to a 1s floor and the loop adds a fixed 5s initial delay
        // (Constants.Pickup.InitialDelaySeconds), so these tests are intentionally a few
        // seconds each — mirrors BuildPluginWithPickup in CERTInextCAPluginTests.cs.
        private static CERTInextCAPlugin BuildV2PluginWithPickup(
            ICERTInextClient client, int retries, int delaySeconds = 1) =>
            new CERTInextCAPlugin(client, new CERTInextConfig
            {
                UseV2Api          = true,
                ApiUrl            = "https://v2.certinext.io",
                OAuthClientId     = "my-client",
                OAuthClientSecret = "my-secret",
                AccountNumber     = "12345",
                AuthMode          = "AccessKey",
                ApiKey            = "v1-key",
                RequestorName     = "Test User",
                RequestorEmail    = "test@example.com",
                SignerIp          = "1.2.3.4",
                SignerPlace       = "New York",
                PickupRetries          = retries,
                PickupDelayInSeconds   = delaySeconds
            });

        private static EnrollmentProductInfo MakeV2ProductInfo() =>
            new EnrollmentProductInfo
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

        /// <summary>
        /// Every V2 enrollment resolves the requested product's <c>productTypeID</c> from the
        /// live Catalog to decide UCC-ness — any Strict-mock enroll test must stub this call
        /// regardless of whether the test cares about UCC behavior (mirrors StubCatalog in
        /// CERTInextCAPluginV2Tests.cs).
        /// </summary>
        private static void StubCatalog(Mock<ICERTInextClient> mock) =>
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true } // non-UCC
                });

        private const string OrderId = "ord_pickup_001";

        private static Task<EnrollmentResult> Enroll(CERTInextCAPlugin plugin) =>
            plugin.Enroll(
                csr:            MockCertificateData.FakeCsrPem,
                subject:        "CN=example.com",
                san:            new Dictionary<string, string[]>(),
                productInfo:    MakeV2ProductInfo(),
                requestFormat:  RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

        private static void StubPlaceAndSubmit(Mock<ICERTInextClient> mock, string initialStatus) =>
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = OrderId, Status = initialStatus });

        // ---------------------------------------------------------------------------
        // pending -> issued on a later poll -> GENERATED + chain
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Pickup_ReturnsIssuedCert_WhenOrderIssuesDuringLaterPoll()
        {
            var mock = NewMock();
            StubCatalog(mock);
            StubPlaceAndSubmit(mock, "pending-csr");
            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            // 1st call: post-CSR check (still pending). 2nd: 1st poll attempt (still pending).
            // 3rd: 2nd poll attempt — the order has now issued.
            mock.SetupSequence(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "pending-dcv" })
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "pending-dcv" })
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "issued" });

            mock.Setup(c => c.DownloadCertificateV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CertificateDownloadResponse
                {
                    OrderId        = OrderId,
                    SerialNumber   = "AABBCC",
                    CertificatePem = MockCertificateData.FakePemCertificate
                });

            var plugin = BuildV2PluginWithPickup(mock.Object, retries: 2);

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            result.CARequestID.Should().Be(OrderId);
            result.Certificate.Should().StartWith("-----BEGIN CERTIFICATE-----");
            mock.Verify(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()),
                Times.Exactly(3));
            mock.Verify(c => c.DownloadCertificateV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()),
                Times.Once);
        }

        // ---------------------------------------------------------------------------
        // issued but the first download fails -> retried -> GENERATED
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Pickup_RetriesDownload_WhenFirstDownloadAttemptFails()
        {
            var mock = NewMock();
            StubCatalog(mock);
            StubPlaceAndSubmit(mock, "pending-csr");
            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            // Post-CSR check is still pending, so EnrollV2Async's own immediate-download branch
            // is never reached — both "issued" observations below come from the pickup poll.
            mock.SetupSequence(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "pending-dcv" })
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "issued" })
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "issued" });

            mock.SetupSequence(c => c.DownloadCertificateV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("simulated transient download failure"))
                .ReturnsAsync(new V2CertificateDownloadResponse
                {
                    OrderId        = OrderId,
                    SerialNumber   = "AABBCC",
                    CertificatePem = MockCertificateData.FakePemCertificate
                });

            var plugin = BuildV2PluginWithPickup(mock.Object, retries: 2);

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            result.Certificate.Should().StartWith("-----BEGIN CERTIFICATE-----");
            mock.Verify(c => c.DownloadCertificateV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()),
                Times.Exactly(2), "the first download failure must not abort the poll");
        }

        // ---------------------------------------------------------------------------
        // still pending at budget -> pending with CARequestID
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Pickup_ReturnsPendingWithCARequestID_WhenOrderNeverIssuesWithinBudget()
        {
            var mock = NewMock();
            StubCatalog(mock);
            StubPlaceAndSubmit(mock, "pending-csr");
            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            // Every poll (including the post-CSR check) still reports pending.
            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "pending-dcv" });

            var plugin = BuildV2PluginWithPickup(mock.Object, retries: 1);

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            result.CARequestID.Should().Be(OrderId);
            mock.Verify(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()),
                Times.AtLeast(2), "an enabled pickup must actually poll before giving up");
            mock.Verify(c => c.DownloadCertificateV2Async(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // PickupRetries=0 -> no polling
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Pickup_Disabled_WhenPickupRetriesZero_ReturnsPendingWithoutPolling()
        {
            var mock = NewMock();
            StubCatalog(mock);
            StubPlaceAndSubmit(mock, "pending-csr");
            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "pending-dcv" });

            var plugin = BuildV2PluginWithPickup(mock.Object, retries: 0);

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            result.CARequestID.Should().Be(OrderId);
            // Only the single post-CSR status check should have run — no pickup polling at all.
            mock.Verify(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()),
                Times.Once, "PickupRetries=0 must disable the V2 synchronous pickup poll");
            mock.Verify(c => c.DownloadCertificateV2Async(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // FAILED mid-poll -> returned as-is
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Pickup_SurfacesTerminalFailedStatus_WhenOrderRejectedDuringPoll()
        {
            var mock = NewMock();
            StubCatalog(mock);
            StubPlaceAndSubmit(mock, "pending-csr");
            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            // Post-CSR check is pending; the first (and only) poll attempt observes a terminal
            // "rejected" status, which StatusMapper.V2StatusToRequestDisposition maps to FAILED.
            mock.SetupSequence(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "pending-dcv" })
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "rejected" });

            var plugin = BuildV2PluginWithPickup(mock.Object, retries: 3);

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.FAILED,
                "a terminal status observed during pickup is surfaced immediately, not polled to exhaustion");
            result.CARequestID.Should().Be(OrderId);
            mock.Verify(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()),
                Times.Exactly(2), "the poll must stop at the first terminal observation, not run all 3 retries");
        }
    }
}
