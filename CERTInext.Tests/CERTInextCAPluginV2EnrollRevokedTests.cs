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
    /// Regression coverage for issue 0052: at enroll time the gateway never holds a stored
    /// certificate body for a brand-new V2 order, so a REVOKED disposition surfaced from
    /// <c>EnrollV2Async</c> — whether observed on the post-CSR-submit status check or during the
    /// synchronous pickup poll (<c>PickUpEnrolledCertificateV2Async</c>) — is always body-less.
    /// Before the fix, that flowed straight through to <see cref="CERTInextCAPlugin.Enroll"/>'s
    /// caller as <c>Status=REVOKED, Certificate=null</c>, which is exactly the shape that poisons
    /// the gateway per issue 0049 (RevocationDate never clears; every later revoked-certificate
    /// search calls FromDER(null) and 500s). These tests drive the fix end-to-end through
    /// <see cref="CERTInextCAPlugin.Enroll"/> (V2 path), mirroring
    /// <c>CERTInextCAPluginV2PickupTests</c>'s mocking patterns. The DCV-gated variant of this
    /// scenario (REVOKED observed on the post-DCV status re-check) lives in
    /// <c>CERTInextCAPluginV2DcvTests</c> since it needs a domain validator factory and only
    /// compiles when <c>SUPPORTS_DCV</c> is defined.
    /// </summary>
    public class CERTInextCAPluginV2EnrollRevokedTests
    {
        private static Mock<ICERTInextClient> NewMock() =>
            new Mock<ICERTInextClient>(MockBehavior.Strict);

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
        /// CERTInextCAPluginV2PickupTests.cs).
        /// </summary>
        private static void StubCatalog(Mock<ICERTInextClient> mock) =>
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true } // non-UCC
                });

        private const string OrderId = "ord_0052_revoked_001";

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
        // REVOKED on the status check immediately after CSR submit -> FAILED
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_RevokedImmediatelyAfterCsrSubmit_ReturnsFailed_NotBodylessRevoked()
        {
            var mock = NewMock();
            StubCatalog(mock);
            StubPlaceAndSubmit(mock, "pending-csr");
            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            // The very first status check after CSR submission already reports the order as
            // revoked — there was never a chance for a certificate body to exist.
            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "revoked" });

            var plugin = BuildV2PluginWithPickup(mock.Object, retries: 3);

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.FAILED,
                "a REVOKED order observed right after CSR submission has no certificate body and " +
                "must never be reported as REVOKED (issue 0052)");
            result.Certificate.Should().BeNull();
            result.CARequestID.Should().Be(OrderId);
            result.StatusMessage.Should().Contain(OrderId).And.Contain("revoked");

            // A terminal (non-EXTERNALVALIDATION) disposition must never enter the pickup poll.
            mock.Verify(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()),
                Times.Once, "a terminal REVOKED disposition observed pre-poll must not trigger the pickup poll");
            mock.Verify(c => c.DownloadCertificateV2Async(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // REVOKED discovered during the synchronous pickup poll -> FAILED
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_RevokedDuringPickupPoll_ReturnsFailed_NotBodylessRevoked()
        {
            var mock = NewMock();
            StubCatalog(mock);
            StubPlaceAndSubmit(mock, "pending-csr");
            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            // Post-CSR check is still pending; the first (and only) poll attempt observes the
            // order was revoked at the CA before ever issuing.
            mock.SetupSequence(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "pending-dcv" })
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "revoked" });

            var plugin = BuildV2PluginWithPickup(mock.Object, retries: 3);

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.FAILED,
                "a REVOKED disposition discovered mid-poll has no certificate body and must never " +
                "be reported as REVOKED (issue 0052)");
            result.Certificate.Should().BeNull();
            result.CARequestID.Should().Be(OrderId);
            result.StatusMessage.Should().Contain(OrderId).And.Contain("revoked");

            mock.Verify(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()),
                Times.Exactly(2), "the poll must stop at the first terminal observation, not run all 3 retries");
            mock.Verify(c => c.DownloadCertificateV2Async(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // Regression: a genuinely FAILED disposition must pass through unchanged
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_FailedDuringPickupPoll_StaysFailed()
        {
            var mock = NewMock();
            StubCatalog(mock);
            StubPlaceAndSubmit(mock, "pending-csr");
            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            mock.SetupSequence(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "pending-dcv" })
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "rejected" });

            var plugin = BuildV2PluginWithPickup(mock.Object, retries: 3);

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.FAILED,
                "a genuinely FAILED disposition must pass through the issue-0052 REVOKED->FAILED " +
                "normalization unchanged");
            result.CARequestID.Should().Be(OrderId);
        }

        // ---------------------------------------------------------------------------
        // Regression: a genuinely issued certificate must pass through unchanged
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_IssuedDuringPickupPoll_StaysGenerated_WithCertificate()
        {
            var mock = NewMock();
            StubCatalog(mock);
            StubPlaceAndSubmit(mock, "pending-csr");
            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            mock.SetupSequence(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
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

            result.Status.Should().Be((int)EndEntityStatus.GENERATED,
                "a genuinely issued certificate must pass through the issue-0052 REVOKED->FAILED " +
                "normalization unchanged");
            result.Certificate.Should().StartWith("-----BEGIN CERTIFICATE-----");
            result.CARequestID.Should().Be(OrderId);
        }
    }
}
