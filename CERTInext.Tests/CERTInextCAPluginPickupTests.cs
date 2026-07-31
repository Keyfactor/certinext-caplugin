// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Unit tests for the synchronous pickup poll (<c>TryPickupIssuedCertificateAsync</c>)
    /// that runs at the end of every enrollment path on both build flavors:
    /// DV products poll <c>GetCertificate</c> and return GENERATED + PEM when CERTInext
    /// issues within the budget; OV/EV products defer immediately (async by CA design,
    /// support ticket #162763); exhaustion or any failure soft-falls back to the pending
    /// result without throwing. Compiles on both the DCV (3.3.0) and no-DCV (3.2.0) flavors.
    /// </summary>
    public class CERTInextCAPluginPickupTests
    {
        private const string DvCode = "842";
        private const string OvCode = "846";
        private const string EvCode = "850";

        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

        private static Mock<ICERTInextClient> NewMock() => new Mock<ICERTInextClient>(MockBehavior.Strict);

        /// <summary>Config with a fast pickup budget so tests don't sit in real delays.</summary>
        private static CERTInextConfig PickupConfig(int retries = 3, int delaySeconds = 1) =>
            new CERTInextConfig { PickupRetries = retries, PickupDelaySeconds = delaySeconds };

        private static List<ProductDetail> SslCatalog() => new List<ProductDetail>
        {
            new ProductDetail { ProductCode = DvCode, ProductName = "DV SSL Certificate 1 Year", ProductTypeId = "13" },
            new ProductDetail { ProductCode = OvCode, ProductName = "OV SSL Certificate 1 Year", ProductTypeId = "15" },
            new ProductDetail { ProductCode = EvCode, ProductName = "EV SSL Certificate 1 Year", ProductTypeId = "17" }
        };

        private static EnrollmentProductInfo ProductInfo(string productName, string productCode) =>
            new EnrollmentProductInfo
            {
                ProductID = productName,
                ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ProductCode"] = productCode
                }
            };

        private static Task<EnrollmentResult> Enroll(
            CERTInextCAPlugin plugin, EnrollmentProductInfo productInfo,
            EnrollmentType type = EnrollmentType.New) =>
            plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=test.example.com",
                san: new Dictionary<string, string[]> { ["dns"] = new[] { "test.example.com" } },
                productInfo: productInfo,
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: type);

        private static void SetupPendingEnroll(Mock<ICERTInextClient> mock) =>
            mock.Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.PendingEnrollResponse());

        private static void SetupCatalog(Mock<ICERTInextClient> mock) =>
            mock.Setup(c => c.GetProductDetailsAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync(SslCatalog());

        // ---------------------------------------------------------------------------
        // DV: pending-N-then-issued → GENERATED + PEM
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Pickup_DvProduct_PendingThenIssued_ReturnsGeneratedWithPem()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);
            SetupCatalog(mock);
            mock.SetupSequence(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.PendingCertRecord(MockCertificateData.CertId2))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord(MockCertificateData.CertId2));

            var plugin = new CERTInextCAPlugin(mock.Object, PickupConfig());

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.GENERATED,
                "a DV order that issues within the pickup budget must return synchronously");
            result.Certificate.Should().Contain("BEGIN CERTIFICATE");
            result.CARequestID.Should().Be(MockCertificateData.CertId2);

            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Exactly(2), "the poll must stop as soon as the certificate is issued");
        }

        [Fact]
        public async Task Pickup_DvProduct_IssuedOnFirstPoll_ReturnsGenerated()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);
            SetupCatalog(mock);
            mock.Setup(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord(MockCertificateData.CertId2));

            var plugin = new CERTInextCAPlugin(mock.Object, PickupConfig());

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Once);
        }

        // ---------------------------------------------------------------------------
        // OV/EV: pending immediately, no poll
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Pickup_OvProduct_ReturnsPendingImmediately_WithoutPolling()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);
            SetupCatalog(mock);

            var plugin = new CERTInextCAPlugin(mock.Object, PickupConfig());

            var result = await Enroll(plugin, ProductInfo(Constants.Products.OvSsl, OvCode));

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            result.StatusMessage.Should().Contain("asynchronously",
                "the operator must be told OV issuance is async by CA design, not a failure");
            result.StatusMessage.Should().Contain("synchronization",
                "the operator must be told the cert completes on a later sync");

            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Never,
                "OV orders take minutes to issue (org verification) — polling holds a Command " +
                "worker thread with no chance of success");
        }

        [Fact]
        public async Task Pickup_EvProduct_ReturnsPendingImmediately_WithoutPolling()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);
            SetupCatalog(mock);

            var plugin = new CERTInextCAPlugin(mock.Object, PickupConfig());

            var result = await Enroll(plugin, ProductInfo(Constants.Products.EvSsl, EvCode));

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Never);
        }

        [Fact]
        public async Task Pickup_OvByTemplateName_Defers_WhenCatalogUnavailable()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);
            mock.Setup(c => c.GetProductDetailsAsync(It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("catalog endpoint down"));

            var plugin = new CERTInextCAPlugin(mock.Object, PickupConfig());

            // Template product name carries the OV token — the fallback classifier
            // must still prevent a futile poll when the catalog can't be fetched.
            var result = await Enroll(plugin, ProductInfo(Constants.Products.OvSslWildcard, OvCode));

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Never);
        }

        // ---------------------------------------------------------------------------
        // Product-type catalog caching
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Pickup_ProductCatalog_IsCachedAcrossEnrollments()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);
            SetupCatalog(mock);

            var plugin = new CERTInextCAPlugin(mock.Object, PickupConfig());
            var ov = ProductInfo(Constants.Products.OvSsl, OvCode);

            await Enroll(plugin, ov);
            await Enroll(plugin, ov);
            await Enroll(plugin, ov);

            mock.Verify(c => c.GetProductDetailsAsync(It.IsAny<CancellationToken>()), Times.Once,
                "the catalog must be cached — never fetched per-enrollment");
        }

        // ---------------------------------------------------------------------------
        // Unknown type: poll optimistically
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Pickup_UnknownProduct_PollsOptimistically()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);
            mock.Setup(c => c.GetProductDetailsAsync(It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("catalog endpoint down"));
            mock.Setup(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord(MockCertificateData.CertId2));

            var plugin = new CERTInextCAPlugin(mock.Object, PickupConfig());

            // Neither the catalog nor the product name identify DV/OV/EV → the bounded poll
            // runs anyway (a wasted wait beats silently breaking a fast product's sync return).
            var result = await Enroll(plugin, ProductInfo(MockCertificateData.ProfileIdTls, MockCertificateData.ProfileIdTls));

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Once);
        }

        // ---------------------------------------------------------------------------
        // Soft fallback — never throw
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Pickup_SoftFallsBackToPending_WhenBudgetExhausted()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);
            SetupCatalog(mock);
            mock.Setup(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.PendingCertRecord(MockCertificateData.CertId2));

            var plugin = new CERTInextCAPlugin(mock.Object, PickupConfig(retries: 2, delaySeconds: 1));

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION,
                "exhausting the pickup budget must degrade to the pending result, never throw");
            result.StatusMessage.Should().Contain("later synchronization");
            // Upper bound 2 is the documented PickupRetries semantics (the old off-by-one
            // yielded retries+1 = 3). Lower bound 1 rather than exactly 2 because the poll
            // loop runs against the real clock — a stalled test runner can legitimately
            // exhaust the 2 s budget after a single poll.
            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Between(1, 2, Moq.Range.Inclusive),
                "PickupRetries=2 must never yield more than two polls");
        }

        [Fact]
        public async Task Pickup_SoftFallsBackToPending_WhenGetCertificateThrows()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);
            SetupCatalog(mock);
            mock.Setup(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("CERTInext API 500"));

            var plugin = new CERTInextCAPlugin(mock.Object, PickupConfig());

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION,
                "a failing pickup poll must not fail the enrollment — the order was accepted");
            result.CARequestID.Should().Be(MockCertificateData.CertId2);
        }

        [Fact]
        public async Task Pickup_ReturnsFailed_WhenOrderReachesTerminalFailure()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);
            SetupCatalog(mock);
            mock.Setup(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new LegacyGetCertificateResponse
                {
                    Id = MockCertificateData.CertId2,
                    Status = "failed"
                });

            var plugin = new CERTInextCAPlugin(mock.Object, PickupConfig());

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.FAILED,
                "a terminal failure discovered during pickup must be surfaced, not left pending");
            result.StatusMessage.Should().NotContain("Issued",
                "the operator-visible message for a rejected order must not claim the certificate was issued");
        }

        // ---------------------------------------------------------------------------
        // Opt-out and no-op paths
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Pickup_Disabled_WhenRetriesZero()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);

            var plugin = new CERTInextCAPlugin(mock.Object, PickupConfig(retries: 0));

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            mock.Verify(c => c.GetProductDetailsAsync(It.IsAny<CancellationToken>()), Times.Never,
                "with pickup disabled the catalog must not be fetched either");
            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Never);
        }

        [Fact]
        public async Task Pickup_Skipped_WhenEnrollReturnsIssuedWithPem()
        {
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedEnrollResponse());

            var plugin = new CERTInextCAPlugin(mock.Object, PickupConfig());

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Never, "an already-complete result needs no pickup");
        }

        [Fact]
        public async Task Pickup_FetchesPem_WhenEnrollReturnsIssuedWithoutPem()
        {
            var mock = NewMock();
            var issuedNoPem = MockCertificateData.IssuedEnrollResponse();
            issuedNoPem.Certificate = null; // fulfilled order whose post-submit download failed
            mock.Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(issuedNoPem);
            mock.Setup(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord());

            var plugin = new CERTInextCAPlugin(mock.Object, PickupConfig());

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            result.Certificate.Should().Contain("BEGIN CERTIFICATE",
                "the pickup must recover the PEM for an issued order whose download failed");
        }

        // ---------------------------------------------------------------------------
        // Catalog failure back-off
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Pickup_CatalogFailure_IsBackedOff_NotRetriedPerEnrollment()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);
            mock.Setup(c => c.GetProductDetailsAsync(It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("catalog endpoint down"));
            mock.Setup(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord(MockCertificateData.CertId2));

            var plugin = new CERTInextCAPlugin(mock.Object, PickupConfig());
            var dv = ProductInfo(Constants.Products.DvSsl, DvCode);

            await Enroll(plugin, dv);
            await Enroll(plugin, dv);
            await Enroll(plugin, dv);

            mock.Verify(c => c.GetProductDetailsAsync(It.IsAny<CancellationToken>()), Times.Once,
                "a failing catalog fetch must be backed off — even while the cache is still " +
                "empty — not retried on every enrollment");
        }

        // ---------------------------------------------------------------------------
        // Renew path
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Pickup_RenewPath_PendingThenIssued_ReturnsGenerated()
        {
            var clientMock = NewMock();
            var readerMock = new Mock<ICertificateDataReader>(MockBehavior.Strict);

            readerMock.Setup(r => r.GetRequestIDBySerialNumber(It.IsAny<string>()))
                .ReturnsAsync(MockCertificateData.CertId1);
            readerMock.Setup(r => r.GetExpirationDateByRequestId(MockCertificateData.CertId1))
                .Returns(DateTime.UtcNow.AddDays(30));

            clientMock.Setup(c => c.RenewCertificateAsync(
                    MockCertificateData.CertId1,
                    It.IsAny<RenewCertificateRequest>(),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.PendingEnrollResponse("renewed-01"));
            SetupCatalog(clientMock);
            clientMock.Setup(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord("renewed-01"));

            var plugin = new CERTInextCAPlugin(clientMock.Object, readerMock.Object, PickupConfig());
            var productInfo = new EnrollmentProductInfo
            {
                ProductID = Constants.Products.DvSsl,
                ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ProductCode"] = DvCode,
                    ["PriorCertSN"] = "AABB",
                    ["RenewalWindowDays"] = "90"
                }
            };

            var result = await Enroll(plugin, productInfo, EnrollmentType.RenewOrReissue);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED,
                "the renew API path must run the same synchronous pickup as new enrollment — " +
                "this is the expiration-renewal workflow scenario");
            result.Certificate.Should().Contain("BEGIN CERTIFICATE");
            clientMock.Verify(c => c.GetCertificateAsync("renewed-01", It.IsAny<CancellationToken>()),
                Times.Once, "the pickup must poll the NEW order number returned by the renewal");
        }

        [Fact]
        public async Task Pickup_RenewPath_RunsEvenWhenDcvEnabled()
        {
            // In-call DCV only exists on the New/Reissue path, so DcvEnabled must NOT
            // suppress the pickup for renewals — that is the expiration-renewal scenario
            // this feature exists for.
            var clientMock = NewMock();
            var readerMock = new Mock<ICertificateDataReader>(MockBehavior.Strict);

            readerMock.Setup(r => r.GetRequestIDBySerialNumber(It.IsAny<string>()))
                .ReturnsAsync(MockCertificateData.CertId1);
            readerMock.Setup(r => r.GetExpirationDateByRequestId(MockCertificateData.CertId1))
                .Returns(DateTime.UtcNow.AddDays(30));

            clientMock.Setup(c => c.RenewCertificateAsync(
                    MockCertificateData.CertId1,
                    It.IsAny<RenewCertificateRequest>(),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.PendingEnrollResponse("renewed-02"));
            SetupCatalog(clientMock);
            clientMock.Setup(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord("renewed-02"));

            var config = PickupConfig();
            config.DcvEnabled = true;
            var plugin = new CERTInextCAPlugin(clientMock.Object, readerMock.Object, config);
            var productInfo = new EnrollmentProductInfo
            {
                ProductID = Constants.Products.DvSsl,
                ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ProductCode"] = DvCode,
                    ["PriorCertSN"] = "AABB",
                    ["RenewalWindowDays"] = "90"
                }
            };

            var result = await Enroll(plugin, productInfo, EnrollmentType.RenewOrReissue);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED,
                "DcvEnabled must not disable the renew-path pickup — no in-call DCV runs there");
        }

        [Fact]
        public async Task Pickup_FetchesPem_ForIssuedOrder_EvenWhenDcvEnabled()
        {
            // An issued-but-PEM-missing order is past validation entirely, so the recovery
            // fetch must run regardless of DCV configuration.
            var mock = NewMock();
            var issuedNoPem = MockCertificateData.IssuedEnrollResponse();
            issuedNoPem.Certificate = null;
            mock.Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(issuedNoPem);
            mock.Setup(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord());
#if SUPPORTS_DCV
            // On the DCV build the enroll path consults TrackOrder for manual-DCV guidance
            // when DcvEnabled is set without a validator factory; let it fail soft.
            mock.Setup(c => c.TrackOrderAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("not relevant to this test"));
#endif

            var config = PickupConfig();
            config.DcvEnabled = true;
            var plugin = new CERTInextCAPlugin(mock.Object, config);

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            result.Certificate.Should().Contain("BEGIN CERTIFICATE",
                "the PEM-recovery fetch must run even when DCV owns pending-order waits");
        }

        [Fact]
        public async Task Pickup_RenewPath_ClassifiesTheProductCodeActuallyOrdered()
        {
            // CERTInextClient.RenewCertificateAsync places the renewal order with the
            // connector's DefaultProductCode, not the template's code — the OV/EV gate
            // must classify what was ordered, or it polls futilely / defers wrongly.
            var clientMock = NewMock();
            var readerMock = new Mock<ICertificateDataReader>(MockBehavior.Strict);

            readerMock.Setup(r => r.GetRequestIDBySerialNumber(It.IsAny<string>()))
                .ReturnsAsync(MockCertificateData.CertId1);
            readerMock.Setup(r => r.GetExpirationDateByRequestId(MockCertificateData.CertId1))
                .Returns(DateTime.UtcNow.AddDays(30));

            clientMock.Setup(c => c.RenewCertificateAsync(
                    MockCertificateData.CertId1,
                    It.IsAny<RenewCertificateRequest>(),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.PendingEnrollResponse("renewed-03"));
            SetupCatalog(clientMock);

            var config = PickupConfig();
            config.DefaultProductCode = OvCode; // what the renewal order is actually placed with
            var plugin = new CERTInextCAPlugin(clientMock.Object, readerMock.Object, config);
            var productInfo = new EnrollmentProductInfo
            {
                ProductID = Constants.Products.DvSsl, // template says DV…
                ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ProductCode"] = DvCode,          // …and so does its code
                    ["PriorCertSN"] = "AABB",
                    ["RenewalWindowDays"] = "90"
                }
            };

            var result = await Enroll(plugin, productInfo, EnrollmentType.RenewOrReissue);

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            clientMock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Never,
                "the order was placed as OV (connector DefaultProductCode) — polling cannot win, " +
                "regardless of what the template's own code says");
        }
    }
}
