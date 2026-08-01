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
    /// Unit tests for the synchronous enrollment-wait poll (<c>TryEnrollmentWaitForCertificateAsync</c>)
    /// that runs at the end of every enrollment path on both build flavors:
    /// DV products poll <c>GetCertificate</c> and return GENERATED + PEM when CERTInext
    /// issues within the budget; OV/EV products defer immediately (async by CA design,
    /// per CERTInext support); exhaustion or any failure soft-falls back to the pending
    /// result without throwing. Compiles on both the DCV (3.3.0) and no-DCV (3.2.0) flavors.
    /// </summary>
    public class CERTInextCAPluginEnrollmentWaitTests
    {
        private const string DvCode = "842";
        private const string OvCode = "846";
        private const string EvCode = "850";

        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

        private static Mock<ICERTInextClient> NewMock() => new Mock<ICERTInextClient>(MockBehavior.Strict);

        /// <summary>
        /// Config with a fixed 5-second poll interval (Constants.Polling.CertificatePollIntervalSeconds,
        /// no longer configurable). The default budget mirrors the plugin's production default
        /// (50s ⇒ 10 max polls) so tests that need a few polls to resolve have headroom without
        /// hitting exhaustion. Tests that specifically exercise budget exhaustion pass a small
        /// explicit totalSeconds instead, sized to the fixed 5s interval — e.g. 10s ⇒ exactly 2 polls.
        /// </summary>
        private static CERTInextConfig EnrollmentWaitConfig(int totalSeconds = 50) =>
            new CERTInextConfig { EnrollmentWaitSeconds = totalSeconds };

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
        public async Task EnrollmentWait_DvProduct_PendingThenIssued_ReturnsGeneratedWithPem()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);
            SetupCatalog(mock);
            mock.SetupSequence(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.PendingCertRecord(MockCertificateData.CertId2))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord(MockCertificateData.CertId2));

            var plugin = new CERTInextCAPlugin(mock.Object, EnrollmentWaitConfig());

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.GENERATED,
                "a DV order that issues within the enrollment-wait budget must return synchronously");
            result.Certificate.Should().Contain("BEGIN CERTIFICATE");
            result.CARequestID.Should().Be(MockCertificateData.CertId2);

            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Exactly(2), "the poll must stop as soon as the certificate is issued");
        }

        [Fact]
        public async Task EnrollmentWait_DvProduct_IssuedOnFirstPoll_ReturnsGenerated()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);
            SetupCatalog(mock);
            mock.Setup(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord(MockCertificateData.CertId2));

            var plugin = new CERTInextCAPlugin(mock.Object, EnrollmentWaitConfig());

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Once);
        }

        // ---------------------------------------------------------------------------
        // OV/EV: pending immediately, no poll
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task EnrollmentWait_OvProduct_ReturnsPendingImmediately_WithoutPolling()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);
            SetupCatalog(mock);

            var plugin = new CERTInextCAPlugin(mock.Object, EnrollmentWaitConfig());

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
        public async Task EnrollmentWait_EvProduct_ReturnsPendingImmediately_WithoutPolling()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);
            SetupCatalog(mock);

            var plugin = new CERTInextCAPlugin(mock.Object, EnrollmentWaitConfig());

            var result = await Enroll(plugin, ProductInfo(Constants.Products.EvSsl, EvCode));

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Never);
        }

        [Fact]
        public async Task EnrollmentWait_OvByTemplateName_Defers_WhenCatalogUnavailable()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);
            mock.Setup(c => c.GetProductDetailsAsync(It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("catalog endpoint down"));

            var plugin = new CERTInextCAPlugin(mock.Object, EnrollmentWaitConfig());

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
        public async Task EnrollmentWait_ProductCatalog_IsCachedAcrossEnrollments()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);
            SetupCatalog(mock);

            var plugin = new CERTInextCAPlugin(mock.Object, EnrollmentWaitConfig());
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
        public async Task EnrollmentWait_UnknownProduct_PollsOptimistically()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);
            mock.Setup(c => c.GetProductDetailsAsync(It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("catalog endpoint down"));
            mock.Setup(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord(MockCertificateData.CertId2));

            var plugin = new CERTInextCAPlugin(mock.Object, EnrollmentWaitConfig());

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
        public async Task EnrollmentWait_SoftFallsBackToPending_WhenBudgetExhausted()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);
            SetupCatalog(mock);
            mock.Setup(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.PendingCertRecord(MockCertificateData.CertId2));

            var plugin = new CERTInextCAPlugin(mock.Object, EnrollmentWaitConfig(10));

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION,
                "exhausting the enrollment-wait budget must degrade to the pending result, never throw");
            result.StatusMessage.Should().Contain("later synchronization");
            // A 10s budget over the fixed 5s interval yields exactly 2 polls. The poll count is
            // capped deterministically (maxPolls = budget / interval) rather than emerging from
            // wall-clock arithmetic, so this is an exact assertion — no real-clock tolerance
            // needed. This is the off-by-one guard: the old bug yielded one extra poll.
            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Exactly(2),
                "a 10s budget over the fixed 5s interval must yield exactly two polls");
        }

        [Fact]
        public async Task EnrollmentWait_SurvivesTransientFailure_AndReturnsIssuedOnRetry()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);
            SetupCatalog(mock);
            mock.SetupSequence(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("momentary CERTInext 500"))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord(MockCertificateData.CertId2));

            var plugin = new CERTInextCAPlugin(mock.Object, EnrollmentWaitConfig());

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.GENERATED,
                "a transient API failure must consume one attempt, not the whole budget — " +
                "the legacy Sectigo pickup loop retried through failures");
            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Exactly(2));
        }

        [Fact]
        public async Task EnrollmentWait_Disabled_WhenRetriesNegative()
        {
            // "-1 to disable" is a common operator convention — it must not silently
            // fall back to the enabled default of 50s.
            var mock = NewMock();
            SetupPendingEnroll(mock);

            var plugin = new CERTInextCAPlugin(mock.Object, EnrollmentWaitConfig(-1));

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            mock.Verify(c => c.GetProductDetailsAsync(It.IsAny<CancellationToken>()), Times.Never);
            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Never);
        }

        [Fact]
        public async Task EnrollmentWait_SoftFallsBackToPending_WhenGetCertificateThrows()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);
            SetupCatalog(mock);
            mock.Setup(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("CERTInext API 500"));

            // Small explicit budget: every poll throws, so this test runs to exhaustion.
            var plugin = new CERTInextCAPlugin(mock.Object, EnrollmentWaitConfig(10));

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION,
                "a failing enrollment-wait poll must not fail the enrollment — the order was accepted");
            result.CARequestID.Should().Be(MockCertificateData.CertId2);
        }

        [Fact]
        public async Task EnrollmentWait_ReturnsFailed_WhenOrderReachesTerminalFailure()
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

            var plugin = new CERTInextCAPlugin(mock.Object, EnrollmentWaitConfig());

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.FAILED,
                "a terminal failure discovered during the enrollment wait must be surfaced, not left pending");
            result.StatusMessage.Should().NotContain("Issued",
                "the operator-visible message for a rejected order must not claim the certificate was issued");
        }

        // ---------------------------------------------------------------------------
        // Opt-out and no-op paths
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task EnrollmentWait_Disabled_WhenRetriesZero()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);

            var plugin = new CERTInextCAPlugin(mock.Object, EnrollmentWaitConfig(0));

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            mock.Verify(c => c.GetProductDetailsAsync(It.IsAny<CancellationToken>()), Times.Never,
                "with the enrollment wait disabled the catalog must not be fetched either");
            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Never);
        }

        [Fact]
        public async Task EnrollmentWait_Skipped_WhenEnrollReturnsIssuedWithPem()
        {
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedEnrollResponse());

            var plugin = new CERTInextCAPlugin(mock.Object, EnrollmentWaitConfig());

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Never, "an already-complete result needs no enrollment wait");
        }

        [Fact]
        public async Task EnrollmentWait_FetchesPem_WhenEnrollReturnsIssuedWithoutPem()
        {
            var mock = NewMock();
            var issuedNoPem = MockCertificateData.IssuedEnrollResponse();
            issuedNoPem.Certificate = null; // fulfilled order whose post-submit download failed
            mock.Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(issuedNoPem);
            mock.Setup(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord());

            var plugin = new CERTInextCAPlugin(mock.Object, EnrollmentWaitConfig());

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            result.Certificate.Should().Contain("BEGIN CERTIFICATE",
                "the enrollment wait must recover the PEM for an issued order whose download failed");
        }

        [Fact]
        public async Task EnrollmentWait_KeepsPolling_WhenGeneratedWithoutBody_ThenRecoversPem()
        {
            // GetCertificateAsync maps status from TrackOrder but swallows a transient
            // DownloadCertificate failure, returning Status=issued with Certificate=null.
            // A body-less GENERATED must NOT be treated as terminal mid-poll — the loop must
            // keep going (each attempt re-downloads) and recover the PEM within the budget.
            var mock = NewMock();
            SetupPendingEnroll(mock);
            SetupCatalog(mock);
            mock.SetupSequence(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new LegacyGetCertificateResponse
                {
                    Id = MockCertificateData.CertId2, Status = "issued", Certificate = null
                })
                .ReturnsAsync(MockCertificateData.IssuedCertRecord(MockCertificateData.CertId2));

            var plugin = new CERTInextCAPlugin(mock.Object, EnrollmentWaitConfig());

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            result.Certificate.Should().Contain("BEGIN CERTIFICATE",
                "a body-less 'issued' response must not end the poll — the next attempt recovers the PEM");
            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Exactly(2), "the poll must continue past a GENERATED-without-body response");
        }

        [Fact]
        public async Task EnrollmentWait_SoftFallsBackToPending_WhenGeneratedBodyNeverArrives()
        {
            // Every poll reports issued but the PEM download keeps failing (Certificate=null),
            // and the budget expires with only a body-less GENERATED in hand. The enrollment wait must
            // NOT surface that as a successful "issued, no certificate" result — Command would
            // store a body-less record — but degrade to pending so a later sync refetches the PEM.
            var mock = NewMock();
            SetupPendingEnroll(mock);
            SetupCatalog(mock);
            mock.Setup(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new LegacyGetCertificateResponse
                {
                    Id = MockCertificateData.CertId2, Status = "issued", Certificate = null
                });

            var plugin = new CERTInextCAPlugin(mock.Object, EnrollmentWaitConfig(15));

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION,
                "an issued order whose PEM never downloads within the budget must degrade to " +
                "pending, never a GENERATED result with no certificate body");
            result.Certificate.Should().BeNullOrEmpty(
                "a bodyless GENERATED must not be returned as a successful enrollment wait");
            result.StatusMessage.Should().Contain("later synchronization");
        }

        [Fact]
        public async Task EnrollmentWait_SoftFallsBackToPending_WhenEnrollIssuedWithoutPem_AndBodyNeverArrives()
        {
            // Entry state (not just a mid-poll read) is issued-without-PEM: EnrollCertificateAsync
            // reported issued but swallowed the post-submit download failure (Certificate=null).
            // The enrollment wait polls to recover the body; if every poll also comes back body-less and the
            // budget expires, the RESULT returned to Command must degrade to pending — it must NOT
            // return the original GENERATED entry state with a null certificate.
            var mock = NewMock();
            var issuedNoPem = MockCertificateData.IssuedEnrollResponse();
            issuedNoPem.Certificate = null;
            mock.Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(issuedNoPem);
            SetupCatalog(mock);
            mock.Setup(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new LegacyGetCertificateResponse
                {
                    Id = MockCertificateData.CertId2, Status = "issued", Certificate = null
                });

            var plugin = new CERTInextCAPlugin(mock.Object, EnrollmentWaitConfig(15));

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION,
                "an issued-without-PEM enroll that the poll cannot recover must be returned pending, " +
                "never as GENERATED with no certificate body");
            result.Certificate.Should().BeNullOrEmpty();
        }

        [Fact]
        public async Task EnrollmentWait_Disabled_DowngradesIssuedWithoutPem_ToPending()
        {
            // Enrollment wait disabled (EnrollmentWaitSeconds=0) short-circuits before any poll. If the enroll
            // response is issued-without-PEM, returning it verbatim would hand Command a bodyless
            // GENERATED. The disabled path must still enforce the no-bodyless-GENERATED invariant
            // and degrade to pending so a later sync imports the certificate.
            var mock = NewMock();
            var issuedNoPem = MockCertificateData.IssuedEnrollResponse();
            issuedNoPem.Certificate = null;
            mock.Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(issuedNoPem);

            var plugin = new CERTInextCAPlugin(mock.Object, EnrollmentWaitConfig(0));

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION,
                "with the enrollment wait disabled a bodyless issued result must still degrade to pending");
            result.Certificate.Should().BeNullOrEmpty();
            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Never, "the disabled enrollment wait must not poll");
        }

        [Fact]
        public async Task EnrollmentWait_DegradesIssuedWithoutPem_ToPending_WhenOrderNumberEmpty()
        {
            // The no-order-number guard is the first return in the enrollment wait and cannot poll or
            // refetch. If the enroll response is issued-without-PEM but carries no order number,
            // that guard must STILL enforce the no-bodyless-GENERATED invariant rather than return
            // the broken result verbatim. (Defense-in-depth: the shipped client throws before
            // returning an empty Id, but the enrollment wait must not depend on that upstream guarantee.)
            var mock = NewMock();
            var issuedNoPemNoId = MockCertificateData.IssuedEnrollResponse();
            issuedNoPemNoId.Certificate = null;
            issuedNoPemNoId.Id = "";
            mock.Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(issuedNoPemNoId);

            var plugin = new CERTInextCAPlugin(mock.Object, EnrollmentWaitConfig());

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION,
                "a bodyless issued result must degrade to pending even when there is no order " +
                "number to poll with");
            result.Certificate.Should().BeNullOrEmpty();
            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Never, "an empty order number cannot be polled");
        }

        // ---------------------------------------------------------------------------
        // Catalog failure back-off
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task EnrollmentWait_CatalogFailure_IsBackedOff_NotRetriedPerEnrollment()
        {
            var mock = NewMock();
            SetupPendingEnroll(mock);
            mock.Setup(c => c.GetProductDetailsAsync(It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("catalog endpoint down"));
            mock.Setup(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord(MockCertificateData.CertId2));

            var plugin = new CERTInextCAPlugin(mock.Object, EnrollmentWaitConfig());
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
        public async Task EnrollmentWait_RenewPath_PendingThenIssued_ReturnsGenerated()
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

            var plugin = new CERTInextCAPlugin(clientMock.Object, readerMock.Object, EnrollmentWaitConfig());
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
                "the renew API path must run the same synchronous enrollment wait as new enrollment — " +
                "this is the expiration-renewal workflow scenario");
            result.Certificate.Should().Contain("BEGIN CERTIFICATE");
            clientMock.Verify(c => c.GetCertificateAsync("renewed-01", It.IsAny<CancellationToken>()),
                Times.Once, "the enrollment wait must poll the NEW order number returned by the renewal");
        }

        [Fact]
        public async Task EnrollmentWait_RenewPath_RunsEvenWhenDcvEnabled()
        {
            // In-call DCV only exists on the New/Reissue path, so DcvEnabled must NOT
            // suppress the enrollment wait for renewals — that is the expiration-renewal scenario
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

            var config = EnrollmentWaitConfig();
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
                "DcvEnabled must not disable the renew-path enrollment wait — no in-call DCV runs there");
        }

        [Fact]
        public async Task EnrollmentWait_FetchesPem_ForIssuedOrder_EvenWhenDcvEnabled()
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

            var config = EnrollmentWaitConfig();
            config.DcvEnabled = true;
            var plugin = new CERTInextCAPlugin(mock.Object, config);

            var result = await Enroll(plugin, ProductInfo(Constants.Products.DvSsl, DvCode));

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            result.Certificate.Should().Contain("BEGIN CERTIFICATE",
                "the PEM-recovery fetch must run even when DCV owns pending-order waits");
        }

        [Fact]
        public async Task EnrollmentWait_RenewPath_ClassifiesTheProductCodeActuallyOrdered()
        {
            // CERTInextClient.RenewCertificateAsync places the renewal order with the
            // connector's DefaultProductCode (not the template's code) and reports the
            // ordered code back on the response's ProfileId — the OV/EV gate must classify
            // that reported code, or it polls futilely / defers wrongly.
            var clientMock = NewMock();
            var readerMock = new Mock<ICertificateDataReader>(MockBehavior.Strict);

            readerMock.Setup(r => r.GetRequestIDBySerialNumber(It.IsAny<string>()))
                .ReturnsAsync(MockCertificateData.CertId1);
            readerMock.Setup(r => r.GetExpirationDateByRequestId(MockCertificateData.CertId1))
                .Returns(DateTime.UtcNow.AddDays(30));

            var renewPending = MockCertificateData.PendingEnrollResponse("renewed-03");
            renewPending.ProfileId = OvCode; // the code the client actually ordered with
            clientMock.Setup(c => c.RenewCertificateAsync(
                    MockCertificateData.CertId1,
                    It.IsAny<RenewCertificateRequest>(),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(renewPending);
            SetupCatalog(clientMock);

            var config = EnrollmentWaitConfig();
            config.DefaultProductCode = OvCode; // what RenewCertificateAsync orders with
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
