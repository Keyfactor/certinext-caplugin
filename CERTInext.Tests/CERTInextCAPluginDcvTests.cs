// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0

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
    /// Unit tests for the DCV orchestration path inside
    /// <see cref="CERTInextCAPlugin.EnrollNewAsync"/> /
    /// <see cref="CERTInextCAPlugin.PerformDcvIfNeededAsync"/>.
    ///
    /// All external dependencies (CERTInext client, DNS validator) are stubbed so
    /// no network calls are made.  Propagation delay is set to 0 so tests run fast.
    /// </summary>
    public class CERTInextCAPluginDcvTests
    {
        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

        private static CERTInextConfig DcvConfig(
            bool enabled                       = true,
            int propagationDelaySeconds        = 1,
            int timeoutMinutes                 = 1,
            int dcvWaitForChallengeSeconds     = 0,
            int dcvWaitForIssuanceSeconds      = 0,
            int pickupRetries                  = 0) =>
            new CERTInextConfig
            {
                DcvEnabled                 = enabled,
                DcvPropagationDelaySeconds = propagationDelaySeconds,
                DcvTimeoutMinutes          = timeoutMinutes,
                // Default to 0 so existing tests preserve the pre-polling single-check
                // behaviour and run fast.  Tests that exercise the new wait paths can opt
                // in with a positive value (see WaitsForChallenge_ToAppear / WaitsForIssuance).
                DcvWaitForChallengeSeconds = dcvWaitForChallengeSeconds,
                DcvWaitForIssuanceSeconds  = dcvWaitForIssuanceSeconds,
                // Disable the synchronous pickup poll by default (same reasoning as the wait
                // budgets above): the DCV path owns issuance for these tests, and a DCV-disabled
                // or no-factory case that ends on a pending result must not pay the real pickup
                // Task.Delay loop. The dedicated pickup tests live in CERTInextCAPluginTests.
                PickupRetries              = pickupRetries
            };

        private static Mock<ICERTInextClient> NewMock() =>
            new Mock<ICERTInextClient>(MockBehavior.Strict);

        private static CERTInextCAPlugin BuildPlugin(
            ICERTInextClient client,
            IDomainValidatorFactory factory,
            CERTInextConfig config = null) =>
            new CERTInextCAPlugin(client, factory, config ?? DcvConfig());

        private static EnrollmentProductInfo MakeProductInfo() =>
            new EnrollmentProductInfo
            {
                ProductID         = MockCertificateData.ProfileIdTls,
                ProductParameters = new Dictionary<string, string> { ["ProfileId"] = MockCertificateData.ProfileIdTls }
            };

        /// <summary>
        /// Returns a mock client pre-wired for the full happy-path DCV flow:
        /// Enroll → TrackOrder (DCV pending) → GetDcv → VerifyDcv → GetCertificate.
        /// </summary>
        private static (Mock<ICERTInextClient> mock, FakeDomainValidator validator) HappyPathMocks(
            string orderNumber = MockCertificateData.DcvOrderId,
            string domain      = MockCertificateData.DcvDomain,
            string token       = MockCertificateData.DcvToken)
        {
            var mock = NewMock();

            mock.Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(new EnrollCertificateResponse { Id = orderNumber, Status = "pending_dcv" });

            // First call: pending (initial check in PerformDcvIfNeededAsync)
            // Subsequent calls: verified (polling in WaitForDcvVerificationAsync)
            mock.SetupSequence(c => c.TrackOrderAsync(orderNumber, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.DcvPendingTrackResponse(orderNumber, domain))
                .ReturnsAsync(MockCertificateData.DcvVerifiedTrackResponse(orderNumber, domain));

            mock.Setup(c => c.GetDcvAsync(orderNumber, domain, Constants.Dcv.MethodDnsTxt, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.DcvTokenResponse(token));

            mock.Setup(c => c.VerifyDcvAsync(orderNumber, domain, Constants.Dcv.MethodDnsTxt, It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            mock.Setup(c => c.GetCertificateAsync(orderNumber, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord(orderNumber));

            var validator = new FakeDomainValidator();
            return (mock, validator);
        }

        private static Task<EnrollmentResult> Enroll(CERTInextCAPlugin plugin) =>
            plugin.Enroll(
                csr:            MockCertificateData.FakeCsrPem,
                subject:        $"CN={MockCertificateData.DcvDomain}",
                san:            new Dictionary<string, string[]> { ["dns"] = new[] { MockCertificateData.DcvDomain } },
                productInfo:    MakeProductInfo(),
                requestFormat:  RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

        // ---------------------------------------------------------------------------
        // Happy path
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Dcv_HappyPath_StagesVerifiesAndCleansUp()
        {
            var (mock, validator) = HappyPathMocks();
            // Issuance budget > 0 so the post-DCV GetCertificate poll runs and lifts the
            // issued cert out of the mock back into the EnrollmentResult.
            var plugin = BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator),
                DcvConfig(dcvWaitForIssuanceSeconds: 10));

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            result.Certificate.Should().Contain("BEGIN CERTIFICATE");

            // Verify Stage was called with the right hostname and token
            string expectedHostname = string.Format(Constants.Dcv.DefaultTxtRecordTemplate, MockCertificateData.DcvDomain);
            validator.StagedRecords.Should().ContainSingle()
                .Which.Should().Be((expectedHostname, MockCertificateData.DcvToken));

            // Verify Cleanup was called (always, including on success)
            validator.CleanedUpKeys.Should().ContainSingle().Which.Should().Be(expectedHostname);

            mock.Verify(c => c.VerifyDcvAsync(
                MockCertificateData.DcvOrderId,
                MockCertificateData.DcvDomain,
                Constants.Dcv.MethodDnsTxt,
                It.IsAny<CancellationToken>()), Times.Once);

            mock.Verify(c => c.GetCertificateAsync(MockCertificateData.DcvOrderId, It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task Dcv_HappyPath_UsesCustomTxtTemplate()
        {
            var (mock, validator) = HappyPathMocks();
            // Issuance budget > 0 so the post-DCV GetCertificate poll runs.
            var config = DcvConfig(dcvWaitForIssuanceSeconds: 10);
            config.DcvTxtRecordTemplate = "dcv-proof.{0}.acme-corp.com";
            var plugin = BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator), config);

            await Enroll(plugin);

            string expectedHostname = $"dcv-proof.{MockCertificateData.DcvDomain}.acme-corp.com";
            validator.StagedRecords.Should().ContainSingle().Which.key.Should().Be(expectedHostname);
            validator.CleanedUpKeys.Should().ContainSingle().Which.Should().Be(expectedHostname);
        }

        // ---------------------------------------------------------------------------
        // DCV skipped conditions
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Dcv_Skipped_WhenOrderAlreadyIssued()
        {
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new EnrollCertificateResponse { Id = MockCertificateData.CertId1, Status = "issued", Certificate = MockCertificateData.FakePemCertificate, SerialNumber = "0A1B2C" });

            mock.Setup(c => c.TrackOrderAsync(MockCertificateData.CertId1, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.AlreadyIssuedTrackResponse());

            var validator = new FakeDomainValidator();
            var plugin = BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator));

            var result = await Enroll(plugin);

            // DCV skipped — order was already issued, result comes from EnrollCertificateAsync directly
            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            validator.StagedRecords.Should().BeEmpty("DCV should be skipped for already-issued orders");
            validator.CleanedUpKeys.Should().BeEmpty();

            mock.Verify(c => c.GetDcvAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Dcv_Skipped_WhenNoDomainVerificationBlock()
        {
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new EnrollCertificateResponse { Id = MockCertificateData.DcvOrderId, Status = "pending" });

            mock.Setup(c => c.TrackOrderAsync(MockCertificateData.DcvOrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new TrackOrderResponse
                {
                    OrderDetails = new TrackOrderResponseDetails
                    {
                        OrderStatusId       = "1",
                        CertificateStatusId = "1",
                        DomainVerification  = null
                    }
                });

            var validator = new FakeDomainValidator();
            var plugin = BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator));

            // PerformDcvIfNeeded returns false → plugin returns result from EnrollCertificateAsync
            var result = await Enroll(plugin);

            validator.StagedRecords.Should().BeEmpty();
            mock.Verify(c => c.GetDcvAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Dcv_SkipsStaging_AndDoesNotIssuancePoll_WhenAllDomainsAlreadyValidated_AndIssuanceBudgetZero()
        {
            // With DcvWaitForIssuanceSeconds=0 (the test fixture's DcvConfig default), an
            // order with DCV already validated short-circuits: no TXT records staged AND
            // no post-DCV GetCertificate poll. Lets sync pick up the cert on its own.
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new EnrollCertificateResponse { Id = MockCertificateData.DcvOrderId, Status = "pending" });

            // domainVerification.status = "1" (Validated) — no pending work
            mock.Setup(c => c.TrackOrderAsync(MockCertificateData.DcvOrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new TrackOrderResponse
                {
                    OrderDetails = new TrackOrderResponseDetails
                    {
                        OrderStatusId       = "1",
                        CertificateStatusId = "1",
                        DomainVerification  = new TrackOrderDomainVerification
                        {
                            Status = Constants.Dcv.StatusValidated
                        }
                    }
                });

            var validator = new FakeDomainValidator();
            var plugin = BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator));

            await Enroll(plugin);

            validator.StagedRecords.Should().BeEmpty();
            mock.Verify(c => c.GetDcvAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            // Issuance budget = 0 means the post-DCV poll short-circuits and GetCertificate
            // is never called from this Enroll() path.
            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Dcv_RunsIssuanceWait_WhenDcvAlreadyValidated_AndIssuanceBudgetPositive()
        {
            // The cached-DCV gap fix: when CERTInext shows DCV already validated (no work
            // for the plugin's DNS-TXT staging) AND the admin has set a positive issuance
            // budget, the plugin should poll GetCertificate until the cert is generated
            // and return the issued result directly from Enroll() — not leave it for sync.
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new EnrollCertificateResponse { Id = MockCertificateData.DcvOrderId, Status = "pending" });

            mock.Setup(c => c.TrackOrderAsync(MockCertificateData.DcvOrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new TrackOrderResponse
                {
                    OrderDetails = new TrackOrderResponseDetails
                    {
                        OrderStatusId       = "1",
                        CertificateStatusId = "1",
                        DomainVerification  = new TrackOrderDomainVerification
                        {
                            Status = Constants.Dcv.StatusValidated
                        }
                    }
                });

            // First post-DCV fetch is still pending; second returns issued.
            mock.SetupSequence(c => c.GetCertificateAsync(MockCertificateData.DcvOrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.PendingCertRecord(MockCertificateData.DcvOrderId))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord(MockCertificateData.DcvOrderId));

            var validator = new FakeDomainValidator();
            var plugin = BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator),
                DcvConfig(dcvWaitForIssuanceSeconds: 10));

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED,
                "the issuance poll must lift the issued cert into the EnrollmentResult, " +
                "not let the order fall through to a pending-then-sync round-trip");
            validator.StagedRecords.Should().BeEmpty("no TXT staging is needed when DCV is already validated");
            mock.Verify(c => c.GetDcvAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            mock.Verify(c => c.GetCertificateAsync(MockCertificateData.DcvOrderId, It.IsAny<CancellationToken>()),
                Times.AtLeast(2), "plugin should have polled at least twice to see the cert transition to issued");
        }

        [Fact]
        public async Task Dcv_Skipped_WhenDcvEnabledFalse()
        {
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedEnrollResponse());

            var validator = new FakeDomainValidator();
            var config = DcvConfig(enabled: false);
            var plugin = BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator), config);

            await Enroll(plugin);

            validator.StagedRecords.Should().BeEmpty("DCV should not run when DcvEnabled=false");
            mock.Verify(c => c.TrackOrderAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // Issue #7 — IDomainValidatorFactory is optional / injected post-construction
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Dcv_SilentlyNoOps_WhenNoFactoryInjected_AndDcvEnabledTrue()
        {
            // Simulates a v3.2 gateway host: plugin instantiated via the parameterless
            // public production constructor, DcvEnabled=true in the connector config,
            // but no IDomainValidatorFactory was injected via SetDomainValidatorFactory
            // (because the host's IAnyCAPlugin assembly doesn't even have that interface).
            // Enroll must:
            //   * NOT throw (no missing-type / null-factory exception),
            //   * NOT touch the CA's TrackOrder for DCV purposes,
            //   * return the enrollment result the CA gave us (here: pending).
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.PendingEnrollResponse());

            // Internal test ctor with factory = null AND DcvEnabled = true.
            var plugin = new CERTInextCAPlugin(mock.Object, domainValidatorFactory: null, DcvConfig(enabled: true));

            var result = await Enroll(plugin);

            result.Should().NotBeNull();
            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION,
                "with no factory the CA's pending response must be passed through unchanged");
            mock.Verify(c => c.TrackOrderAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never,
                "EnrollNewAsync must short-circuit the DCV block when _domainValidatorFactory is null");
        }

        [Fact]
        public async Task SetDomainValidatorFactory_AfterConstruction_WiresFactoryForSubsequentEnroll()
        {
            // The v3.3+ gateway path: host instantiates the plugin via the parameterless
            // public constructor, resolves an IDomainValidatorFactory from its own
            // service container, then calls SetDomainValidatorFactory(factory) before
            // Initialize.  Subsequent Enroll() calls must use the injected factory.
            var (mock, validator) = HappyPathMocks();

            // Plugin starts with NO factory — proves the setter does the wire-up, not
            // some prior constructor parameter.
            var plugin = new CERTInextCAPlugin(
                mock.Object,
                domainValidatorFactory: null,
                DcvConfig(dcvWaitForIssuanceSeconds: 10));

            plugin.SetDomainValidatorFactory(new FakeDomainValidatorFactory(validator));

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED,
                "the factory injected via SetDomainValidatorFactory must drive DCV end-to-end");
            validator.StagedRecords.Should().NotBeEmpty(
                "SetDomainValidatorFactory must populate _domainValidatorFactory so DCV staging runs");
        }

        [Fact]
        public async Task SetDomainValidatorFactory_SecondCall_OverridesFirst()
        {
            // Property-style setter semantics: the most recent SetDomainValidatorFactory
            // call wins. Important for gateway hosts that may resolve a fresh factory
            // per-initialize cycle.  Tested behaviorally — drive Enroll() and assert
            // the SECOND factory's validator received the TXT staging call (no reflection
            // on internal fields).
            var (mock, _) = HappyPathMocks();
            var firstValidator = new FakeDomainValidator();
            var secondValidator = new FakeDomainValidator();

            var plugin = new CERTInextCAPlugin(
                mock.Object,
                domainValidatorFactory: null,
                DcvConfig(dcvWaitForIssuanceSeconds: 10));

            // First setter call is ignored by the override; only the second factory's
            // validator should ever see traffic.
            plugin.SetDomainValidatorFactory(new FakeDomainValidatorFactory(firstValidator));
            plugin.SetDomainValidatorFactory(new FakeDomainValidatorFactory(secondValidator));

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            firstValidator.StagedRecords.Should().BeEmpty(
                "the first factory must be replaced — its validator should never be called");
            secondValidator.StagedRecords.Should().NotBeEmpty(
                "the second SetDomainValidatorFactory call must replace the first; its validator drives DCV");
        }

        // ---------------------------------------------------------------------------
        // Cancelled/rejected orders short-circuit even with validated DCV state
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData("4")] // OrderStatusId 4 = Order Cancelled
        [InlineData("5")] // OrderStatusId 5 = Order Rejected
        public async Task Dcv_Skipped_WhenOrderStatusIdIsTerminal_EvenIfDcvValidated(string terminalOrderStatusId)
        {
            // Regression guard for the cached-DCV path: a cancelled or rejected order
            // can still have domainVerification.Status="1" carried over from a prior
            // validated round. Without this guard the plugin would return true from
            // PerformDcvIfNeededAsync and the caller would spend the full
            // DcvWaitForIssuanceSeconds budget polling GetCertificate for a cert that
            // is never going to issue. Per audit report B2 on PR #2.
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new EnrollCertificateResponse { Id = MockCertificateData.DcvOrderId, Status = "pending" });

            mock.Setup(c => c.TrackOrderAsync(MockCertificateData.DcvOrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new TrackOrderResponse
                {
                    OrderDetails = new TrackOrderResponseDetails
                    {
                        OrderStatusId       = terminalOrderStatusId,
                        CertificateStatusId = "1",
                        // Validated DCV state — without the OrderStatusId guard this would
                        // erroneously trigger the issuance-wait path.
                        DomainVerification  = new TrackOrderDomainVerification
                        {
                            Status = Constants.Dcv.StatusValidated
                        }
                    }
                });

            var validator = new FakeDomainValidator();
            // Issuance-wait budget > 0 AND pickup ENABLED (pickupRetries > 0) so a wrong-path
            // entry would manifest as a GetCertificate call we DON'T expect — this test must
            // fail if either the DCV issuance-wait guard OR the synchronous-pickup gate
            // (dcvIssuanceWaitRan) regresses and starts polling a cancelled/rejected order.
            var plugin = BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator),
                DcvConfig(dcvWaitForIssuanceSeconds: 10, pickupRetries: 5));

            await Enroll(plugin);

            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Never,
                "Enroll must not enter WaitForIssuanceAfterDcvAsync OR the synchronous pickup poll " +
                "when the order is cancelled/rejected, even if DCV happens to be in a 'validated' state");
            validator.StagedRecords.Should().BeEmpty(
                "DCV staging must not run for a cancelled/rejected order");
        }

        // ---------------------------------------------------------------------------
        // Sync path is single-shot for the DCV challenge wait
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task SyncDcvRetry_DoesSingleShotTrackOrder_WhenChallengeNotReady()
        {
            // Sync MUST NOT poll the configured DcvWaitForChallengeSeconds budget per
            // pending order — that would scale O(orders × 60s) per cycle and tie up
            // gateway threads for minutes per sync.  When TrackOrder returns null
            // domainVerification, sync exits immediately and lets the next sync cycle
            // pick the order up.
            var mock = NewMock();

            // High config budget — would normally drive 6+ polls × 5s waits.  The sync
            // override of 0 must prevent that.
            var config = DcvConfig(dcvWaitForChallengeSeconds: 60);

            mock.Setup(c => c.TrackOrderAsync(MockCertificateData.DcvOrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new TrackOrderResponse
                {
                    OrderDetails = new TrackOrderResponseDetails
                    {
                        OrderStatusId       = "1",
                        CertificateStatusId = "1",
                        DomainVerification  = null
                    }
                });

            // GetSingleRecord calls GetCertificateAsync first to materialize the record;
            // the sync-DCV-retry kicks in afterwards.  The pending response keeps the
            // retry path engaged so we exercise the override.  The assertion below pins
            // Times.Exactly(1) on TrackOrderAsync: with override=0, the polling loop
            // takes one TrackOrder call, sees domainVerification null, and bails — no
            // further polls inside the 60s budget the config nominally allows.
            mock.Setup(c => c.GetCertificateAsync(MockCertificateData.DcvOrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.PendingCertRecord(MockCertificateData.DcvOrderId));

            var validator = new FakeDomainValidator();
            var plugin = BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator), config);

            var sw = System.Diagnostics.Stopwatch.StartNew();
            // GetSingleRecord calls TryRunDcvDuringSyncAsync internally — which is the
            // sync-style path with waitForChallengeSecondsOverride=0.
            var record = await plugin.GetSingleRecord(MockCertificateData.DcvOrderId);
            sw.Stop();

            record.Should().NotBeNull();
            // The 0-budget single shot must complete well under the 60s config budget.
            // Use a generous 10s ceiling to tolerate slow CI hosts; the actual cost is
            // ~1 TrackOrder.  Without the override we'd be ≥60s.
            sw.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(10),
                "sync's DCV retry must be single-shot, not poll the configured challenge budget");

            mock.Verify(c => c.TrackOrderAsync(MockCertificateData.DcvOrderId, It.IsAny<CancellationToken>()),
                Times.Exactly(1),
                "PerformDcvIfNeededAsync's single-shot challenge check must make exactly ONE " +
                "TrackOrder call when waitForChallengeSecondsOverride=0 and the slot is null. " +
                "Without the override, the polling loop would issue many more calls within " +
                "the 60s budget.");
        }

        // ---------------------------------------------------------------------------
        // Failure modes
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Dcv_Throws_WhenNoProviderForDomain()
        {
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new EnrollCertificateResponse { Id = MockCertificateData.DcvOrderId, Status = "pending" });

            mock.Setup(c => c.TrackOrderAsync(MockCertificateData.DcvOrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.DcvPendingTrackResponse());

            mock.Setup(c => c.GetDcvAsync(MockCertificateData.DcvOrderId, MockCertificateData.DcvDomain, Constants.Dcv.MethodDnsTxt, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.DcvTokenResponse());

            // Factory returns null → no DNS provider configured
            var plugin = BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator: null));

            Func<Task> act = () => Enroll(plugin);

            await act.Should().ThrowAsync<InvalidOperationException>()
                .WithMessage("*No DNS provider plugin is configured*");
        }

        [Fact]
        public async Task Dcv_Throws_WhenStageValidationFails()
        {
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new EnrollCertificateResponse { Id = MockCertificateData.DcvOrderId, Status = "pending" });

            mock.Setup(c => c.TrackOrderAsync(MockCertificateData.DcvOrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.DcvPendingTrackResponse());

            mock.Setup(c => c.GetDcvAsync(MockCertificateData.DcvOrderId, MockCertificateData.DcvDomain, Constants.Dcv.MethodDnsTxt, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.DcvTokenResponse());

            var validator = new FakeDomainValidator { StageSucceeds = false, StageError = "DNS zone not writable" };
            var plugin = BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator));

            Func<Task> act = () => Enroll(plugin);

            await act.Should().ThrowAsync<InvalidOperationException>()
                .WithMessage("*Failed to stage DNS validation*DNS zone not writable*");

            // No VerifyDcv call — failed before reaching that step
            mock.Verify(c => c.VerifyDcvAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Dcv_CleanupAlwaysCalled_EvenWhenVerifyDcvThrows()
        {
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new EnrollCertificateResponse { Id = MockCertificateData.DcvOrderId, Status = "pending" });

            mock.Setup(c => c.TrackOrderAsync(MockCertificateData.DcvOrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.DcvPendingTrackResponse());

            mock.Setup(c => c.GetDcvAsync(MockCertificateData.DcvOrderId, MockCertificateData.DcvDomain, Constants.Dcv.MethodDnsTxt, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.DcvTokenResponse());

            mock.Setup(c => c.VerifyDcvAsync(MockCertificateData.DcvOrderId, MockCertificateData.DcvDomain, Constants.Dcv.MethodDnsTxt, It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("CERTInext DNS record not found"));

            var validator = new FakeDomainValidator();
            var plugin = BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator));

            Func<Task> act = () => Enroll(plugin);

            await act.Should().ThrowAsync<Exception>().WithMessage("*DNS record not found*");

            // Cleanup must run even when VerifyDcv throws
            string expectedHostname = string.Format(Constants.Dcv.DefaultTxtRecordTemplate, MockCertificateData.DcvDomain);
            validator.CleanedUpKeys.Should().ContainSingle().Which.Should().Be(expectedHostname);
        }

        [Fact]
        public async Task Dcv_Throws_WhenGetDcvReturnsNoToken()
        {
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new EnrollCertificateResponse { Id = MockCertificateData.DcvOrderId, Status = "pending" });

            mock.Setup(c => c.TrackOrderAsync(MockCertificateData.DcvOrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.DcvPendingTrackResponse());

            mock.Setup(c => c.GetDcvAsync(MockCertificateData.DcvOrderId, MockCertificateData.DcvDomain, Constants.Dcv.MethodDnsTxt, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new GetDcvResponse { DcvDetails = new DcvResponseDetails { Token = null } });

            var validator = new FakeDomainValidator();
            var plugin = BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator));

            Func<Task> act = () => Enroll(plugin);

            await act.Should().ThrowAsync<InvalidOperationException>()
                .WithMessage("*GetDcv returned no token*");
        }

        // ---------------------------------------------------------------------------
        // EMS-956 tolerance — see analysis/certinext-support-ticket-2026-05-12.md
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Dcv_Defers_When_GetDcv_ReturnsEms956()
        {
            // Simulates the post-pre-vetted-org behaviour: TrackOrder shows a pending DCV
            // slot, but CERTInext's GetDcv endpoint still rejects calls with EMS-956 for a
            // window after enrollment. Plugin must NOT throw — it must return the pending
            // result so the gateway records the order and the sync-retry can pick it up.
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new EnrollCertificateResponse { Id = MockCertificateData.DcvOrderId, Status = "pending_dcv" });

            mock.Setup(c => c.TrackOrderAsync(MockCertificateData.DcvOrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.DcvPendingTrackResponse());

            mock.Setup(c => c.GetDcvAsync(MockCertificateData.DcvOrderId, MockCertificateData.DcvDomain, Constants.Dcv.MethodDnsTxt, It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception(
                    "CERTInext GetDcv failed for order '" + MockCertificateData.DcvOrderId + "': EMS-956 Invalid Request for this API."));

            var validator = new FakeDomainValidator();
            var plugin = BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator));

            // Should NOT throw — must return pending enrollment result so the gateway
            // records the order and lets sync-retry recover later.
            var result = await Enroll(plugin);
            result.Should().NotBeNull();

            // The DNS provider must not have been touched — staging a TXT record without a
            // valid token would be wasted work and could collide with the future retry.
            validator.StagedRecords.Should().BeEmpty();
            validator.CleanedUpKeys.Should().BeEmpty();

            // VerifyDcv must never be called either.
            mock.Verify(c => c.VerifyDcvAsync(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Never);
        }

        [Fact]
        public async Task Dcv_Defers_When_GetDcv_ReturnsInvalidRequestMessage_WithoutEms956Code()
        {
            // Tolerance must also match the human-readable phrase, not only the error code,
            // because the CERTInext client wraps non-200 responses in a generic Exception
            // whose Message is the upstream errorMessage field (sometimes without the code).
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new EnrollCertificateResponse { Id = MockCertificateData.DcvOrderId, Status = "pending_dcv" });

            mock.Setup(c => c.TrackOrderAsync(MockCertificateData.DcvOrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.DcvPendingTrackResponse());

            mock.Setup(c => c.GetDcvAsync(MockCertificateData.DcvOrderId, MockCertificateData.DcvDomain, Constants.Dcv.MethodDnsTxt, It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("Invalid Request for this API"));

            var validator = new FakeDomainValidator();
            var plugin = BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator));

            var result = await Enroll(plugin);
            result.Should().NotBeNull();
            validator.StagedRecords.Should().BeEmpty();
        }

        [Fact]
        public async Task Dcv_Rethrows_When_GetDcv_FailsWithUnrelatedError()
        {
            // Tolerance is narrow: a genuine server error (5xx, transport, auth) must still
            // bubble up so the gateway treats the enrollment as failed and the operator can
            // diagnose. This guards against accidentally swallowing every GetDcv exception.
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new EnrollCertificateResponse { Id = MockCertificateData.DcvOrderId, Status = "pending_dcv" });

            mock.Setup(c => c.TrackOrderAsync(MockCertificateData.DcvOrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.DcvPendingTrackResponse());

            mock.Setup(c => c.GetDcvAsync(MockCertificateData.DcvOrderId, MockCertificateData.DcvDomain, Constants.Dcv.MethodDnsTxt, It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("HTTP 500: Internal Server Error"));

            var validator = new FakeDomainValidator();
            var plugin = BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator));

            Func<Task> act = () => Enroll(plugin);
            await act.Should().ThrowAsync<Exception>()
                .WithMessage("*HTTP 500*");
        }

        // ---------------------------------------------------------------------------
        // DcvWaitForChallengeSeconds — wait for domainVerification to appear
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Dcv_WaitsForChallenge_WhenDomainVerificationAppearsLate()
        {
            // First TrackOrder returns null domainVerification (CERTInext hasn't materialised
            // the slot yet), second returns a populated pending slot.  With a positive
            // DcvWaitForChallengeSeconds the plugin must poll and proceed with DCV, NOT skip.
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new EnrollCertificateResponse { Id = MockCertificateData.DcvOrderId, Status = "pending_dcv" });

            // Sequence: 1st TrackOrder = no DCV slot, 2nd = pending, then verified for the wait poll.
            mock.SetupSequence(c => c.TrackOrderAsync(MockCertificateData.DcvOrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new TrackOrderResponse
                {
                    OrderDetails = new TrackOrderResponseDetails
                    {
                        OrderStatusId       = "1",
                        CertificateStatusId = "1",
                        DomainVerification  = null
                    }
                })
                .ReturnsAsync(MockCertificateData.DcvPendingTrackResponse())
                .ReturnsAsync(MockCertificateData.DcvVerifiedTrackResponse());

            mock.Setup(c => c.GetDcvAsync(MockCertificateData.DcvOrderId, MockCertificateData.DcvDomain, Constants.Dcv.MethodDnsTxt, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.DcvTokenResponse());
            mock.Setup(c => c.VerifyDcvAsync(MockCertificateData.DcvOrderId, MockCertificateData.DcvDomain, Constants.Dcv.MethodDnsTxt, It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.GetCertificateAsync(MockCertificateData.DcvOrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord(MockCertificateData.DcvOrderId));

            var validator = new FakeDomainValidator();
            // Both budgets positive so the polling paths exercise end-to-end.
            var plugin = BuildPlugin(
                mock.Object,
                new FakeDomainValidatorFactory(validator),
                DcvConfig(dcvWaitForChallengeSeconds: 10, dcvWaitForIssuanceSeconds: 10));

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            validator.StagedRecords.Should().NotBeEmpty("DCV must have run after polling found the slot");
        }

        [Fact]
        public async Task Dcv_GivesUpWaitingForChallenge_AfterBudgetExpires()
        {
            // domainVerification stays null forever.  With a short positive budget the plugin
            // must poll for the budget and then return false (deferred to sync), NOT throw.
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new EnrollCertificateResponse { Id = MockCertificateData.DcvOrderId, Status = "pending" });

            mock.Setup(c => c.TrackOrderAsync(MockCertificateData.DcvOrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new TrackOrderResponse
                {
                    OrderDetails = new TrackOrderResponseDetails
                    {
                        OrderStatusId       = "1",
                        CertificateStatusId = "1",
                        DomainVerification  = null
                    }
                });

            var validator = new FakeDomainValidator();
            // 5-second budget keeps the test fast but tolerates loaded CI hosts where a
            // 2-second budget could overshoot to a single poll.
            var plugin = BuildPlugin(
                mock.Object,
                new FakeDomainValidatorFactory(validator),
                DcvConfig(dcvWaitForChallengeSeconds: 5));

            var result = await Enroll(plugin);

            result.Should().NotBeNull();
            validator.StagedRecords.Should().BeEmpty("no DCV slot was ever exposed");
            mock.Verify(c => c.TrackOrderAsync(MockCertificateData.DcvOrderId, It.IsAny<CancellationToken>()),
                Times.AtLeast(2), "plugin should have polled at least twice within the 5-second budget");
        }

        // ---------------------------------------------------------------------------
        // DcvWaitForIssuanceSeconds — wait for cert PEM after DCV verifies
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Dcv_WaitsForIssuance_AfterDcvVerifies()
        {
            // First post-DCV GetCertificate returns pending; second returns issued. Plugin
            // must poll and return the issued result to Enroll(), not the first pending one.
            var (mock, validator) = HappyPathMocks();

            // Override default GetCertificate setup: first pending, then issued.
            mock.SetupSequence(c => c.GetCertificateAsync(MockCertificateData.DcvOrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.PendingCertRecord(MockCertificateData.DcvOrderId))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord(MockCertificateData.DcvOrderId));

            var plugin = BuildPlugin(
                mock.Object,
                new FakeDomainValidatorFactory(validator),
                DcvConfig(dcvWaitForIssuanceSeconds: 10));

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED,
                "post-DCV polling must return the issued status, not the first pending fetch");
            mock.Verify(c => c.GetCertificateAsync(MockCertificateData.DcvOrderId, It.IsAny<CancellationToken>()),
                Times.AtLeast(2), "plugin should have polled at least twice for issuance");
        }

        // ---------------------------------------------------------------------------
        // Undrainable pending domains must not strand the valid ones on the same order
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Builds a TrackOrder response whose domainVerification block lists several pending
        /// domains, so tests can mix validatable and unvalidatable keys on one order.
        /// </summary>
        private static TrackOrderResponse DcvPendingTrackResponseMultiDomain(
            string orderNumber, params string[] domains)
        {
            var detail = System.Text.Json.JsonSerializer.SerializeToElement(new DomainVerificationDetail
            {
                DcvMethod = Constants.Dcv.MethodDnsTxt,
                DcvStatus = Constants.Dcv.StatusPending,
                Status    = "1"
            });

            var raw = new Dictionary<string, System.Text.Json.JsonElement>();
            foreach (string d in domains)
                raw[d] = detail;

            return new TrackOrderResponse
            {
                OrderDetails = new TrackOrderResponseDetails
                {
                    OrderStatusId       = "1",
                    CertificateStatusId = "1",
                    DomainVerification  = new TrackOrderDomainVerification
                    {
                        Status           = Constants.Dcv.StatusPending,
                        RawDomainEntries = raw
                    }
                }
            };
        }

        /// <summary>
        /// Builds a TrackOrder response with one already-validated domain (dcvStatus=1) and one
        /// still-pending, unresolvable domain (dcvStatus=0) — the shape CERTInext produces when it
        /// has cached a prior DCV validation for the CN while a non-DNS SAN on the same order is
        /// still outstanding.
        /// </summary>
        private static TrackOrderResponse DcvMixedStatusTrackResponse(
            string validatedDomain, string pendingDomain)
        {
            var validated = System.Text.Json.JsonSerializer.SerializeToElement(new DomainVerificationDetail
            {
                DcvMethod = Constants.Dcv.MethodDnsTxt,
                DcvStatus = Constants.Dcv.StatusValidated,
                Status    = "1"
            });
            var pending = System.Text.Json.JsonSerializer.SerializeToElement(new DomainVerificationDetail
            {
                DcvMethod = Constants.Dcv.MethodDnsTxt,
                DcvStatus = Constants.Dcv.StatusPending,
                Status    = "1"
            });

            return new TrackOrderResponse
            {
                OrderDetails = new TrackOrderResponseDetails
                {
                    OrderStatusId       = "1",
                    CertificateStatusId = "1",
                    DomainVerification  = new TrackOrderDomainVerification
                    {
                        // Aggregate stays pending because one domain still is — this must not take
                        // the early "already validated" return at the top of the method.
                        Status           = Constants.Dcv.StatusPending,
                        RawDomainEntries = new Dictionary<string, System.Text.Json.JsonElement>
                        {
                            [validatedDomain] = validated,
                            [pendingDomain]    = pending
                        }
                    }
                }
            };
        }

        /// <summary>
        /// Regression for the false invariant behind the round-1 fix's own misconfiguration check:
        /// "the CN is always a pending domain too" is untrue whenever CERTInext has cached a prior
        /// DCV validation for it (a case this same file's cached-validation branch documents), so a
        /// non-DNS SAN sharing the order with an already-validated CN must not throw — it must defer
        /// to the next sync cycle exactly like the single-domain case does.
        /// </summary>
        [Fact]
        public async Task Dcv_CachedCnPlusUnresolvableSan_DefersWithoutThrowing()
        {
            const string order   = MockCertificateData.DcvOrderId;
            const string cn      = MockCertificateData.DcvDomain;
            const string ip      = "192.0.2.10";

            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new EnrollCertificateResponse { Id = order, Status = "pending" });

            mock.Setup(c => c.TrackOrderAsync(order, It.IsAny<CancellationToken>()))
                .ReturnsAsync(DcvMixedStatusTrackResponse(validatedDomain: cn, pendingDomain: ip));

            // The IP clears the FQDN regex and reaches GetDcv, per the sandbox-measured shape.
            mock.Setup(c => c.GetDcvAsync(order, ip, Constants.Dcv.MethodDnsTxt, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.DcvTokenResponse(MockCertificateData.DcvToken));

            var validator = new FakeDomainValidator();
            // Resolves for the CN (a real, working DNS provider) but not for the IP literal — the
            // scenario that must prove "a provider IS deployed" rather than "nothing is deployed".
            var plugin = BuildPlugin(
                mock.Object,
                new SelectiveDomainValidatorFactory(validator, resolvableDomain: cn),
                DcvConfig());

            Func<Task> act = () => Enroll(plugin);

            await act.Should().NotThrowAsync(
                "an unresolvable non-DNS SAN must defer the order to the next sync cycle, not fail " +
                "the enrollment — the CN having cached DCV proves a provider is deployed and working, " +
                "so this is not the 'nothing is deployed' misconfiguration case");

            validator.StagedRecords.Should().BeEmpty(
                "the only pending domain is unresolvable, so nothing should have been staged");
        }

        /// <summary>
        /// A non-FQDN pending domain must be skipped, not thrown on.
        ///
        /// Regression: non-DNS SANs are now submitted to CERTInext, which registers them verbatim
        /// as order domains, so an email/URI SAN turns up as a domainVerification key that fails the
        /// FQDN check. That check used to throw for the whole order — escaping Enroll (which has no
        /// catch) after the order was already placed, so the enrollment failed with an orphaned
        /// order and no TXT record was staged for the *valid* domains beside it. Every sync retry
        /// re-threw and TryRunDcvDuringSyncAsync swallowed it, so the order could never progress.
        /// </summary>
        [Fact]
        public async Task Dcv_NonFqdnPendingDomain_IsSkipped_AndValidDomainStillStaged()
        {
            const string order = MockCertificateData.DcvOrderId;
            const string good  = MockCertificateData.DcvDomain;
            const string bad   = "admin@example.com";   // what an rfc822 SAN comes back as

            var mock = NewMock();

            mock.Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new EnrollCertificateResponse { Id = order, Status = "pending_dcv" });

            mock.SetupSequence(c => c.TrackOrderAsync(order, It.IsAny<CancellationToken>()))
                .ReturnsAsync(DcvPendingTrackResponseMultiDomain(order, good, bad))
                .ReturnsAsync(MockCertificateData.DcvVerifiedTrackResponse(order, good));

            // Only the valid domain should ever reach GetDcv/VerifyDcv. MockBehavior.Strict means
            // an unexpected call for `bad` fails the test on its own.
            mock.Setup(c => c.GetDcvAsync(order, good, Constants.Dcv.MethodDnsTxt, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.DcvTokenResponse(MockCertificateData.DcvToken));
            mock.Setup(c => c.VerifyDcvAsync(order, good, Constants.Dcv.MethodDnsTxt, It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.GetCertificateAsync(order, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord(order));

            var validator = new FakeDomainValidator();
            var plugin = BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator),
                DcvConfig(dcvWaitForIssuanceSeconds: 10));

            // Must not throw — that is the regression.
            var result = await Enroll(plugin);

            string expectedHostname = string.Format(Constants.Dcv.DefaultTxtRecordTemplate, good);
            validator.StagedRecords.Should().ContainSingle(
                "the valid DNS domain must still be staged even though a co-tenant domain is unusable")
                .Which.Should().Be((expectedHostname, MockCertificateData.DcvToken));

            mock.Verify(c => c.GetDcvAsync(order, bad, It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Never, "a non-FQDN domain must never be sent to GetDcv");
            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
        }

        /// <summary>
        /// A pending domain that resolves no DNS provider (an IP-literal SAN passes the FQDN regex
        /// but no zone can match it) must likewise be skipped rather than failing the whole order.
        /// </summary>
        [Fact]
        public async Task Dcv_DomainWithNoResolvableValidator_IsSkipped_AndValidDomainStillStaged()
        {
            const string order = MockCertificateData.DcvOrderId;
            const string good  = MockCertificateData.DcvDomain;
            const string ip    = "192.0.2.10";   // what an iPAddress SAN comes back as

            var mock = NewMock();

            mock.Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new EnrollCertificateResponse { Id = order, Status = "pending_dcv" });

            mock.SetupSequence(c => c.TrackOrderAsync(order, It.IsAny<CancellationToken>()))
                .ReturnsAsync(DcvPendingTrackResponseMultiDomain(order, good, ip))
                .ReturnsAsync(MockCertificateData.DcvVerifiedTrackResponse(order, good));

            // The IP literal clears the FQDN filter, so GetDcv IS called for it; the dead end is
            // that no validator resolves. Stub it so reaching that point is legitimate.
            mock.Setup(c => c.GetDcvAsync(order, It.IsAny<string>(), Constants.Dcv.MethodDnsTxt, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.DcvTokenResponse(MockCertificateData.DcvToken));
            mock.Setup(c => c.VerifyDcvAsync(order, good, Constants.Dcv.MethodDnsTxt, It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.GetCertificateAsync(order, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord(order));

            var validator = new FakeDomainValidator();
            var plugin = BuildPlugin(
                mock.Object,
                new SelectiveDomainValidatorFactory(validator, resolvableDomain: good),
                DcvConfig(dcvWaitForIssuanceSeconds: 10));

            var result = await Enroll(plugin);

            string expectedHostname = string.Format(Constants.Dcv.DefaultTxtRecordTemplate, good);
            validator.StagedRecords.Should().ContainSingle(
                "only the domain with a resolvable provider should be staged, and it must still be staged")
                .Which.Should().Be((expectedHostname, MockCertificateData.DcvToken));
            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
        }

        /// <summary>Factory that resolves a validator for exactly one domain and null for all others.</summary>
        private sealed class SelectiveDomainValidatorFactory : IDomainValidatorFactory
        {
            private readonly IDomainValidator _validator;
            private readonly string _resolvableDomain;

            public SelectiveDomainValidatorFactory(IDomainValidator validator, string resolvableDomain)
            {
                _validator = validator;
                _resolvableDomain = resolvableDomain;
            }

            public IDomainValidator ResolveDomainValidator(string domain, string validationType) =>
                string.Equals(domain, _resolvableDomain, StringComparison.OrdinalIgnoreCase) ? _validator : null;

            public IDomainValidator PrimaryValidator => _validator;
        }

        /// <summary>
        /// Like <see cref="FakeDomainValidator"/>, but StageValidation fails only for hostnames
        /// matching <see cref="_failingHostnameSubstring"/> — needed to prove that a failure on one
        /// domain of a multi-domain order still cleans up what was already staged for the others.
        /// </summary>
        private sealed class PartiallyFailingDomainValidator : IDomainValidator
        {
            private readonly string _failingHostnameSubstring;

            public PartiallyFailingDomainValidator(string failingHostnameSubstring) =>
                _failingHostnameSubstring = failingHostnameSubstring;

            public List<(string key, string value)> StagedRecords { get; } = new();
            public List<string> CleanedUpKeys { get; } = new();

            public void Initialize(IDomainValidatorConfigProvider configProvider) { }

            public Task<DomainValidationResult> StageValidation(string key, string value, CancellationToken cancellationToken)
            {
                bool shouldFail = key.Contains(_failingHostnameSubstring, StringComparison.OrdinalIgnoreCase);
                if (!shouldFail)
                    StagedRecords.Add((key, value));

                return Task.FromResult(new DomainValidationResult
                {
                    Success      = !shouldFail,
                    ErrorMessage = shouldFail ? "Stage failed (test stub, selective)" : null
                });
            }

            public Task<DomainValidationResult> CleanupValidation(string key, CancellationToken cancellationToken)
            {
                CleanedUpKeys.Add(key);
                return Task.FromResult(new DomainValidationResult { Success = true });
            }

            public Task ValidateConfiguration(Dictionary<string, object> configuration) => Task.CompletedTask;
            public Dictionary<string, PropertyConfigInfo> GetDomainValidatorAnnotations() => new();
            public string GetValidationType() => "dns-01";
        }

        /// <summary>
        /// Regression: a StageValidation failure on one domain of a multi-domain order must not
        /// leave the TXT records already published for the earlier domains orphaned. Before the
        /// fix, the staging loop's throw sites were outside the try/finally that owns cleanup, so
        /// this was reachable only by accident (pre-fix, a UCC order's SANs never reached CERTInext
        /// at all, so an order rarely had more than one pending domain to stage). Submitting every
        /// requested SAN makes multi-domain staging the normal case, so this must hold now.
        /// </summary>
        [Fact]
        public async Task Dcv_StageFailureOnSecondDomain_CleansUpFirstDomainsTxtRecord()
        {
            const string order = MockCertificateData.DcvOrderId;
            const string good  = "a.example.com";
            const string bad   = "b.example.com";

            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new EnrollCertificateResponse { Id = order, Status = "pending_dcv" });

            mock.Setup(c => c.TrackOrderAsync(order, It.IsAny<CancellationToken>()))
                .ReturnsAsync(DcvPendingTrackResponseMultiDomain(order, good, bad));

            mock.Setup(c => c.GetDcvAsync(order, good, Constants.Dcv.MethodDnsTxt, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.DcvTokenResponse("token-a"));
            mock.Setup(c => c.GetDcvAsync(order, bad, Constants.Dcv.MethodDnsTxt, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.DcvTokenResponse("token-b"));

            var validator = new PartiallyFailingDomainValidator(failingHostnameSubstring: bad);
            var plugin = BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator));

            Func<Task> act = () => Enroll(plugin);

            await act.Should().ThrowAsync<InvalidOperationException>()
                .WithMessage("*Failed to stage DNS validation*");

            string goodHostname = string.Format(Constants.Dcv.DefaultTxtRecordTemplate, good);
            validator.StagedRecords.Should().ContainSingle(
                "only the domain staged before the failure should have a recorded StageValidation call")
                .Which.key.Should().Be(goodHostname);
            validator.CleanedUpKeys.Should().Contain(goodHostname,
                "the TXT record already published for the domain that succeeded must be removed " +
                "when a later domain in the same order fails to stage — otherwise it is orphaned in " +
                "the customer's DNS zone with nothing else in the codebase to ever clean it up");
        }
    }
}
