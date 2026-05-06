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
            bool enabled                 = true,
            int propagationDelaySeconds  = 1,
            int timeoutMinutes           = 1) =>
            new CERTInextConfig
            {
                DcvEnabled                 = enabled,
                DcvPropagationDelaySeconds = propagationDelaySeconds,
                DcvTimeoutMinutes          = timeoutMinutes
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

            mock.Setup(c => c.TrackOrderAsync(orderNumber, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.DcvPendingTrackResponse(orderNumber, domain));

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
            var plugin = BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator));

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
            var config = DcvConfig();
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
        public async Task Dcv_Skipped_WhenAllDomainsAlreadyValidated()
        {
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
    }
}
