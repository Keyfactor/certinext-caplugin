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
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Regression tests for issues/0020: EMS-1080 ("Domain is already verified") from either
    /// V2 DCV entry point (<c>GetDcvV2Async</c> or <c>VerifyDcvV2Async</c>) must be treated as
    /// DCV already satisfied — skip TXT publish, proceed straight to tracking — not as a
    /// failure deferred to the next sync cycle. Driven end-to-end through
    /// <see cref="CERTInextCAPlugin.Enroll"/> (V2 path) so the assertions exercise the same
    /// code path Command actually calls, using <see cref="FakeDomainValidator"/> to observe
    /// whether a TXT record was ever staged.
    /// </summary>
    public class CERTInextCAPluginV2DcvTests
    {
        private static Mock<ICERTInextClient> NewMock() =>
            new Mock<ICERTInextClient>(MockBehavior.Strict);

        private static CERTInextCAPlugin BuildV2DcvPlugin(
            ICERTInextClient client, IDomainValidatorFactory factory, string dcvTxtRecordTemplate = null,
            int pickupRetries = 0) =>
            new CERTInextCAPlugin(client, factory, new CERTInextConfig
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
                PickupRetries        = pickupRetries,
                PickupDelayInSeconds = 1,
                DcvEnabled                 = true,
                DcvTimeoutMinutes          = 1,
                DcvPropagationDelaySeconds = 1,
                DcvTxtRecordTemplate       = dcvTxtRecordTemplate
            });

        private static EnrollmentProductInfo MakeV2ProductInfo() =>
            new EnrollmentProductInfo
            {
                ProductID = "DV SSL",
                ProductParameters = new Dictionary<string, string>(System.StringComparer.OrdinalIgnoreCase)
                {
                    ["ProductCode"]    = "842",
                    ["ProductFamily"]  = "ssl",
                    ["ProductVariant"] = "dv",
                    ["DomainName"]     = "example.com"
                }
            };

        private static Task<EnrollmentResult> Enroll(CERTInextCAPlugin plugin) =>
            plugin.Enroll(
                csr:            MockCertificateData.FakeCsrPem,
                subject:        "CN=example.com",
                san:            new Dictionary<string, string[]> { ["dns"] = new[] { "example.com" } },
                productInfo:    MakeV2ProductInfo(),
                requestFormat:  RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

        private const string OrderId = "ord_ems1080_001";

        private static V2CreateOrderResponse PlaceOrderResponse() =>
            new V2CreateOrderResponse { OrderId = OrderId, Status = "pending-dcv" };

        private static V2OrderStatusResponse PendingDcvStatus() =>
            new V2OrderStatusResponse { OrderId = OrderId, Status = "pending-dcv", Domain = "example.com" };

        private static V2OrderStatusResponse IssuedStatus() =>
            new V2OrderStatusResponse { OrderId = OrderId, Status = "issued", Domain = "example.com" };

        private static V2CertificateDownloadResponse DownloadResponse() =>
            new V2CertificateDownloadResponse
            {
                OrderId        = OrderId,
                SerialNumber   = "AA11BB22",
                CertificatePem = MockCertificateData.FakePemCertificate
            };

        // ---------------------------------------------------------------------------
        // Regression (issues/0020): GetDcv returns EMS-1080
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task PerformDcvV2_GetDcvReturnsEms1080_TreatedAsSatisfied_NoStagingAndProceedsToTracking()
        {
            var mock = NewMock();
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true } // non-UCC
                });
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(PlaceOrderResponse());

            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            // 1st call: post-CSR check (pending-dcv). 2nd+: the PerformDcvV2IfNeededAsync poll
            // loop and EnrollV2Async's post-DCV re-check both see "issued" immediately.
            mock.SetupSequence(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(PendingDcvStatus())
                .ReturnsAsync(IssuedStatus())
                .ReturnsAsync(IssuedStatus());

            mock.Setup(c => c.GetDcvV2Async(OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new System.Exception(
                    $"CERTInext V2 API error during 'V2 get DCV challenge'. HTTP 422. " +
                    "Unprocessable Entity: EMS-1080 Domain is already verified."));

            mock.Setup(c => c.DownloadCertificateV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(DownloadResponse());

            var validator = new FakeDomainValidator();
            var plugin = BuildV2DcvPlugin(mock.Object, new FakeDomainValidatorFactory(validator));

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED,
                "EMS-1080 must be treated as DCV satisfied, not a failure — the order should " +
                "proceed to tracking and come back issued");
            validator.StagedRecords.Should().BeEmpty(
                "GetDcv returning EMS-1080 means there is no fresh challenge to publish");

            // VerifyDcv must never be reached — there is nothing to verify when GetDcv itself
            // reports the domain is already verified.
            mock.Verify(c => c.VerifyDcvV2Async(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Never);
        }

        // ---------------------------------------------------------------------------
        // Regression (issues/0020): VerifyDcv returns EMS-1080
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task PerformDcvV2_VerifyDcvReturnsEms1080_TreatedAsSatisfied_ProceedsToTracking()
        {
            var mock = NewMock();
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true } // non-UCC
                });
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(PlaceOrderResponse());

            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            mock.SetupSequence(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(PendingDcvStatus())
                .ReturnsAsync(IssuedStatus())
                .ReturnsAsync(IssuedStatus());

            // GetDcv succeeds normally and returns a token to publish...
            mock.Setup(c => c.GetDcvV2Async(OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvChallengeResponse
                {
                    Token           = "dcv-token-abc123",
                    TokenExpiryDate = "2026-12-31 23:59:59"
                });

            // ...but by the time VerifyDcv is called, the domain became already-verified.
            mock.Setup(c => c.VerifyDcvV2Async(OrderId, "example.com", It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new System.Exception(
                    $"CERTInext V2 API error during 'V2 verify DCV'. HTTP 422. " +
                    "Unprocessable Entity: EMS-1080 Domain is already verified."));

            mock.Setup(c => c.DownloadCertificateV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(DownloadResponse());

            var validator = new FakeDomainValidator();
            var plugin = BuildV2DcvPlugin(mock.Object, new FakeDomainValidatorFactory(validator));

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED,
                "EMS-1080 from VerifyDcv must be treated as verified, not a failure — the order " +
                "should proceed to tracking and come back issued");

            // The TXT record was staged (GetDcv succeeded) — this exercises the "verified between
            // GetDcv and VerifyDcv" race rather than the GetDcv-level no-op.
            validator.StagedRecords.Should().ContainSingle();
            validator.CleanedUpKeys.Should().ContainSingle(
                "staged records are always cleaned up, including on the EMS-1080 verify path");
        }

        // ---------------------------------------------------------------------------
        // Regression (issues/0037): live GetDcv response shape has no fileNameContent
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Regression (issues/0037): a live fresh-domain GetDcv challenge response was
        /// captured as exactly <c>{"tokenExpiryDate":"...","token":"..."}</c> — no
        /// <c>orderNumber</c>/<c>domainName</c>/<c>dcvMethod</c>/<c>fileNameContent</c>.
        /// Before the fix, <see cref="V2DcvChallengeResponse"/> modeled <c>fileNameContent</c>
        /// instead of <c>token</c>, so this shape deserialized with a null token, which drove
        /// <c>PerformDcvV2IfNeededAsync</c>'s null-token guard and left the order stuck at
        /// EXTERNALVALIDATION forever (no TXT ever staged, no exception, just a returned
        /// <c>false</c>). This constructs the response exactly as the fixed DTO now
        /// deserializes the real live body, and proves the plugin extracts and publishes the
        /// token instead of deferring.
        /// </summary>
        [Fact]
        public async Task PerformDcvV2_LiveShapeTokenOnly_StagesTxtRecord_DoesNotHitNullTokenGuard()
        {
            var mock = NewMock();
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true } // non-UCC
                });
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(PlaceOrderResponse());

            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            mock.SetupSequence(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(PendingDcvStatus())
                .ReturnsAsync(IssuedStatus())
                .ReturnsAsync(IssuedStatus());

            // Real live shape (issues/0037 probe, 2026-09-25): only Token/TokenExpiryDate are
            // ever populated — no OrderNumber/DomainName/DcvMethod exist on the DTO anymore.
            const string liveToken = "D6026954B9EB7D31E3FE8B2194F07087";
            mock.Setup(c => c.GetDcvV2Async(OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvChallengeResponse
                {
                    Token           = liveToken,
                    TokenExpiryDate = "2026-09-27 15:27:00"
                });

            mock.Setup(c => c.VerifyDcvV2Async(OrderId, "example.com", It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvVerifyResponse { OverallStatus = "VERIFIED" });

            mock.Setup(c => c.DownloadCertificateV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(DownloadResponse());

            var validator = new FakeDomainValidator();
            var plugin = BuildV2DcvPlugin(mock.Object, new FakeDomainValidatorFactory(validator));

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED,
                "the live token-only shape must be extracted and published, not deferred by " +
                "the null-token guard");

            validator.StagedRecords.Should().ContainSingle(
                "GetDcv returned a real token, so a TXT record must be staged from it")
                .Which.Should().Be(("_emsign-validation.example.com", liveToken),
                    "the staged value must come from the new Token property, not the removed " +
                    "FileNameContent property; the hostname uses the default " +
                    "DcvTxtRecordTemplate (issues/0027 item 5a) since none is configured here");

            mock.Verify(c => c.VerifyDcvV2Async(
                OrderId, "example.com", It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Once);
        }

        // ---------------------------------------------------------------------------
        // Regression (issues/0027 item 5a): DcvTxtRecordTemplate must be honored by the V2
        // DCV path, not hardcoded to "_emudhra-challenge.{domain}" — mirrors V1's
        // PerformDcvIfNeededAsync (config value if set, else Constants.Dcv.DefaultTxtRecordTemplate).
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task PerformDcvV2_ConfiguredTxtRecordTemplate_IsHonored()
        {
            var mock = NewMock();
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true } // non-UCC
                });
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(PlaceOrderResponse());

            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            mock.SetupSequence(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(PendingDcvStatus())
                .ReturnsAsync(IssuedStatus())
                .ReturnsAsync(IssuedStatus());

            const string token = "configured-template-token";
            mock.Setup(c => c.GetDcvV2Async(OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvChallengeResponse { Token = token, TokenExpiryDate = "2026-12-31 23:59:59" });

            mock.Setup(c => c.VerifyDcvV2Async(OrderId, "example.com", It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvVerifyResponse { OverallStatus = "VERIFIED" });

            mock.Setup(c => c.DownloadCertificateV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(DownloadResponse());

            var validator = new FakeDomainValidator();
            var plugin = BuildV2DcvPlugin(
                mock.Object, new FakeDomainValidatorFactory(validator),
                dcvTxtRecordTemplate: "_custom-dcv-check.{0}");

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            validator.StagedRecords.Should().ContainSingle()
                .Which.Should().Be(("_custom-dcv-check.example.com", token),
                    "the configured DcvTxtRecordTemplate must be used to build the TXT " +
                    "hostname, not the old hardcoded '_emudhra-challenge' label");
        }

        [Fact]
        public async Task PerformDcvV2_UnconfiguredTxtRecordTemplate_UsesV1Default()
        {
            var mock = NewMock();
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true } // non-UCC
                });
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(PlaceOrderResponse());

            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            mock.SetupSequence(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(PendingDcvStatus())
                .ReturnsAsync(IssuedStatus())
                .ReturnsAsync(IssuedStatus());

            const string token = "default-template-token";
            mock.Setup(c => c.GetDcvV2Async(OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvChallengeResponse { Token = token, TokenExpiryDate = "2026-12-31 23:59:59" });

            mock.Setup(c => c.VerifyDcvV2Async(OrderId, "example.com", It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvVerifyResponse { OverallStatus = "VERIFIED" });

            mock.Setup(c => c.DownloadCertificateV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(DownloadResponse());

            var validator = new FakeDomainValidator();
            // No dcvTxtRecordTemplate override — must fall back to the same default V1 uses.
            var plugin = BuildV2DcvPlugin(mock.Object, new FakeDomainValidatorFactory(validator));

            await Enroll(plugin);

            validator.StagedRecords.Should().ContainSingle()
                .Which.Should().Be(("_emsign-validation.example.com", token),
                    "with no DcvTxtRecordTemplate configured, V2 must fall back to " +
                    "Constants.Dcv.DefaultTxtRecordTemplate (the same default V1 uses) rather " +
                    "than a separate, hardcoded V2 literal");
        }

        // ---------------------------------------------------------------------------
        // Issue 0051: the inline DCV path owns the in-call issuance wait — EnrollV2Async must
        // not stack a second PickUpEnrolledCertificateV2Async poll on top of it.
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task EnrollV2_DcvRan_SkipsPickupPoll_EvenThoughPickupIsEnabled()
        {
            var mock = NewMock();
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true } // non-UCC
                });
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(PlaceOrderResponse());

            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            // 1st call: post-CSR check (pending-dcv). 2nd: PerformDcvV2IfNeededAsync's own
            // tracking poll (step 4) — moves to a *different* pending state so that inner loop
            // breaks (DCV steps completed) without the order having actually issued. 3rd:
            // EnrollV2Async's post-DCV re-check, observing the same still-pending state. If the
            // pickup poll incorrectly ran afterward, a 4th TrackOrderV2Async call would occur.
            mock.SetupSequence(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(PendingDcvStatus())
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "pending-organization-verification", Domain = "example.com" })
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "pending-organization-verification", Domain = "example.com" });

            mock.Setup(c => c.GetDcvV2Async(OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvChallengeResponse { Token = "dcv-token-xyz", TokenExpiryDate = "2026-12-31 23:59:59" });
            mock.Setup(c => c.VerifyDcvV2Async(OrderId, "example.com", It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvVerifyResponse { OverallStatus = "VERIFIED" });

            var validator = new FakeDomainValidator();
            // PickupRetries > 0 and clamped to a fast 1s delay — if the dcvV2Ran gate didn't
            // work, this budget is easily enough for the pickup poll to run and this test would
            // observe extra TrackOrderV2Async/DownloadCertificateV2Async calls.
            var plugin = BuildV2DcvPlugin(mock.Object, new FakeDomainValidatorFactory(validator), pickupRetries: 5);

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION,
                "the order never actually issued — DCV ran, but the order is still pending elsewhere");
            result.CARequestID.Should().Be(OrderId);
            mock.Verify(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()),
                Times.Exactly(3),
                "a pickup poll must not stack on top of the inline DCV wait — no 4th TrackOrderV2Async call");
            mock.Verify(c => c.DownloadCertificateV2Async(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // Issue 0052: a REVOKED disposition discovered on the post-DCV status re-check must be
        // mapped to FAILED, not returned as a body-less REVOKED record — mirrors
        // EnrollV2_DcvRan_SkipsPickupPoll_EvenThoughPickupIsEnabled above, but the second
        // TrackOrderV2Async observation is "revoked" instead of another pending state.
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task EnrollV2_PostDcvRecheckRevoked_ReturnsFailed_NotBodylessRevoked()
        {
            var mock = NewMock();
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true } // non-UCC
                });
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(PlaceOrderResponse());

            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            // 1st call: post-CSR check (pending-dcv), triggers the inline DCV block. 2nd:
            // PerformDcvV2SingleDomainAsync's own internal step-4 poll (it calls
            // TrackOrderV2Async itself to wait out "pending-dcv" — see its doc comment) observes
            // "revoked", which is != "pending-dcv" so that poll loop breaks and DCV reports done.
            // 3rd: EnrollV2Async's own post-DCV re-check observes the same revoked status.
            mock.SetupSequence(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(PendingDcvStatus())
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "revoked", Domain = "example.com" })
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "revoked", Domain = "example.com" });

            mock.Setup(c => c.GetDcvV2Async(OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvChallengeResponse { Token = "dcv-token-revoked", TokenExpiryDate = "2026-12-31 23:59:59" });
            mock.Setup(c => c.VerifyDcvV2Async(OrderId, "example.com", It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvVerifyResponse { OverallStatus = "VERIFIED" });

            var validator = new FakeDomainValidator();
            // Pickup enabled to prove the poll is correctly skipped (dcvV2Ran) rather than
            // masking the revoked status behind additional polling/downloads.
            var plugin = BuildV2DcvPlugin(mock.Object, new FakeDomainValidatorFactory(validator), pickupRetries: 5);

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.FAILED,
                "a REVOKED disposition discovered on the post-DCV re-check has no certificate " +
                "body and must never be reported as REVOKED (issue 0052)");
            result.Certificate.Should().BeNull();
            result.CARequestID.Should().Be(OrderId);
            result.StatusMessage.Should().Contain(OrderId).And.Contain("revoked");

            mock.Verify(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()),
                Times.Exactly(3),
                "the pickup poll must not run on top of the inline DCV wait — no 4th TrackOrderV2Async call");
            mock.Verify(c => c.DownloadCertificateV2Async(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // Synchronize (V2, issues/0022) — DCV-during-sync age-window / per-pass-cap gating.
        // Reuses EvaluateDcvSyncEligibility/DcvSyncDecision — same bounds V1 sync uses (issue
        // 0002), applied to the V2 /reports/orders path.
        // ---------------------------------------------------------------------------

        private static async IAsyncEnumerable<T> AsyncEnumerable<T>(params T[] items)
        {
            foreach (var item in items)
                yield return item;
            await Task.CompletedTask;
        }

        private static OrderReportEntryV2 PendingDcvRow(string orderNumber, DateTime orderDateUtc) =>
            new OrderReportEntryV2
            {
                OrderNumber       = orderNumber,
                OrderStatus       = "Order Accepted",
                CertificateStatus = "Pending for Approver",
                DomainName        = "example.com",
                OrderDate         = orderDateUtc.ToString("o")
            };

        [Fact]
        public async Task SynchronizeV2_PendingDcvOrder_AgedOutOfWindow_SkipsDcv_EmitsPendingWithoutResolvingFamily()
        {
            var mock = NewMock();
            var oldRow = PendingDcvRow("ord_old_001", DateTime.UtcNow.AddHours(-48));

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(oldRow));

            // Age window of 1h — the 48h-old order above is well outside it.
            var config = new CERTInextConfig
            {
                UseV2Api = true, ApiUrl = "https://v2.certinext.io",
                OAuthClientId = "c", OAuthClientSecret = "s",
                DcvEnabled = true, DcvTimeoutMinutes = 1, DcvPropagationDelaySeconds = 1,
                DcvSyncMaxOrderAgeHours = 1, DcvSyncMaxPerPass = 0
            };
            var plugin = new CERTInextCAPlugin(mock.Object, new FakeDomainValidatorFactory(new FakeDomainValidator()), config);

            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);
            await plugin.Synchronize(buffer, DateTime.UtcNow.AddDays(-1), true, CancellationToken.None);

            var records = buffer.ToArray();
            records.Should().ContainSingle(r => r.CARequestID == "ord_old_001"
                && r.Status == (int)EndEntityStatus.EXTERNALVALIDATION);

            // Aged-out rows must not even resolve a family — that's the point of the age gate.
            mock.Verify(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            mock.Verify(c => c.GetDcvV2Async(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task SynchronizeV2_PendingDcvOrders_ExceedingPerPassCap_OnlyAttemptsUpToCap()
        {
            var mock = NewMock();
            var row1 = PendingDcvRow("ord_cap_001", DateTime.UtcNow.AddMinutes(-30));
            var row2 = PendingDcvRow("ord_cap_002", DateTime.UtcNow.AddMinutes(-20));

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row1, row2));

            // Only the first (cap=1) row should ever have its family resolved.
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync("ord_cap_001", It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse
                {
                    OrderId = "ord_cap_001", Status = "pending-dcv", Domain = "example.com"
                }));

            // Fail fast at GetDcv so PerformDcvV2IfNeededAsync returns false quickly without
            // needing the full staging/verify chain mocked — the point of this test is the cap
            // gate, not the DCV flow itself.
            mock.Setup(c => c.GetDcvV2Async("ord_cap_001", It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("simulated transient GetDcv failure"));

            var config = new CERTInextConfig
            {
                UseV2Api = true, ApiUrl = "https://v2.certinext.io",
                OAuthClientId = "c", OAuthClientSecret = "s",
                DcvEnabled = true, DcvTimeoutMinutes = 1, DcvPropagationDelaySeconds = 1,
                DcvSyncMaxOrderAgeHours = 0, DcvSyncMaxPerPass = 1
            };
            var plugin = new CERTInextCAPlugin(mock.Object, new FakeDomainValidatorFactory(new FakeDomainValidator()), config);

            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);
            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            var records = buffer.ToArray();
            records.Should().HaveCount(2);
            records.Should().OnlyContain(r => r.Status == (int)EndEntityStatus.EXTERNALVALIDATION);

            mock.Verify(c => c.ResolveAndTrackOrderV2WithFamilyAsync("ord_cap_001", It.IsAny<CancellationToken>()), Times.Once);
            mock.Verify(c => c.ResolveAndTrackOrderV2WithFamilyAsync("ord_cap_002", It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // Issue 0042 — UCC additionalDomains SANs never got DCV-validated because the V2 DCV
        // machinery only ever drove the order's primary domain. These tests exercise the
        // generalized PerformDcvV2MultiDomainAsync path (driven from Track Order's
        // verifications.domain.domains[] block) end to end through Enroll/Synchronize, the
        // same way the EMS-1080 tests above exercise the single-domain path.
        // ---------------------------------------------------------------------------

        private static V2DomainVerificationEntry DomainEntry(
            string domain, string dcvStatus, string dcvMethod = null, string verifiedAt = null) =>
            new V2DomainVerificationEntry
            {
                Domain       = domain,
                DomainStatus = "ACTIVE",
                DcvStatus    = dcvStatus,
                DcvMethod    = dcvMethod,
                VerifiedAt   = verifiedAt,
                CaaStatus    = "SKIPPED"
            };

        private static V2OrderStatusResponse StatusWithDomains(string status, params V2DomainVerificationEntry[] domains) =>
            new V2OrderStatusResponse
            {
                OrderId       = OrderId,
                Status        = status,
                Domain        = domains.FirstOrDefault()?.Domain,
                Verifications = new V2Verifications
                {
                    Domain = new V2DomainVerification { Status = "PENDING", Domains = domains.ToList() }
                }
            };

        private const string UccPrimary = "example.com";
        private const string UccSanA = "a.pending0042.example.com";
        private const string UccSanB = "b.pending0042.example.com";

        [Fact]
        public async Task PerformDcvV2_Ucc_PrimaryVerified_TwoPendingSans_StagesAndVerifiesOnlyPendingSans_CleansUpAll()
        {
            var mock = NewMock();
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true }
                });
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(PlaceOrderResponse());
            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            // 1st TrackOrder call (post-CSR check): primary already VERIFIED, both SANs PENDING.
            // Every call after that (the WaitForDomainsVerifiedV2Async poll, and EnrollV2Async's
            // own post-DCV re-check) sees the order fully issued with every domain VERIFIED.
            int trackCalls = 0;
            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(() =>
                {
                    trackCalls++;
                    return trackCalls == 1
                        ? StatusWithDomains("pending-dcv",
                            DomainEntry(UccPrimary, "VERIFIED", "dns-txt"),
                            DomainEntry(UccSanA, "PENDING"),
                            DomainEntry(UccSanB, "PENDING"))
                        : StatusWithDomains("issued",
                            DomainEntry(UccPrimary, "VERIFIED", "dns-txt"),
                            DomainEntry(UccSanA, "VERIFIED", "dns-txt"),
                            DomainEntry(UccSanB, "VERIFIED", "dns-txt"));
                });

            mock.Setup(c => c.GetDcvV2Async(OrderId, UccSanA, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvChallengeResponse { Token = "token-a", TokenExpiryDate = "2026-12-31 23:59:59" });
            mock.Setup(c => c.GetDcvV2Async(OrderId, UccSanB, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvChallengeResponse { Token = "token-b", TokenExpiryDate = "2026-12-31 23:59:59" });

            mock.Setup(c => c.VerifyDcvV2Async(OrderId, UccSanA, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvVerifyResponse { OverallStatus = "VERIFIED" });
            mock.Setup(c => c.VerifyDcvV2Async(OrderId, UccSanB, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvVerifyResponse { OverallStatus = "VERIFIED" });

            mock.Setup(c => c.DownloadCertificateV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(DownloadResponse());

            var validator = new FakeDomainValidator();
            var plugin = BuildV2DcvPlugin(mock.Object, new FakeDomainValidatorFactory(validator));

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);

            validator.StagedRecords.Select(r => r.key).Should().BeEquivalentTo(
                new[] { $"_emsign-validation.{UccSanA}", $"_emsign-validation.{UccSanB}" },
                "only the two pending SANs should be staged — the already-VERIFIED primary must never be re-challenged");

            validator.CleanedUpKeys.Should().BeEquivalentTo(
                new[] { $"_emsign-validation.{UccSanA}", $"_emsign-validation.{UccSanB}" },
                "every staged record must be cleaned up");

            mock.Verify(c => c.GetDcvV2Async(OrderId, UccPrimary, It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            mock.Verify(c => c.VerifyDcvV2Async(OrderId, UccPrimary, It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task PerformDcvV2_Ucc_OneSanVerifyFails_OtherStillVerified_AllCleanedUp_OrderStaysPending()
        {
            var mock = NewMock();
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true }
                });
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(PlaceOrderResponse());
            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            // 1st call: post-CSR, both SANs pending. Every later call (the poll for the one SAN
            // that DID verify, and EnrollV2Async's post-DCV re-check): SanA verified, SanB still
            // pending — the order legitimately cannot advance further this pass.
            int trackCalls = 0;
            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(() =>
                {
                    trackCalls++;
                    return trackCalls == 1
                        ? StatusWithDomains("pending-dcv",
                            DomainEntry(UccPrimary, "VERIFIED", "dns-txt"),
                            DomainEntry(UccSanA, "PENDING"),
                            DomainEntry(UccSanB, "PENDING"))
                        : StatusWithDomains("pending-dcv",
                            DomainEntry(UccPrimary, "VERIFIED", "dns-txt"),
                            DomainEntry(UccSanA, "VERIFIED", "dns-txt"),
                            DomainEntry(UccSanB, "PENDING"));
                });

            mock.Setup(c => c.GetDcvV2Async(OrderId, UccSanA, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvChallengeResponse { Token = "token-a", TokenExpiryDate = "2026-12-31 23:59:59" });
            mock.Setup(c => c.GetDcvV2Async(OrderId, UccSanB, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvChallengeResponse { Token = "token-b", TokenExpiryDate = "2026-12-31 23:59:59" });

            mock.Setup(c => c.VerifyDcvV2Async(OrderId, UccSanA, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvVerifyResponse { OverallStatus = "VERIFIED" });
            mock.Setup(c => c.VerifyDcvV2Async(OrderId, UccSanB, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("simulated transient verify failure for SanB"));

            var validator = new FakeDomainValidator();
            // PickupRetries > 0 (mirrors the 0051 regression test above): confirms dcvV2Ran still
            // gates the pickup poll even on the partial-failure multi-domain path.
            var plugin = BuildV2DcvPlugin(mock.Object, new FakeDomainValidatorFactory(validator), pickupRetries: 5);

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION,
                "SanB never verified, so the order must stay pending — not be treated as failed or issued");
            result.CARequestID.Should().Be(OrderId);

            validator.CleanedUpKeys.Should().BeEquivalentTo(
                new[] { $"_emsign-validation.{UccSanA}", $"_emsign-validation.{UccSanB}" },
                "both staged records must be cleaned up regardless of SanB's verify failure");

            mock.Verify(c => c.VerifyDcvV2Async(OrderId, UccSanA, It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
            mock.Verify(c => c.VerifyDcvV2Async(OrderId, UccSanB, It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
            mock.Verify(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()),
                Times.Exactly(3),
                "a pickup poll must not stack on top of the inline DCV wait — no 4th TrackOrderV2Async call");
            mock.Verify(c => c.DownloadCertificateV2Async(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task SynchronizeV2_Ucc_OneSanStillPendingFromAnEarlierPass_OnlyThatSanIsProcessed()
        {
            var mock = NewMock();
            const string syncOrderId = "ord_ucc_sync_001";
            var row = PendingDcvRow(syncOrderId, DateTime.UtcNow.AddMinutes(-10));

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            // Primary and SanA were already verified on an earlier sync pass; only SanB remains.
            var pendingStatus = new V2OrderStatusResponse
            {
                OrderId = syncOrderId,
                Status = "pending-dcv",
                Domain = UccPrimary,
                Verifications = new V2Verifications
                {
                    Domain = new V2DomainVerification
                    {
                        Status = "PENDING",
                        Domains = new List<V2DomainVerificationEntry>
                        {
                            DomainEntry(UccPrimary, "VERIFIED", "dns-txt"),
                            DomainEntry(UccSanA, "VERIFIED", "dns-txt"),
                            DomainEntry(UccSanB, "PENDING")
                        }
                    }
                }
            };
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(syncOrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, pendingStatus));

            mock.Setup(c => c.GetDcvV2Async(syncOrderId, UccSanB, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvChallengeResponse { Token = "token-b", TokenExpiryDate = "2026-12-31 23:59:59" });
            mock.Setup(c => c.VerifyDcvV2Async(syncOrderId, UccSanB, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvVerifyResponse { OverallStatus = "VERIFIED" });

            var issuedStatus = new V2OrderStatusResponse
            {
                OrderId = syncOrderId,
                Status = "issued",
                Domain = UccPrimary,
                Verifications = new V2Verifications
                {
                    Domain = new V2DomainVerification
                    {
                        Status = "VERIFIED",
                        Domains = new List<V2DomainVerificationEntry>
                        {
                            DomainEntry(UccPrimary, "VERIFIED", "dns-txt"),
                            DomainEntry(UccSanA, "VERIFIED", "dns-txt"),
                            DomainEntry(UccSanB, "VERIFIED", "dns-txt")
                        }
                    }
                }
            };
            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), syncOrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(issuedStatus);
            mock.Setup(c => c.ResolveAndTrackOrderV2Async(syncOrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(issuedStatus);
            mock.Setup(c => c.ResolveAndDownloadCertificateV2Async(syncOrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CertificateDownloadResponse
                {
                    OrderId = syncOrderId, SerialNumber = "AA11BB22", CertificatePem = MockCertificateData.FakePemCertificate
                });

            var config = new CERTInextConfig
            {
                UseV2Api = true, ApiUrl = "https://v2.certinext.io",
                OAuthClientId = "c", OAuthClientSecret = "s",
                DcvEnabled = true, DcvTimeoutMinutes = 1, DcvPropagationDelaySeconds = 1,
                DcvSyncMaxOrderAgeHours = 0, DcvSyncMaxPerPass = 0
            };
            var validator = new FakeDomainValidator();
            var plugin = new CERTInextCAPlugin(mock.Object, new FakeDomainValidatorFactory(validator), config);

            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);
            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            buffer.ToArray().Should().ContainSingle(r => r.CARequestID == syncOrderId);

            mock.Verify(c => c.GetDcvV2Async(syncOrderId, UccSanB, It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
            mock.Verify(c => c.GetDcvV2Async(syncOrderId, UccSanA, It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            mock.Verify(c => c.GetDcvV2Async(syncOrderId, UccPrimary, It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            mock.Verify(c => c.GetDcvV2Async(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never,
                "the no-domain single-domain-fallback overload must not be used once domainEntries is populated");

            validator.StagedRecords.Should().ContainSingle();
            validator.CleanedUpKeys.Should().ContainSingle();
        }

        [Fact]
        public async Task PerformDcvV2_DomainsArrayAbsent_UsesSingleDomainFallback_NeverThePerDomainOverload()
        {
            var mock = NewMock();
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true }
                });
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(PlaceOrderResponse());
            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            // No Verifications block anywhere in this sequence — the pre-0042 shape.
            mock.SetupSequence(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(PendingDcvStatus())
                .ReturnsAsync(IssuedStatus())
                .ReturnsAsync(IssuedStatus());

            mock.Setup(c => c.GetDcvV2Async(OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvChallengeResponse { Token = "legacy-token", TokenExpiryDate = "2026-12-31 23:59:59" });
            mock.Setup(c => c.VerifyDcvV2Async(OrderId, "example.com", It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvVerifyResponse { OverallStatus = "VERIFIED" });
            mock.Setup(c => c.DownloadCertificateV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(DownloadResponse());

            var validator = new FakeDomainValidator();
            var plugin = BuildV2DcvPlugin(mock.Object, new FakeDomainValidatorFactory(validator));

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            validator.StagedRecords.Should().ContainSingle();

            // The 4-argument (per-domain) overload is a distinct method — confirming it was
            // never called proves the domainEntries-absent case took the untouched legacy path,
            // not the generalized multi-domain one (issue 0042's "keep today's primary-domain
            // behaviour exactly" requirement).
            mock.Verify(c => c.GetDcvV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Never);
        }

        [Fact]
        public async Task PerformDcvV2_Ucc_Ems1080OnPendingSan_TreatedAsVerified_NotAnError_NoStagingOrVerify()
        {
            var mock = NewMock();
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true }
                });
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(PlaceOrderResponse());
            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            int trackCalls = 0;
            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(() =>
                {
                    trackCalls++;
                    return trackCalls == 1
                        ? StatusWithDomains("pending-dcv",
                            DomainEntry(UccPrimary, "VERIFIED", "dns-txt"),
                            DomainEntry(UccSanA, "PENDING"))
                        : StatusWithDomains("issued",
                            DomainEntry(UccPrimary, "VERIFIED", "dns-txt"),
                            DomainEntry(UccSanA, "VERIFIED", "dns-txt"));
                });

            // EMS-1080 at GetDcv for the pending SAN — the domain became verified CA-side
            // between Track Order reporting it pending and this challenge fetch.
            mock.Setup(c => c.GetDcvV2Async(OrderId, UccSanA, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception(
                    "CERTInext V2 API error during 'V2 get DCV challenge (per-domain)'. HTTP 422. " +
                    "Unprocessable Entity: EMS-1080 Domain is already verified."));

            mock.Setup(c => c.DownloadCertificateV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(DownloadResponse());

            var validator = new FakeDomainValidator();
            var plugin = BuildV2DcvPlugin(mock.Object, new FakeDomainValidatorFactory(validator));

            var result = await Enroll(plugin);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED,
                "EMS-1080 on a pending SAN must be treated as already verified, not a failure");
            validator.StagedRecords.Should().BeEmpty(
                "EMS-1080 at GetDcv means there is no fresh challenge to publish for this SAN");
            validator.CleanedUpKeys.Should().BeEmpty("nothing was staged, so there is nothing to clean up");

            mock.Verify(c => c.VerifyDcvV2Async(
                    OrderId, UccSanA, It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Never,
                "VerifyDcv must never be reached for a domain GetDcv already reported as verified");
        }

        [Fact]
        public void V2OrderStatusResponse_Deserializes_PendingSanDomainsArray_WithoutDcvMethod()
        {
            // Raw shape from issues/0042 "Pending-SAN challenge shape (live)" (order 7465857196,
            // 2026-09-28) — pending entries carry no "dcvMethod" key at all; it only appears once
            // an entry reaches VERIFIED.
            const string rawJson = @"{
                ""orderId"": ""7465857196"",
                ""status"": ""pending-approval"",
                ""domain"": ""ucc0042-202609290046.dcv-test.scrup.org"",
                ""verifications"": {
                    ""domain"": {
                        ""status"": ""PENDING"",
                        ""domains"": [
                            {""domain"":""a.pending0042-202609290046.example.com"",""domainStatus"":""ACTIVE"",""dcvStatus"":""PENDING"",""caaStatus"":""SKIPPED""},
                            {""domain"":""b.pending0042-202609290046.example.com"",""domainStatus"":""ACTIVE"",""dcvStatus"":""PENDING"",""caaStatus"":""SKIPPED""},
                            {""domain"":""ucc0042-202609290046.dcv-test.scrup.org"",""domainStatus"":""ACTIVE"",""dcvMethod"":""dns-txt"",""dcvStatus"":""VERIFIED"",""verifiedAt"":""2026-09-29T00:46:09Z"",""caaStatus"":""PASSED""}
                        ]
                    },
                    ""empty"": false
                }
            }";

            // Null-forgiving here: System.Text.Json's Deserialize<T> is annotated to return
            // T?, but a successfully-parsed non-null JSON object (as above) never actually
            // produces a null reference — the Should().NotBeNull() below is the runtime
            // guarantee backing that, which the compiler's static analysis can't see through.
            var result = JsonSerializer.Deserialize<V2OrderStatusResponse>(rawJson)!;

            result.Should().NotBeNull();
            result.Verifications.Should().NotBeNull();
            result.Verifications.Domain.Should().NotBeNull();
            result.Verifications.Domain.Status.Should().Be("PENDING");
            result.Verifications.Domain.Domains.Should().HaveCount(3);

            var sanA = result.Verifications.Domain.Domains.Single(d => d.Domain == "a.pending0042-202609290046.example.com");
            sanA.DcvStatus.Should().Be("PENDING");
            sanA.DcvMethod.Should().BeNull("pending entries carry no dcvMethod key at all — absent, not present-but-null-looking");
            sanA.VerifiedAt.Should().BeNull();

            var verifiedPrimary = result.Verifications.Domain.Domains.Single(
                d => d.Domain == "ucc0042-202609290046.dcv-test.scrup.org");
            verifiedPrimary.DcvStatus.Should().Be("VERIFIED");
            verifiedPrimary.DcvMethod.Should().Be("dns-txt");
            verifiedPrimary.VerifiedAt.Should().Be("2026-09-29T00:46:09Z");
        }
    }
}
