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
            ICERTInextClient client, IDomainValidatorFactory factory) =>
            new CERTInextCAPlugin(client, factory, new CERTInextConfig
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
                PickupRetries   = 0,
                DcvEnabled                 = true,
                DcvTimeoutMinutes          = 1,
                DcvPropagationDelaySeconds = 1
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
                    OrderNumber     = OrderId,
                    DomainName      = "example.com",
                    DcvMethod       = "2",
                    FileNameContent = "dcv-token-abc123"
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
    }
}
