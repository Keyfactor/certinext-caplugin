// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
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
    /// V2 DCV for domains SSL.com validates (<c>validatedBy: SSLCOM</c> on the account's domain row):
    /// the plugin must publish SSL.com's own record from <c>GET /domains/{id}/dcv</c> (never
    /// <c>DcvTxtRecordTemplate</c>), verify through <c>POST /domains/{id}/dcv/verify</c>, leave the order
    /// pending on any SSL.com-side delay or outage, and keep emSign domains on the order-level flow.
    /// Driven through <see cref="CERTInextCAPlugin.Enroll"/> like <see cref="CERTInextCAPluginV2DcvTests"/>.
    /// </summary>
    public class V2SslComDomainDcvPluginTests
    {
        private const string OrderId = "ord_sslcom_001";
        private const string Domain = "example.com";
        private const string DomainId = "dom_8K9mQ2vR";
        private const string TxtOptionId = "49e7f9e7-c08e-40ba-945d-321a67c0442c";
        private const string SslComRecordName = "_pki-validation.example.com";
        private const string SslComRecordValue = "sslcom-dcv-value-1";

        private static CERTInextCAPlugin BuildPlugin(ICERTInextClient client, IDomainValidatorFactory factory) =>
            new CERTInextCAPlugin(client, factory, new CERTInextConfig
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
                PickupRetries        = 0,
                PickupDelayInSeconds = 1,
                DcvEnabled                 = true,
                DcvTimeoutMinutes          = 1,
                DcvPropagationDelaySeconds = 1,
                // Set on purpose: the SSL.com path must ignore it.
                DcvTxtRecordTemplate       = "_emsign-validation.{0}"
            });

        private static Task<EnrollmentResult> Enroll(CERTInextCAPlugin plugin, params string[] sans) =>
            plugin.Enroll(
                csr:            MockCertificateData.FakeCsrPem,
                subject:        "CN=" + Domain,
                san:            new Dictionary<string, string[]> { ["dns"] = sans.Length == 0 ? new[] { Domain } : sans },
                productInfo:    new EnrollmentProductInfo
                {
                    ProductID = "DV SSL",
                    ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["ProductCode"]    = "842",
                        ["ProductFamily"]  = "ssl",
                        ["ProductVariant"] = "dv",
                        ["DomainName"]     = Domain
                    }
                },
                requestFormat:  RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

        /// <summary>Strict mock wired for a V2 DV enrollment that lands in pending-dcv.</summary>
        private static Mock<ICERTInextClient> NewEnrollMock(Func<int, V2OrderStatusResponse> trackByCall)
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true }
                });
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = OrderId, Status = "pending-dcv" });
            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            int calls = 0;
            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(() => trackByCall(++calls));
            mock.Setup(c => c.DownloadCertificateV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CertificateDownloadResponse
                {
                    OrderId = OrderId, SerialNumber = "AA11BB22", CertificatePem = MockCertificateData.FakePemCertificate
                });
            return mock;
        }

        private static V2OrderStatusResponse Status(string status) =>
            new V2OrderStatusResponse { OrderId = OrderId, Status = status, Domain = Domain };

        private static V2DomainRecord SslComRow(string name = Domain, string id = DomainId) =>
            new V2DomainRecord { DomainId = id, DomainName = name, DcvStatus = "PENDING", ValidatedBy = "SSLCOM" };

        private static V2DomainDcvDetails TxtDetails(string recordName = SslComRecordName, string value = SslComRecordValue,
            string optionId = TxtOptionId) =>
            new V2DomainDcvDetails
            {
                Method = "dns-txt", RecordName = recordName, RecordValue = value, OptionId = optionId,
                ValidatedBy = "SSLCOM", CaStatus = "PENDING"
            };

        private static void VerifyNoOrderLevelDcv(Mock<ICERTInextClient> mock)
        {
            mock.Verify(c => c.GetDcvV2Async(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            mock.Verify(c => c.GetDcvV2Async(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<CancellationToken>()), Times.Never);
            mock.Verify(c => c.VerifyDcvV2Async(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task SslComDomain_StagesSslComRecordNotTemplate_VerifiesSelectedOption_Issues()
        {
            var mock = NewEnrollMock(n => n == 1 ? Status("pending-dcv") : Status("issued"));
            mock.Setup(c => c.FindDomainV2Async(Domain, It.IsAny<CancellationToken>())).ReturnsAsync(SslComRow());
            mock.Setup(c => c.GetDomainDcvV2Async(DomainId, It.IsAny<CancellationToken>())).ReturnsAsync(TxtDetails());
            mock.Setup(c => c.VerifyDomainDcvV2Async(DomainId, TxtOptionId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DomainDcvVerifyResult { Verified = true, ValidTill = "2027-11-13T00:00:00Z" });

            var validator = new FakeDomainValidator();
            var result = await Enroll(BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator)));

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            validator.StagedRecords.Should().ContainSingle()
                .Which.Should().Be((SslComRecordName, SslComRecordValue),
                    "SSL.com's exact record name and value are published; DcvTxtRecordTemplate is ignored");
            validator.CleanedUpKeys.Should().Equal(SslComRecordName);
            mock.Verify(c => c.VerifyDomainDcvV2Async(DomainId, TxtOptionId, It.IsAny<CancellationToken>()), Times.Once);
            VerifyNoOrderLevelDcv(mock);
        }

        [Fact]
        public async Task SslComDomain_SelectedMethodIsCname_PicksExactNameTxtOption()
        {
            var mock = NewEnrollMock(n => n == 1 ? Status("pending-dcv") : Status("issued"));
            mock.Setup(c => c.FindDomainV2Async(Domain, It.IsAny<CancellationToken>())).ReturnsAsync(SslComRow());
            mock.Setup(c => c.GetDomainDcvV2Async(DomainId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DomainDcvDetails
                {
                    Method = "dns-cname", RecordName = "_cname.example.com", RecordValue = "target.sslcom.example",
                    OptionId = "opt-cname", ValidatedBy = "SSLCOM", CaStatus = "PENDING",
                    Options = new List<V2DcvOption>
                    {
                        new V2DcvOption { OptionId = "opt-cname", Method = "dns-cname", RecordName = "_cname.example.com",
                            RecordValue = "target.sslcom.example", ExactName = true },
                        new V2DcvOption { OptionId = "opt-parent-txt", Method = "dns-txt", RecordName = "_pki-validation.com",
                            RecordValue = "parent-value", ExactName = false },
                        new V2DcvOption { OptionId = "opt-exact-txt", Method = "dns-txt", RecordName = SslComRecordName,
                            RecordValue = SslComRecordValue, ExactName = true }
                    }
                });
            mock.Setup(c => c.VerifyDomainDcvV2Async(DomainId, "opt-exact-txt", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DomainDcvVerifyResult { Verified = true });

            var validator = new FakeDomainValidator();
            var result = await Enroll(BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator)));

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            validator.StagedRecords.Should().ContainSingle().Which.Should().Be((SslComRecordName, SslComRecordValue),
                "a CNAME can't be published through IDomainValidator, so the exact-name dns-txt option wins");
        }

        [Fact]
        public async Task SslComDomain_OnlyCnameOffered_PublishesNothing_LeavesOrderPending()
        {
            var mock = NewEnrollMock(_ => Status("pending-dcv"));
            mock.Setup(c => c.FindDomainV2Async(Domain, It.IsAny<CancellationToken>())).ReturnsAsync(SslComRow());
            mock.Setup(c => c.GetDomainDcvV2Async(DomainId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DomainDcvDetails
                {
                    Method = "dns-cname", RecordName = "_cname.example.com", RecordValue = "target.sslcom.example",
                    OptionId = "opt-cname", ValidatedBy = "SSLCOM", CaStatus = "PENDING"
                });

            var validator = new FakeDomainValidator();
            var result = await Enroll(BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator)));

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            validator.StagedRecords.Should().BeEmpty();
            mock.Verify(c => c.VerifyDomainDcvV2Async(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Never);
            VerifyNoOrderLevelDcv(mock);
        }

        [Fact]
        public async Task SslComDomain_Verify422UnderReview_LeavesOrderPending_CleansUp()
        {
            var mock = NewEnrollMock(_ => Status("pending-dcv"));
            mock.Setup(c => c.FindDomainV2Async(Domain, It.IsAny<CancellationToken>())).ReturnsAsync(SslComRow());
            mock.Setup(c => c.GetDomainDcvV2Async(DomainId, It.IsAny<CancellationToken>())).ReturnsAsync(TxtDetails());
            mock.Setup(c => c.VerifyDomainDcvV2Async(DomainId, TxtOptionId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DomainDcvVerifyResult
                {
                    Verified = false, CaStatus = "UNDER_REVIEW", CaMessage = "Manual review in progress"
                });

            var validator = new FakeDomainValidator();
            var result = await Enroll(BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator)));

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION,
                "UNDER_REVIEW is not a failure: the order stays pending and sync retries");
            validator.StagedRecords.Should().ContainSingle();
            validator.CleanedUpKeys.Should().Equal(SslComRecordName);
            mock.Verify(c => c.CancelOrderV2Async(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task SslComDomain_Verify502_LeavesOrderPending_CleansUp()
        {
            var mock = NewEnrollMock(_ => Status("pending-dcv"));
            mock.Setup(c => c.FindDomainV2Async(Domain, It.IsAny<CancellationToken>())).ReturnsAsync(SslComRow());
            mock.Setup(c => c.GetDomainDcvV2Async(DomainId, It.IsAny<CancellationToken>())).ReturnsAsync(TxtDetails());
            mock.Setup(c => c.VerifyDomainDcvV2Async(DomainId, TxtOptionId, It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("CERTInext V2 API error during 'V2 verify domain DCV'. HTTP 502."));

            var validator = new FakeDomainValidator();
            var result = await Enroll(BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator)));

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            validator.CleanedUpKeys.Should().Equal(SslComRecordName);
        }

        [Fact]
        public async Task SslComDomain_GetDcv502_PublishesNothing_LeavesOrderPending()
        {
            var mock = NewEnrollMock(_ => Status("pending-dcv"));
            mock.Setup(c => c.FindDomainV2Async(Domain, It.IsAny<CancellationToken>())).ReturnsAsync(SslComRow());
            mock.Setup(c => c.GetDomainDcvV2Async(DomainId, It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("CERTInext V2 API error during 'V2 get domain DCV'. HTTP 502."));

            var validator = new FakeDomainValidator();
            var result = await Enroll(BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator)));

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            validator.StagedRecords.Should().BeEmpty();
            VerifyNoOrderLevelDcv(mock);
        }

        [Fact]
        public async Task SslComDomain_AlreadyValidated_VerifiesWithoutPublishing()
        {
            var mock = NewEnrollMock(n => n == 1 ? Status("pending-dcv") : Status("issued"));
            mock.Setup(c => c.FindDomainV2Async(Domain, It.IsAny<CancellationToken>())).ReturnsAsync(SslComRow());
            mock.Setup(c => c.GetDomainDcvV2Async(DomainId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DomainDcvDetails { ValidatedBy = "SSLCOM", CaStatus = "VALIDATED", OptionId = TxtOptionId });
            mock.Setup(c => c.VerifyDomainDcvV2Async(DomainId, TxtOptionId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DomainDcvVerifyResult { Verified = true });

            var validator = new FakeDomainValidator();
            var result = await Enroll(BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator)));

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            validator.StagedRecords.Should().BeEmpty();
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task EmsignDomainOrFailedLookup_KeepsOrderLevelFlowAndTemplate(bool lookupThrows)
        {
            var mock = NewEnrollMock(n => n == 1 ? Status("pending-dcv") : Status("issued"));
            if (lookupThrows)
                mock.Setup(c => c.FindDomainV2Async(Domain, It.IsAny<CancellationToken>()))
                    .ThrowsAsync(new Exception("CERTInext V2 API error during 'V2 find domain'. HTTP 500."));
            else
                mock.Setup(c => c.FindDomainV2Async(Domain, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new V2DomainRecord { DomainId = DomainId, DomainName = Domain, DcvStatus = "PENDING" });
            mock.Setup(c => c.GetDcvV2Async(OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvChallengeResponse { Token = "emsign-token" });
            mock.Setup(c => c.VerifyDcvV2Async(OrderId, Domain, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvVerifyResponse { OverallStatus = "VERIFIED" });

            var validator = new FakeDomainValidator();
            var result = await Enroll(BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator)));

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            validator.StagedRecords.Should().ContainSingle().Which.Should().Be(("_emsign-validation.example.com", "emsign-token"));
            mock.Verify(c => c.GetDomainDcvV2Async(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            mock.Verify(c => c.VerifyDomainDcvV2Async(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Never);
        }

        private const string SanEmsign = "a.example.com";
        private const string SanSslCom = "b.example.com";

        private static V2OrderStatusResponse UccStatus(string status, string emsignStatus, string sslComStatus) =>
            new V2OrderStatusResponse
            {
                OrderId = OrderId,
                Status = status,
                Domain = Domain,
                Verifications = new V2Verifications
                {
                    Domain = new V2DomainVerification
                    {
                        Status = "PENDING",
                        Domains = new List<V2DomainVerificationEntry>
                        {
                            new V2DomainVerificationEntry { Domain = Domain, DcvStatus = "VERIFIED" },
                            new V2DomainVerificationEntry { Domain = SanEmsign, DcvStatus = emsignStatus },
                            new V2DomainVerificationEntry { Domain = SanSslCom, DcvStatus = sslComStatus }
                        }
                    }
                }
            };

        [Fact]
        public async Task Ucc_MixedValidators_EachDomainTakesItsOwnFlow_AllCleanedUp()
        {
            var mock = NewEnrollMock(n => n == 1
                ? UccStatus("pending-dcv", "PENDING", "PENDING")
                : UccStatus("issued", "VERIFIED", "VERIFIED"));
            mock.Setup(c => c.FindDomainV2Async(SanEmsign, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DomainRecord { DomainId = "dom_a", DomainName = SanEmsign });
            mock.Setup(c => c.FindDomainV2Async(SanSslCom, It.IsAny<CancellationToken>()))
                .ReturnsAsync(SslComRow(SanSslCom, "dom_b"));
            mock.Setup(c => c.GetDcvV2Async(OrderId, SanEmsign, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvChallengeResponse { Token = "token-a" });
            mock.Setup(c => c.VerifyDcvV2Async(OrderId, SanEmsign, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvVerifyResponse { OverallStatus = "VERIFIED" });
            mock.Setup(c => c.GetDomainDcvV2Async("dom_b", It.IsAny<CancellationToken>()))
                .ReturnsAsync(TxtDetails("_pki-validation.b.example.com", "value-b", "opt-b"));
            mock.Setup(c => c.VerifyDomainDcvV2Async("dom_b", "opt-b", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DomainDcvVerifyResult { Verified = true });

            var validator = new FakeDomainValidator();
            // One SAN on the CSR, as in CERTInextCAPluginV2DcvTests: the per-domain block comes from Track.
            var result = await Enroll(BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator)));

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            validator.StagedRecords.Should().BeEquivalentTo(new[]
            {
                ("_emsign-validation.a.example.com", "token-a"),
                ("_pki-validation.b.example.com", "value-b")
            });
            validator.CleanedUpKeys.Should().BeEquivalentTo(
                "_emsign-validation.a.example.com", "_pki-validation.b.example.com");
            mock.Verify(c => c.VerifyDcvV2Async(OrderId, SanSslCom, It.IsAny<string>(), It.IsAny<CancellationToken>()),
                Times.Never, "the SSL.com SAN is verified through the domain endpoint only");
            mock.Verify(c => c.FindDomainV2Async(Domain, It.IsAny<CancellationToken>()), Times.Never,
                "the already-VERIFIED primary is not looked up");
        }

        [Fact]
        public async Task Ucc_SslComSanUnderReview_EmsignSanStillVerified_OrderStaysPending()
        {
            var mock = NewEnrollMock(n => n == 1
                ? UccStatus("pending-dcv", "PENDING", "PENDING")
                : UccStatus("pending-dcv", "VERIFIED", "PENDING"));
            mock.Setup(c => c.FindDomainV2Async(SanEmsign, It.IsAny<CancellationToken>()))
                .ReturnsAsync((V2DomainRecord)null);
            mock.Setup(c => c.FindDomainV2Async(SanSslCom, It.IsAny<CancellationToken>()))
                .ReturnsAsync(SslComRow(SanSslCom, "dom_b"));
            mock.Setup(c => c.GetDcvV2Async(OrderId, SanEmsign, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvChallengeResponse { Token = "token-a" });
            mock.Setup(c => c.VerifyDcvV2Async(OrderId, SanEmsign, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DcvVerifyResponse { OverallStatus = "VERIFIED" });
            mock.Setup(c => c.GetDomainDcvV2Async("dom_b", It.IsAny<CancellationToken>()))
                .ReturnsAsync(TxtDetails("_pki-validation.b.example.com", "value-b", "opt-b"));
            mock.Setup(c => c.VerifyDomainDcvV2Async("dom_b", "opt-b", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2DomainDcvVerifyResult { Verified = false, CaStatus = "UNDER_REVIEW" });

            var validator = new FakeDomainValidator();
            // One SAN on the CSR, as in CERTInextCAPluginV2DcvTests: the per-domain block comes from Track.
            var result = await Enroll(BuildPlugin(mock.Object, new FakeDomainValidatorFactory(validator)));

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            validator.CleanedUpKeys.Should().HaveCount(2, "both staged records are cleaned up");
        }
    }
}
