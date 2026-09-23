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
        // Synchronize still uses V1
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Synchronize_V2Enabled_StillCallsV1ListCertificatesAsync()
        {
            var mock = new Mock<ICERTInextClient>();

            // V1 sync path uses ListCertificatesAsync (the legacy wrapper)
            mock.Setup(c => c.ListCertificatesAsync(
                    It.IsAny<System.DateTime?>(),
                    It.IsAny<int>(),
                    It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable<LegacyGetCertificateResponse>());

            var plugin = BuildV2Plugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);
            buffer.CompleteAdding();

            // Run sync — should not throw
            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            mock.Verify(c => c.ListCertificatesAsync(
                It.IsAny<System.DateTime?>(),
                It.IsAny<int>(),
                It.IsAny<CancellationToken>()), Times.AtLeastOnce);
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
        // G1: ValidateCAConnectionInfo — V2 branch (ApiUrlV2/ClientId/ClientSecret)
        //
        // These test the CURRENT requirements: the V1 fields (ApiUrl/AccountNumber/AuthMode/...)
        // are always required, independent of UseV2Api. Phase 4 may relax that in V2 mode — each
        // case below builds its own minimal `info` dictionary so that change is a local edit per
        // test rather than a shared fixture that would need to be untangled.
        // ---------------------------------------------------------------------------

        private static Dictionary<string, object> ValidV1Fields() => new()
        {
            ["ApiUrl"] = "https://v1.certinext.io",
            ["AccountNumber"] = "12345",
            ["AuthMode"] = "AccessKey",
            ["ApiKey"] = "v1-key"
        };

        [Fact]
        public async Task ValidateCAConnectionInfo_Throws_WhenApiUrlV2Missing()
        {
            var plugin = BuildV2Plugin(NewMock().Object);
            var info = ValidV1Fields();
            info["UseV2Api"] = true;
            info["ClientId"] = "my-client";
            info["ClientSecret"] = "my-secret";
            // No ApiUrlV2

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*ApiUrlV2*required*");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_Throws_WhenApiUrlV2IsNotUri()
        {
            var plugin = BuildV2Plugin(NewMock().Object);
            var info = ValidV1Fields();
            info["UseV2Api"] = true;
            info["ApiUrlV2"] = "not-a-url";
            info["ClientId"] = "my-client";
            info["ClientSecret"] = "my-secret";

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*ApiUrlV2*valid absolute URI*");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_Throws_WhenClientIdMissing()
        {
            var plugin = BuildV2Plugin(NewMock().Object);
            var info = ValidV1Fields();
            info["UseV2Api"] = true;
            info["ApiUrlV2"] = "https://v2.certinext.io";
            // No ClientId
            info["ClientSecret"] = "my-secret";

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*ClientId*required*");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_Throws_WhenClientSecretMissing()
        {
            var plugin = BuildV2Plugin(NewMock().Object);
            var info = ValidV1Fields();
            info["UseV2Api"] = true;
            info["ApiUrlV2"] = "https://v2.certinext.io";
            info["ClientId"] = "my-client";
            // No ClientSecret

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*ClientSecret*required*");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_UseV2ApiFalse_IgnoresV2Fields()
        {
            // V1 field deliberately missing (ApiUrl) so the method throws before attempting any
            // live connectivity — proving this offline. The point of the test is that the
            // resulting error is about the V1 field only; the missing/invalid V2 fields below
            // must not appear in the error at all when UseV2Api is false.
            var plugin = BuildV2Plugin(NewMock().Object);
            var info = new Dictionary<string, object>
            {
                ["AccountNumber"] = "12345",
                ["AuthMode"] = "AccessKey",
                ["ApiKey"] = "v1-key",
                // No ApiUrl
                ["UseV2Api"] = false,
                ["ApiUrlV2"] = "not-a-url",
                // ClientId / ClientSecret also missing
            };

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            var ex = await act.Should().ThrowAsync<AnyCAValidationException>();
            ex.Which.Message.Should().Contain("ApiUrl").And.NotContain("ApiUrlV2")
                .And.NotContain("ClientId").And.NotContain("ClientSecret");
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
            var info = ValidV1Fields();
            info["UseV2Api"] = true;
            info["ApiUrlV2"] = server.Urls[0];
            info["ClientId"] = "my-client";
            info["ClientSecret"] = "my-secret";

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().NotThrowAsync(
                "all V1 and V2 fields are present and valid, and the live V2 ping succeeds");
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
