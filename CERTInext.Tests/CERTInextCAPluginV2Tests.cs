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

        private static CERTInextCAPlugin BuildV2Plugin(
            ICERTInextClient client,
            bool ignoreExpired = false,
            string dcvTxtRecordTemplate = null,
            string requestorIsdCode = null,
            string requestorMobileNumber = null,
            ICertificateDataReader certDataReader = null) =>
            new CERTInextCAPlugin(client, new CERTInextConfig
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
                PickupRetries   = 0,
                IgnoreExpired   = ignoreExpired,
                DcvTxtRecordTemplate  = dcvTxtRecordTemplate,
                RequestorIsdCode      = requestorIsdCode,
                RequestorMobileNumber = requestorMobileNumber
            }, certDataReader);

        /// <summary>
        /// Issue 0049: a mock <see cref="ICertificateDataReader"/> whose
        /// <see cref="ICertificateDataReader.GetExpirationDateByRequestId"/> returns a date,
        /// simulating a gateway row that already holds a certificate body. Tests that exercise
        /// revocation-detail/ProductId logic on a REVOKED-with-no-body record use this so the
        /// bodyless-REVOKED guard (<see cref="CERTInextCAPlugin.DecideBodylessRevokedRecord"/>,
        /// exercised directly in <c>Issue0049BodylessRevokedGuardTests</c>) lets the record
        /// through unchanged, keeping these tests focused on their own concern.
        /// </summary>
        private static ICertificateDataReader GatewayHoldsBodyReader(DateTime? expiry = null)
        {
            var mock = new Mock<ICertificateDataReader>();
            mock.Setup(r => r.GetExpirationDateByRequestId(It.IsAny<string>()))
                .Returns(expiry ?? DateTime.UtcNow.AddDays(30));
            return mock.Object;
        }

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

        /// <summary>
        /// Stubs <see cref="ICERTInextClient.GetProductDetailsV2Async"/> — every V2 enrollment now
        /// resolves the requested product's <c>productTypeID</c> from the live Catalog to decide
        /// UCC-ness (issues/f3-v2-multi-san-limitation.md), so any Strict-mock enroll test must
        /// stub this call regardless of whether the test cares about UCC behavior.
        /// </summary>
        private static void StubCatalog(Mock<ICERTInextClient> mock, string productCode, string productTypeId) =>
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = productCode, ProductTypeId = productTypeId, Active = true }
                });

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
            StubCatalog(mock, "842", "13"); // non-UCC (DV SSL)
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
            StubCatalog(mock, "842", "13"); // non-UCC (DV SSL)
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

        // By design (0021): V2 has no distinct renewal endpoint the plugin uses — CERTInext's
        // `/reissue` endpoint exists but is intentionally not called. RenewOrReissue places a
        // brand-new order via the same PlaceOrderV2Async path as a fresh enrollment; the prior
        // order/certificate is left issued rather than revoked or reused.
        [Fact]
        public async Task Enroll_V2Enabled_RenewOrReissue_PlacesNewOrderByDesign()
        {
            var mock = NewMock();
            StubCatalog(mock, "842", "13"); // non-UCC (DV SSL)
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
        // V2 product code resolution when no explicit ProductCode is configured (issue 0036).
        // ProductVariant is deliberately left at its "dv" default in these two tests even though
        // ProductID selects OV/EV SSL — ProductVariant and ProductID are independent enrollment
        // parameters (see issue 0036's own note on this), and using "dv" keeps the OV/EV
        // organization-block guard (issue 0028) out of scope so the test isolates product-code
        // resolution specifically.
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_V2_NoExplicitProductCode_ResolvesLiveCodeFromCatalog_NotStaleV1Table()
        {
            // ProductID "OV SSL" with NO ProductCode/ProfileId override. Pre-fix, this would have
            // fallen back to Constants.Products.DefaultProductCodes["OV SSL"] = "842" and sent that
            // on the wire — which the live catalog (per this stub) actually maps to DV SSL, not OV
            // SSL (issue 0036's silent-misissuance scenario). Post-fix, the code must be resolved
            // from the catalog entry whose productTypeID matches OV SSL ("16") — "846" in this
            // stub — a different value than the stale table's "842".
            var mock = NewMock();
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true }, // DV SSL
                    new ProductDetail { ProductCode = "846", ProductTypeId = "16", Active = true }, // OV SSL
                });

            string capturedProductCode = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>(
                    (_, code, __, ___) => capturedProductCode = code)
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = "ord_resolve_001", Status = "pending-dcv" });
            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), "ord_resolve_001", It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), "ord_resolve_001", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = "ord_resolve_001", Status = "pending-dcv" });

            var plugin = BuildV2Plugin(mock.Object);
            var productInfo = new EnrollmentProductInfo
            {
                ProductID = Constants.Products.OvSsl,
                ProductParameters = new Dictionary<string, string>
                {
                    ["ProductFamily"]  = "ssl",
                    ["ProductVariant"] = "dv",
                    ["DomainName"]     = "example.com"
                }
            };

            var result = await plugin.Enroll(
                MockCertificateData.FakeCsrPem,
                "CN=example.com, O=Acme",
                new Dictionary<string, string[]>(),
                productInfo,
                RequestFormat.PKCS10,
                EnrollmentType.New);

            result.CARequestID.Should().Be("ord_resolve_001");
            capturedProductCode.Should().Be("846",
                "the resolved code must come from the catalog's OV SSL entry (productTypeID 16), not " +
                "Constants.Products.DefaultProductCodes[\"OV SSL\"] (\"842\"), which the live catalog in " +
                "this stub actually maps to DV SSL");
            mock.Verify(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()), Times.Once,
                "the catalog fetched for code resolution must be the same call reused for UCC detection, not a second fetch");
        }

        [Fact]
        public async Task Enroll_V2_NoExplicitProductCode_NoMatchingCatalogEntry_FailsFastInsteadOfSilentlyProceeding()
        {
            // No override configured, and the live catalog (stubbed here) has no entry with the
            // productTypeID expected for EV SSL ("19") — must fail loudly with a clear message
            // rather than silently falling back to a wrong/stale code or ordering an unintended
            // product.
            var mock = NewMock();
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true }, // DV SSL only
                });

            var plugin = BuildV2Plugin(mock.Object);
            var productInfo = new EnrollmentProductInfo
            {
                ProductID = Constants.Products.EvSsl,
                ProductParameters = new Dictionary<string, string>
                {
                    ["ProductFamily"]  = "ssl",
                    ["ProductVariant"] = "dv",
                    ["DomainName"]     = "example.com"
                }
            };

            var result = await plugin.Enroll(
                MockCertificateData.FakeCsrPem,
                "CN=example.com, O=Acme",
                new Dictionary<string, string[]>(),
                productInfo,
                RequestFormat.PKCS10,
                EnrollmentType.New);

            result.Status.Should().Be((int)EndEntityStatus.FAILED);
            result.StatusMessage.Should().Contain("could not resolve a live product code");
            mock.Verify(c => c.PlaceOrderV2Async(
                It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()), Times.Never);
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
        // GetSingleRecord — RevocationDate/RevocationReason (issues/0034)
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task GetSingleRecord_V2Enabled_Revoked_PopulatesRevocationDateAndReason()
        {
            var mock = NewMock();
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                    MockCertificateData.V2OrderId1, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse
                {
                    OrderId        = MockCertificateData.V2OrderId1,
                    Status         = "revoked",
                    ProductVariant = "dv",
                    Revocation = new V2RevocationDetails
                    {
                        Status      = "Certificate Revoked",
                        Reason      = "cessation-of-operation",
                        ProcessedAt = new DateTime(2026, 9, 24, 20, 44, 41, DateTimeKind.Utc)
                    }
                }));

            // Issue 0049: this record has no certificate body, so the bodyless-REVOKED guard
            // would otherwise downgrade it to FAILED — a reader that reports the gateway
            // already holds a body keeps this test focused on revocation-detail population.
            var plugin = BuildV2Plugin(mock.Object, certDataReader: GatewayHoldsBodyReader());
            var record = await plugin.GetSingleRecord(MockCertificateData.V2OrderId1);

            record.Status.Should().Be((int)EndEntityStatus.REVOKED);
            record.RevocationDate.Should().Be(new DateTime(2026, 9, 24, 20, 44, 41, DateTimeKind.Utc));
            record.RevocationReason.Should().Be(5); // cessation-of-operation
        }

        [Fact]
        public async Task GetSingleRecord_V2Enabled_NotRevoked_RevocationFieldsDefault()
        {
            var mock = NewMock();
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                    MockCertificateData.V2OrderId1, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse
                {
                    OrderId        = MockCertificateData.V2OrderId1,
                    Status         = "issued",
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

            record.RevocationDate.Should().BeNull();
            record.RevocationReason.Should().Be(0);
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
        // Reason code fallback (issues/0026): CERTInext rejects the spec-documented
        // "unspecified" reason value (422 "Invalid Revoke Reason ID"), confirmed live.
        // Command defaults to CRL reason 0 (unspecified) when no reason is given, so
        // the plugin retries once with "cessation-of-operation" for that specific case.
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Revoke_V2Enabled_UnspecifiedReasonRejected_RetriesWithCessationOfOperation()
        {
            var mock = new Mock<ICERTInextClient>();
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                    MockCertificateData.V2OrderId1, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse
                {
                    OrderId = MockCertificateData.V2OrderId1,
                    Status  = "issued"
                }));

            var seenReasons = new List<string>();
            mock.Setup(c => c.RevokeOrderV2Async(
                    Constants.ApiV2.FamilySsl, MockCertificateData.V2OrderId1,
                    It.IsAny<V2RevokeRequest>(), It.IsAny<CancellationToken>()))
                .Returns((string family, string orderId, V2RevokeRequest req, CancellationToken ct) =>
                {
                    seenReasons.Add(req.Reason);
                    if (req.Reason == Constants.RevocationReasonV2.Unspecified)
                        throw new InvalidOperationException("V2 revoke rejected. Unprocessable Entity: Invalid Revoke Reason ID");
                    return Task.CompletedTask;
                });

            var plugin = BuildV2Plugin(mock.Object);
            // Reason code 0 (unspecified) is Command's default when no explicit reason is given.
            var status = await plugin.Revoke(MockCertificateData.V2OrderId1, "AABB", 0u);

            status.Should().Be((int)EndEntityStatus.REVOKED);
            seenReasons.Should().Equal(
                Constants.RevocationReasonV2.Unspecified,
                Constants.RevocationReasonV2.CessationOfOperation);
        }

        [Fact]
        public async Task Revoke_V2Enabled_NonUnspecifiedReasonRejected_DoesNotRetry()
        {
            var mock = new Mock<ICERTInextClient>();
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                    MockCertificateData.V2OrderId1, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse
                {
                    OrderId = MockCertificateData.V2OrderId1,
                    Status  = "issued"
                }));

            // CRL reason 6 (certificateHold) maps to "certificate-hold", which is also
            // rejected live (issues/0026) — but since it isn't "unspecified", the plugin
            // must surface the failure as-is rather than retry.
            mock.Setup(c => c.RevokeOrderV2Async(
                    Constants.ApiV2.FamilySsl, MockCertificateData.V2OrderId1,
                    It.IsAny<V2RevokeRequest>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new InvalidOperationException("V2 revoke rejected. Unprocessable Entity: Invalid Revoke Reason ID"));

            var plugin = BuildV2Plugin(mock.Object);
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(
                () => plugin.Revoke(MockCertificateData.V2OrderId1, "AABB", 6u));

            ex.Message.Should().Contain("Invalid Revoke Reason ID");
            mock.Verify(c => c.RevokeOrderV2Async(
                Constants.ApiV2.FamilySsl, MockCertificateData.V2OrderId1,
                It.IsAny<V2RevokeRequest>(), It.IsAny<CancellationToken>()), Times.Once);
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
        // Synchronize (V2, issues/0022) — uses V2 /reports/orders, not V1 GetOrderReport.
        // ---------------------------------------------------------------------------

        private static OrderReportEntryV2 ReportRow(
            string orderNumber, string orderStatus, string certificateStatus,
            string domainName = "example.com", string productCode = "842",
            string certificateExpiryDate = null) =>
            new OrderReportEntryV2
            {
                OrderNumber           = orderNumber,
                OrderStatus           = orderStatus,
                CertificateStatus     = certificateStatus,
                DomainName            = domainName,
                ProductCode           = productCode,
                OrderDate             = System.DateTime.UtcNow.AddHours(-1).ToString("o"),
                CertificateExpiryDate = certificateExpiryDate
            };

        [Fact]
        public async Task Synchronize_V2Enabled_UsesListOrdersV2Async_NotV1ListCertificates()
        {
            var mock = new Mock<ICERTInextClient>();

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable<OrderReportEntryV2>());

            var plugin = BuildV2Plugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            mock.Verify(c => c.ListOrdersV2Async(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()), Times.AtLeastOnce);
            mock.Verify(c => c.ListCertificatesAsync(
                It.IsAny<System.DateTime?>(), It.IsAny<int>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Synchronize_V2Enabled_IssuedRow_DownloadsCertificateBody()
        {
            var mock = new Mock<ICERTInextClient>();
            var row = ReportRow("ord_v2sync_001", "Order Fulfilled", "Certificate Downloaded");

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            mock.Setup(c => c.ResolveAndDownloadCertificateV2Async("ord_v2sync_001", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CertificateDownloadResponse
                {
                    OrderId        = "ord_v2sync_001",
                    SerialNumber   = "AABBCC",
                    CertificatePem = MockCertificateData.FakePemCertificate
                });

            var plugin = BuildV2Plugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            var records = buffer.ToArray();
            records.Should().ContainSingle();
            records[0].CARequestID.Should().Be("ord_v2sync_001");
            records[0].Status.Should().Be((int)EndEntityStatus.GENERATED);
            records[0].Certificate.Should().StartWith("-----BEGIN CERTIFICATE-----");
            records[0].ProductID.Should().Be("842");

            // Recognised report-status strings must not need a live track fallback.
            mock.Verify(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Synchronize_V2Enabled_UnrecognizedStatus_FallsBackToLiveTrack()
        {
            var mock = new Mock<ICERTInextClient>();
            // "Something New" is deliberately not in the known display-string vocabulary
            // (issues/0022 — the vocabulary is not confirmed exhaustive).
            var row = ReportRow("ord_v2sync_002", "Something New", "Also New");

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync("ord_v2sync_002", It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse
                {
                    OrderId = "ord_v2sync_002", Status = "issued", Domain = "example.com"
                }));

            mock.Setup(c => c.ResolveAndDownloadCertificateV2Async("ord_v2sync_002", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CertificateDownloadResponse
                {
                    OrderId        = "ord_v2sync_002",
                    CertificatePem = MockCertificateData.FakePemCertificate
                });

            var plugin = BuildV2Plugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            var records = buffer.ToArray();
            records.Should().ContainSingle();
            records[0].Status.Should().Be((int)EndEntityStatus.GENERATED,
                "an unrecognised report status must fall back to the authoritative live track " +
                "call rather than being dropped or guessed");

            mock.Verify(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                "ord_v2sync_002", It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task Synchronize_V2Enabled_RevokedRow_EmittedAsRevoked()
        {
            var mock = new Mock<ICERTInextClient>();
            var row = ReportRow("ord_v2sync_003", "Revoked", "Certificate Revoked");

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            // Issue 0049: this row has no certificate body, so the bodyless-REVOKED guard would
            // otherwise downgrade/skip it — a reader that reports the gateway already holds a
            // body keeps this test focused on "revoked rows never attempt a download".
            var plugin = BuildV2Plugin(mock.Object, certDataReader: GatewayHoldsBodyReader());
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            var records = buffer.ToArray();
            records.Should().ContainSingle();
            records[0].Status.Should().Be((int)EndEntityStatus.REVOKED);

            // Revoked rows have no body to download.
            mock.Verify(c => c.ResolveAndDownloadCertificateV2Async(
                It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // Synchronize — RevocationDate/RevocationReason (issues/0034). OrderReportEntryV2
        // carries no revocation reason/date of its own — only a live TrackOrder response's
        // nested `revocation` object does, so these fields require a resolved
        // V2OrderStatusResponse regardless of which code path got there.
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Synchronize_V2Enabled_RevokedRow_ViaDisplayString_PopulatesRevocationDetails()
        {
            var mock = new Mock<ICERTInextClient>();
            // "Revoked"/"Certificate Revoked" resolve via the report's own display-string
            // vocabulary (TryMapV2ReportDisplayStatus) with no live track call — the revocation
            // detail must be fetched lazily, on top of that, specifically for this row.
            var row = ReportRow("ord_v2sync_004", "Revoked", "Certificate Revoked");

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync("ord_v2sync_004", It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse
                {
                    OrderId = "ord_v2sync_004",
                    Status  = "revoked",
                    Revocation = new V2RevocationDetails
                    {
                        Status      = "Certificate Revoked",
                        Reason      = "key-compromise",
                        ProcessedAt = new System.DateTime(2026, 9, 24, 20, 44, 41, System.DateTimeKind.Utc)
                    }
                }));

            // Issue 0049: no certificate body on this row — a reader that reports the gateway
            // already holds a body keeps this test focused on revocation-detail population
            // rather than the bodyless-REVOKED guard (covered separately).
            var plugin = BuildV2Plugin(mock.Object, certDataReader: GatewayHoldsBodyReader());
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            var records = buffer.ToArray();
            records.Should().ContainSingle();
            records[0].Status.Should().Be((int)EndEntityStatus.REVOKED);
            records[0].RevocationDate.Should().Be(new System.DateTime(2026, 9, 24, 20, 44, 41, System.DateTimeKind.Utc));
            records[0].RevocationReason.Should().Be(1); // key-compromise

            mock.Verify(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                "ord_v2sync_004", It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task Synchronize_V2Enabled_RevokedRow_ViaUnresolvedFallback_PopulatesRevocationDetails()
        {
            var mock = new Mock<ICERTInextClient>();
            // Deliberately unrecognized display strings so disposition resolves via the
            // unresolved-status fallback, which already performs a live TrackOrder call —
            // trackedStatus (and its Revocation) is already populated before the
            // revocation-specific lazy-fetch in Synchronize would otherwise need to run one.
            var row = ReportRow("ord_v2sync_005", "Something New", "Also New");

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync("ord_v2sync_005", It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse
                {
                    OrderId = "ord_v2sync_005",
                    Status  = "revoked",
                    Revocation = new V2RevocationDetails
                    {
                        Status      = "Certificate Revoked",
                        Reason      = "superseded",
                        ProcessedAt = new System.DateTime(2026, 1, 2, 3, 4, 5, System.DateTimeKind.Utc)
                    }
                }));

            // Issue 0049: no certificate body on this row — a reader that reports the gateway
            // already holds a body keeps this test focused on revocation-detail population
            // rather than the bodyless-REVOKED guard (covered separately).
            var plugin = BuildV2Plugin(mock.Object, certDataReader: GatewayHoldsBodyReader());
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            var records = buffer.ToArray();
            records.Should().ContainSingle();
            records[0].RevocationDate.Should().Be(new System.DateTime(2026, 1, 2, 3, 4, 5, System.DateTimeKind.Utc));
            records[0].RevocationReason.Should().Be(4); // superseded

            // Only the one fallback call — the revocation-specific lazy-fetch must not
            // double-call when trackedStatus is already populated.
            mock.Verify(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                "ord_v2sync_005", It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task Synchronize_V2Enabled_NotRevokedRow_RevocationFieldsDefault()
        {
            var mock = new Mock<ICERTInextClient>();
            var row = ReportRow("ord_v2sync_006", "Order Fulfilled", "Certificate Downloaded");

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            mock.Setup(c => c.ResolveAndDownloadCertificateV2Async("ord_v2sync_006", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CertificateDownloadResponse
                {
                    OrderId        = "ord_v2sync_006",
                    CertificatePem = MockCertificateData.FakePemCertificate
                });

            var plugin = BuildV2Plugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            var records = buffer.ToArray();
            records.Should().ContainSingle();
            records[0].RevocationDate.Should().BeNull();
            records[0].RevocationReason.Should().Be(0);

            // Not revoked — must not incur the revocation-detail lazy-fetch at all.
            mock.Verify(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // Synchronize — ProductID preference: report row's ProductCode vs. a lazily-
        // fetched trackedStatus.ProductVariant (issues/0035). No new live call is added
        // by this preference — it only reads whatever trackedStatus already exists in
        // local scope from one of the three pre-existing lazy-fetch branches (unresolved-
        // status fallback, DCV attempt, revoked-row lookup).
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Synchronize_V2Enabled_ProductId_PrefersReportRowProductCode_OverTrackedStatus()
        {
            var mock = new Mock<ICERTInextClient>();
            // Unrecognised display strings force the unresolved-status fallback, which
            // populates trackedStatus (with a *different* ProductVariant) — the report
            // row's own non-empty ProductCode must still win.
            var row = ReportRow("ord_v2sync_035a", "Something New", "Also New", productCode: "842");

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync("ord_v2sync_035a", It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse
                {
                    OrderId        = "ord_v2sync_035a",
                    Status         = "revoked",
                    ProductVariant = "ov-ucc"
                }));

            // Issue 0049: no certificate body on this row — a reader that reports the gateway
            // already holds a body keeps this test focused on ProductID preference rather than
            // the bodyless-REVOKED guard (covered separately).
            var plugin = BuildV2Plugin(mock.Object, certDataReader: GatewayHoldsBodyReader());
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            var records = buffer.ToArray();
            records.Should().ContainSingle();
            records[0].ProductID.Should().Be("842", "the report row's own ProductCode must be " +
                "preferred over trackedStatus.ProductVariant whenever it is present");

            // No extra call beyond the fallback the unresolved status already required.
            mock.Verify(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                "ord_v2sync_035a", It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task Synchronize_V2Enabled_ProductId_FallsBackToTrackedStatusProductVariant_WhenReportRowEmpty()
        {
            var mock = new Mock<ICERTInextClient>();
            var row = ReportRow("ord_v2sync_035b", "Something New", "Also New", productCode: "");

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync("ord_v2sync_035b", It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse
                {
                    OrderId        = "ord_v2sync_035b",
                    Status         = "revoked",
                    ProductVariant = "ov-ucc"
                }));

            // Issue 0049: no certificate body on this row — a reader that reports the gateway
            // already holds a body keeps this test focused on ProductID preference rather than
            // the bodyless-REVOKED guard (covered separately).
            var plugin = BuildV2Plugin(mock.Object, certDataReader: GatewayHoldsBodyReader());
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            var records = buffer.ToArray();
            records.Should().ContainSingle();
            records[0].ProductID.Should().Be("ov-ucc", "when the report row's ProductCode is " +
                "empty, an already-populated trackedStatus.ProductVariant must be used instead " +
                "of leaving the field empty");
        }

        [Fact]
        public async Task Synchronize_V2Enabled_ProductId_EmptyWhenReportRowEmptyAndNoTrackedStatusFetched()
        {
            var mock = new Mock<ICERTInextClient>();
            // Recognised display strings resolve disposition without any live track call,
            // so trackedStatus is never populated for this row.
            var row = ReportRow("ord_v2sync_035c", "Order Fulfilled", "Certificate Downloaded", productCode: "");

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            mock.Setup(c => c.ResolveAndDownloadCertificateV2Async("ord_v2sync_035c", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CertificateDownloadResponse
                {
                    OrderId        = "ord_v2sync_035c",
                    CertificatePem = MockCertificateData.FakePemCertificate
                });

            var plugin = BuildV2Plugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            var records = buffer.ToArray();
            records.Should().ContainSingle();
            records[0].ProductID.Should().Be(string.Empty, "with no ProductCode and no " +
                "trackedStatus fetched for this row, ProductID must stay empty rather than " +
                "crash or guess a value");

            // Confirms trackedStatus really is null here — no fetch was ever made for this row.
            mock.Verify(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Synchronize_V2Enabled_ProductId_EmptyWhenTrackedStatusProductVariantAlsoEmpty()
        {
            var mock = new Mock<ICERTInextClient>();
            var row = ReportRow("ord_v2sync_035d", "Something New", "Also New", productCode: "");

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync("ord_v2sync_035d", It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse
                {
                    OrderId        = "ord_v2sync_035d",
                    Status         = "revoked",
                    ProductVariant = null
                }));

            // Issue 0049: no certificate body on this row — a reader that reports the gateway
            // already holds a body keeps this test focused on ProductID preference rather than
            // the bodyless-REVOKED guard (covered separately).
            var plugin = BuildV2Plugin(mock.Object, certDataReader: GatewayHoldsBodyReader());
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            var records = buffer.ToArray();
            records.Should().ContainSingle();
            records[0].ProductID.Should().Be(string.Empty, "when both the report row's " +
                "ProductCode and trackedStatus.ProductVariant are empty/null, ProductID must " +
                "stay empty rather than guess a value");
        }

        [Fact]
        public async Task Synchronize_V2Enabled_TerminalStatus_SkippedNotEmitted()
        {
            var mock = new Mock<ICERTInextClient>();
            var row = ReportRow("ord_v2sync_004", "Order Cancelled", null);

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            var plugin = BuildV2Plugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            buffer.ToArray().Should().BeEmpty("terminal/cancelled orders are skipped, not emitted");
        }

        [Fact]
        public async Task Synchronize_V2Enabled_IncrementalSync_RequestsLookbackWindow()
        {
            var mock = new Mock<ICERTInextClient>();
            string capturedFrom = null;
            var lastSync = new System.DateTime(2026, 6, 15, 12, 0, 0, System.DateTimeKind.Utc);

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, int, CancellationToken>((from, to, size, ct) => capturedFrom = from)
                .Returns(AsyncEnumerable<OrderReportEntryV2>());

            var plugin = BuildV2Plugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, lastSync, fullSync: false, CancellationToken.None);

            // Default lookback is 72h (Constants.ApiV2.DefaultSyncLookbackHours) — the requested
            // 'from' must be lastSync minus that window, not lastSync itself (issues/0022: the
            // from/to filter's order-date-vs-issue-date semantics were not confirmed live).
            var expectedFrom = lastSync.AddHours(-Constants.ApiV2.DefaultSyncLookbackHours).ToString("yyyy-MM-dd");
            capturedFrom.Should().Be(expectedFrom);
        }

        [Fact]
        public async Task Synchronize_V2Enabled_FullSync_RequestsNoFromFilter()
        {
            var mock = new Mock<ICERTInextClient>();
            string capturedFrom = "unset";

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, int, CancellationToken>((from, to, size, ct) => capturedFrom = from)
                .Returns(AsyncEnumerable<OrderReportEntryV2>());

            var plugin = BuildV2Plugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, System.DateTime.UtcNow, fullSync: true, CancellationToken.None);

            capturedFrom.Should().BeNull("a full sync requests the entire order history, not a bounded window");
        }

        // ---------------------------------------------------------------------------
        // Synchronize — IgnoreExpired (issues/0027 item 3). V1's Synchronize skips expired
        // certs when IgnoreExpired is configured; SynchronizeV2Async had no equivalent check
        // even though the report row (OrderReportEntryV2.CertificateExpiryDate) carries the
        // data needed. CertificateExpiryDate is a string whose format isn't confirmed live,
        // so an unparseable/missing value must NOT be skipped.
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Synchronize_V2Enabled_IgnoreExpired_ExpiredCert_Skipped()
        {
            var mock = new Mock<ICERTInextClient>();
            var row = ReportRow(
                "ord_v2sync_expired_001", "Order Fulfilled", "Certificate Downloaded",
                certificateExpiryDate: System.DateTime.UtcNow.AddDays(-30).ToString("o"));

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            var plugin = BuildV2Plugin(mock.Object, ignoreExpired: true);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            buffer.ToArray().Should().BeEmpty(
                "an expired certificate must be skipped entirely when IgnoreExpired=true");

            // Skipped before any status/download work — no live calls should be made for this row.
            mock.Verify(c => c.ResolveAndDownloadCertificateV2Async(
                It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
            mock.Verify(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Synchronize_V2Enabled_IgnoreExpired_NonExpiredCert_Kept()
        {
            var mock = new Mock<ICERTInextClient>();
            var row = ReportRow(
                "ord_v2sync_expired_002", "Order Fulfilled", "Certificate Downloaded",
                certificateExpiryDate: System.DateTime.UtcNow.AddDays(30).ToString("o"));

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            mock.Setup(c => c.ResolveAndDownloadCertificateV2Async("ord_v2sync_expired_002", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CertificateDownloadResponse
                {
                    OrderId        = "ord_v2sync_expired_002",
                    CertificatePem = MockCertificateData.FakePemCertificate
                });

            var plugin = BuildV2Plugin(mock.Object, ignoreExpired: true);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            var records = buffer.ToArray();
            records.Should().ContainSingle(
                "a certificate that has not yet expired must still be emitted even with " +
                "IgnoreExpired=true");
            records[0].CARequestID.Should().Be("ord_v2sync_expired_002");
        }

        [Fact]
        public async Task Synchronize_V2Enabled_IgnoreExpired_UnparseableExpiryDate_NotSkipped()
        {
            var mock = new Mock<ICERTInextClient>();
            var row = ReportRow(
                "ord_v2sync_expired_003", "Order Fulfilled", "Certificate Downloaded",
                certificateExpiryDate: "not-a-real-date");

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            mock.Setup(c => c.ResolveAndDownloadCertificateV2Async("ord_v2sync_expired_003", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CertificateDownloadResponse
                {
                    OrderId        = "ord_v2sync_expired_003",
                    CertificatePem = MockCertificateData.FakePemCertificate
                });

            var plugin = BuildV2Plugin(mock.Object, ignoreExpired: true);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            buffer.ToArray().Should().ContainSingle(
                "an unparseable CertificateExpiryDate must not be treated as expired — the row " +
                "should be emitted, not silently dropped");
        }

        [Fact]
        public async Task Synchronize_V2Enabled_IgnoreExpired_MissingExpiryDate_NotSkipped()
        {
            var mock = new Mock<ICERTInextClient>();
            var row = ReportRow(
                "ord_v2sync_expired_004", "Order Fulfilled", "Certificate Downloaded",
                certificateExpiryDate: null);

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            mock.Setup(c => c.ResolveAndDownloadCertificateV2Async("ord_v2sync_expired_004", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CertificateDownloadResponse
                {
                    OrderId        = "ord_v2sync_expired_004",
                    CertificatePem = MockCertificateData.FakePemCertificate
                });

            var plugin = BuildV2Plugin(mock.Object, ignoreExpired: true);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            buffer.ToArray().Should().ContainSingle(
                "a missing CertificateExpiryDate (empty until issuance per the DTO's doc " +
                "comment) must not be treated as expired");
        }

        [Fact]
        public async Task Synchronize_V2Enabled_IgnoreExpiredFalse_ExpiredCert_NotSkipped()
        {
            var mock = new Mock<ICERTInextClient>();
            var row = ReportRow(
                "ord_v2sync_expired_005", "Order Fulfilled", "Certificate Downloaded",
                certificateExpiryDate: System.DateTime.UtcNow.AddDays(-30).ToString("o"));

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            mock.Setup(c => c.ResolveAndDownloadCertificateV2Async("ord_v2sync_expired_005", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CertificateDownloadResponse
                {
                    OrderId        = "ord_v2sync_expired_005",
                    CertificatePem = MockCertificateData.FakePemCertificate
                });

            // IgnoreExpired defaults to false — the filter must be opt-in.
            var plugin = BuildV2Plugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            buffer.ToArray().Should().ContainSingle(
                "with IgnoreExpired left at its default (false), expired certs must still be emitted");
        }

        // ---------------------------------------------------------------------------
        // Chain PEM assembly — Enroll V2 with chainPem
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_V2_WithChainPem_ConcatenatesLeafAndIntermediate()
        {
            var mock = NewMock();
            StubCatalog(mock, "842", "13"); // non-UCC (DV SSL)

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
            StubCatalog(mock, "842", "13"); // non-UCC (DV SSL)

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
        // ValidateCAConnectionInfo — consolidated config (issues/0022).
        //
        // V2 mode: a single ApiUrl (required in both modes) plus OAuthClientId/OAuthClientSecret.
        // V1-only fields (AccountNumber, AuthMode, ApiKey, ...) are NOT required when UseV2Api
        // is true. ApiUrlV2/ClientId/ClientSecret no longer exist.
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task ValidateCAConnectionInfo_V2_Throws_WhenApiUrlMissing()
        {
            var plugin = BuildV2Plugin(NewMock().Object);
            var info = new Dictionary<string, object>
            {
                ["UseV2Api"] = true,
                ["OAuthClientId"] = "my-client",
                ["OAuthClientSecret"] = "my-secret"
                // No ApiUrl
            };

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*ApiUrl*required*");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_V2_Throws_WhenApiUrlIsNotUri()
        {
            var plugin = BuildV2Plugin(NewMock().Object);
            var info = new Dictionary<string, object>
            {
                ["UseV2Api"] = true,
                ["ApiUrl"] = "not-a-url",
                ["OAuthClientId"] = "my-client",
                ["OAuthClientSecret"] = "my-secret"
            };

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*ApiUrl*valid absolute URI*");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_V2_Throws_WhenOAuthClientIdMissing()
        {
            var plugin = BuildV2Plugin(NewMock().Object);
            var info = new Dictionary<string, object>
            {
                ["UseV2Api"] = true,
                ["ApiUrl"] = "https://v2.certinext.io",
                // No OAuthClientId
                ["OAuthClientSecret"] = "my-secret"
            };

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*OAuthClientId*required*");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_V2_Throws_WhenOAuthClientSecretMissing()
        {
            var plugin = BuildV2Plugin(NewMock().Object);
            var info = new Dictionary<string, object>
            {
                ["UseV2Api"] = true,
                ["ApiUrl"] = "https://v2.certinext.io",
                ["OAuthClientId"] = "my-client"
                // No OAuthClientSecret
            };

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*OAuthClientSecret*required*");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_V2_DoesNotRequireV1Credentials()
        {
            // No AccountNumber, AuthMode, or ApiKey at all — V1 credentials must be optional
            // when UseV2Api is true (issues/0022). Uses a real WireMock server so the live V2
            // ping (the only other thing this method does) succeeds.
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
            var info = new Dictionary<string, object>
            {
                ["UseV2Api"] = true,
                ["ApiUrl"] = server.Urls[0],
                ["OAuthClientId"] = "my-client",
                ["OAuthClientSecret"] = "my-secret"
                // No AccountNumber / AuthMode / ApiKey at all.
            };

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().NotThrowAsync(
                "V1 credentials (AccountNumber/AuthMode/ApiKey) must not be required when UseV2Api is true");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_V1_UseV2ApiFalse_StillRequiresAccountNumberAndAuthMode()
        {
            // UseV2Api false (the default/legacy path) — V1 requirements are unchanged, and the
            // (now nonexistent) V2-only fields must never appear in the resulting error.
            var plugin = BuildV2Plugin(NewMock().Object);
            var info = new Dictionary<string, object>
            {
                ["ApiUrl"] = "https://v1.certinext.io",
                ["UseV2Api"] = false
                // No AccountNumber, no AuthMode/ApiKey.
            };

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            var ex = await act.Should().ThrowAsync<AnyCAValidationException>();
            ex.Which.Message.Should().Contain("AccountNumber")
                .And.NotContain("ApiUrlV2").And.NotContain("OAuthClientId").And.NotContain("OAuthClientSecret");
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
            var info = new Dictionary<string, object>
            {
                ["UseV2Api"] = true,
                ["ApiUrl"] = server.Urls[0],
                ["OAuthClientId"] = "my-client",
                ["OAuthClientSecret"] = "my-secret"
            };

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().NotThrowAsync(
                "ApiUrl and OAuthClientId/OAuthClientSecret are present and valid, and the live V2 ping succeeds");
        }

        // ---------------------------------------------------------------------------
        // ValidateProductInfo — V2 (issue 0025). ValidateProductInfo builds its own
        // CERTInextClient from connectionInfo rather than using the Moq-injected client (like
        // ValidateCAConnectionInfo), so these tests use a real WireMock server as ApiUrl.
        // ---------------------------------------------------------------------------

        private static void StubV2TokenAndAuthMe(WireMockServer server)
        {
            server
                .Given(Request.Create().WithPath("/oauth/token").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2TokenResponseJson()));
        }

        private static Dictionary<string, object> BuildV2ConnectionInfo(string apiUrl) => new Dictionary<string, object>
        {
            ["UseV2Api"] = true,
            ["ApiUrl"] = apiUrl,
            ["OAuthClientId"] = "my-client",
            ["OAuthClientSecret"] = "my-secret"
        };

        private static EnrollmentProductInfo BuildProductInfo(string productCode) => new EnrollmentProductInfo
        {
            ProductID = "ssl",
            ProductParameters = new Dictionary<string, string> { ["ProductCode"] = productCode }
        };

        [Fact]
        public async Task ValidateProductInfo_V2_Succeeds_WhenProductCodeInCatalog()
        {
            using var server = WireMockServer.Start();
            StubV2TokenAndAuthMe(server);
            server
                .Given(Request.Create().WithPath("/api/certinext/v2/catalog/products").UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.GetCatalogProductsV2NestedJson()));

            var plugin = BuildV2Plugin(NewMock().Object);
            var connInfo = BuildV2ConnectionInfo(server.Urls[0]);
            var productInfo = BuildProductInfo(MockCertificateData.ProfileIdTls);

            Func<Task> act = () => plugin.ValidateProductInfo(productInfo, connInfo);

            await act.Should().NotThrowAsync();

            // Regression guard for issue 0025: in V2 mode this must go through the V2 catalog,
            // never the V1-only GetProductDetails endpoint.
            server.LogEntries.Should().NotContain(e => e.RequestMessage.Path == "/GetProductDetails");
            server.LogEntries.Should().Contain(e => e.RequestMessage.Path == "/api/certinext/v2/catalog/products");
        }

        [Fact]
        public async Task ValidateProductInfo_V2_Throws_WhenProductCodeNotInCatalog()
        {
            using var server = WireMockServer.Start();
            StubV2TokenAndAuthMe(server);
            server
                .Given(Request.Create().WithPath("/api/certinext/v2/catalog/products").UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.GetCatalogProductsV2NestedJson()));

            var plugin = BuildV2Plugin(NewMock().Object);
            var connInfo = BuildV2ConnectionInfo(server.Urls[0]);
            var productInfo = BuildProductInfo("999999");

            Func<Task> act = () => plugin.ValidateProductInfo(productInfo, connInfo);

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*not found*");
        }

        [Fact]
        public async Task ValidateProductInfo_V2_Throws_WhenCatalogEmpty()
        {
            using var server = WireMockServer.Start();
            StubV2TokenAndAuthMe(server);
            server
                .Given(Request.Create().WithPath("/api/certinext/v2/catalog/products").UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.GetCatalogProductsV2EmptyJson()));

            var plugin = BuildV2Plugin(NewMock().Object);
            var connInfo = BuildV2ConnectionInfo(server.Urls[0]);
            var productInfo = BuildProductInfo(MockCertificateData.ProfileIdTls);

            Func<Task> act = () => plugin.ValidateProductInfo(productInfo, connInfo);

            // No soft-accept on an empty/unusable catalog — must match V1's strict behaviour.
            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*not found*");
        }

        [Fact]
        public async Task ValidateProductInfo_V2_Throws_WhenCatalogReturnsError()
        {
            using var server = WireMockServer.Start();
            StubV2TokenAndAuthMe(server);
            server
                .Given(Request.Create().WithPath("/api/certinext/v2/catalog/products").UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(500)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody("{\"secretApiKeyLeak\":\"should-not-appear-in-message\"}"));

            var plugin = BuildV2Plugin(NewMock().Object);
            var connInfo = BuildV2ConnectionInfo(server.Urls[0]);
            var productInfo = BuildProductInfo(MockCertificateData.ProfileIdTls);

            Func<Task> act = () => plugin.ValidateProductInfo(productInfo, connInfo);

            var ex = await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*Unable to validate*");
            ex.Which.Message.Should().NotContain("secretApiKeyLeak");
        }

        // ---------------------------------------------------------------------------
        // productTypeID correctness check (issue 0036) — catches a code that exists in the
        // catalog but means a different product than the one selected, for both the
        // explicit-override case and the no-override/fallback case. Pre-fix, ValidateProductInfo
        // only checked catalog-existence and would have passed all of these.
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task ValidateProductInfo_V2_Throws_WhenProductCodeExistsButProductTypeIdMismatchesSelectedProduct()
        {
            // Template selects "OV SSL" (expects productTypeID "16") but overrides ProductCode to
            // "842", which the live catalog (stubbed here) resolves to productTypeID "13" = DV
            // SSL. The code exists — a pure existence check would pass this — but it means a
            // different product than the one selected.
            using var server = WireMockServer.Start();
            StubV2TokenAndAuthMe(server);
            server
                .Given(Request.Create().WithPath("/api/certinext/v2/catalog/products").UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(@"[{""productCode"":""842"",""productName"":""DV SSL Certificate"",""productTypeID"":""13""}]"));

            var plugin = BuildV2Plugin(NewMock().Object);
            var connInfo = BuildV2ConnectionInfo(server.Urls[0]);
            var productInfo = new EnrollmentProductInfo
            {
                ProductID = Constants.Products.OvSsl,
                ProductParameters = new Dictionary<string, string> { ["ProductCode"] = "842" }
            };

            Func<Task> act = () => plugin.ValidateProductInfo(productInfo, connInfo);

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*does not correspond to the selected product*");
        }

        [Fact]
        public async Task ValidateProductInfo_V2_Succeeds_WhenNoExplicitProductCode_ResolvesByProductTypeId()
        {
            // No ProductCode/ProfileId override configured — must validate via the live catalog's
            // productTypeID for the selected ProductId, not via Constants.Products.DefaultProductCodes
            // (V1-only; wrong numbering for V2).
            using var server = WireMockServer.Start();
            StubV2TokenAndAuthMe(server);
            server
                .Given(Request.Create().WithPath("/api/certinext/v2/catalog/products").UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(@"[{""productCode"":""846"",""productName"":""OV SSL Certificate"",""productTypeID"":""16""}]"));

            var plugin = BuildV2Plugin(NewMock().Object);
            var connInfo = BuildV2ConnectionInfo(server.Urls[0]);
            var productInfo = new EnrollmentProductInfo
            {
                ProductID = Constants.Products.OvSsl,
                ProductParameters = new Dictionary<string, string>()
            };

            Func<Task> act = () => plugin.ValidateProductInfo(productInfo, connInfo);

            await act.Should().NotThrowAsync();
        }

        [Fact]
        public async Task ValidateProductInfo_V2_Throws_WhenNoExplicitProductCode_AndCatalogHasNoMatchingProductTypeId()
        {
            // No override configured, and the live catalog has no entry with the productTypeID
            // expected for EV SSL ("19") — must fail loudly rather than silently pass.
            using var server = WireMockServer.Start();
            StubV2TokenAndAuthMe(server);
            server
                .Given(Request.Create().WithPath("/api/certinext/v2/catalog/products").UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(@"[{""productCode"":""842"",""productName"":""DV SSL Certificate"",""productTypeID"":""13""}]"));

            var plugin = BuildV2Plugin(NewMock().Object);
            var connInfo = BuildV2ConnectionInfo(server.Urls[0]);
            var productInfo = new EnrollmentProductInfo
            {
                ProductID = Constants.Products.EvSsl,
                ProductParameters = new Dictionary<string, string>()
            };

            Func<Task> act = () => plugin.ValidateProductInfo(productInfo, connInfo);

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*Could not find a CERTInext V2 catalog entry*");
        }

        // ---------------------------------------------------------------------------
        // Issue 0049 — bodyless-REVOKED guard. A V2 REVOKED record with no certificate
        // body must never reach the gateway buffer / be returned as-is unless
        // ICertificateDataReader.GetExpirationDateByRequestId confirms the gateway
        // already holds a body for that CARequestID (DecideBodylessRevokedRecord).
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Synchronize_Issue0049_RevokedNoBody_GatewayHoldsBody_EmitsBodylessRevoked()
        {
            var mock = new Mock<ICERTInextClient>();
            var row = ReportRow("ord_0049_a", "Revoked", "Certificate Revoked");

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            var readerMock = new Mock<ICertificateDataReader>();
            readerMock.Setup(r => r.GetExpirationDateByRequestId("ord_0049_a"))
                .Returns(DateTime.UtcNow.AddDays(45));

            var plugin = BuildV2Plugin(mock.Object, certDataReader: readerMock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            var records = buffer.ToArray();
            records.Should().ContainSingle(
                    "the gateway already holds a body for this order, so the revoke must " +
                    "still propagate as a bodyless REVOKED record")
                .Which.Status.Should().Be((int)EndEntityStatus.REVOKED);
            records[0].Certificate.Should().BeNullOrEmpty();

            readerMock.Verify(r => r.GetExpirationDateByRequestId("ord_0049_a"), Times.Once);
        }

        [Fact]
        public async Task Synchronize_Issue0049_RevokedNoBody_GatewayRowHasNoBody_EmitsFailedNotRevoked()
        {
            var mock = new Mock<ICERTInextClient>();
            var row = ReportRow("ord_0049_b", "Revoked", "Certificate Revoked");

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            var readerMock = new Mock<ICertificateDataReader>();
            readerMock.Setup(r => r.GetExpirationDateByRequestId("ord_0049_b"))
                .Returns((DateTime?)null); // row exists, but the gateway holds no body

            var plugin = BuildV2Plugin(mock.Object, certDataReader: readerMock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            var records = buffer.ToArray();
            records.Should().ContainSingle(
                    "a gateway row with no body must be downgraded to FAILED, never left as a " +
                    "bodyless REVOKED record")
                .Which.Status.Should().Be((int)EndEntityStatus.FAILED);
            records[0].Certificate.Should().BeNullOrEmpty();
            records[0].RevocationDate.Should().BeNull();
            records[0].RevocationReason.Should().Be(0);
        }

        [Fact]
        public async Task Synchronize_Issue0049_RevokedNoBody_NoGatewayRow_SkipsRecordEntirely()
        {
            var mock = new Mock<ICERTInextClient>();
            var row = ReportRow("ord_0049_c", "Revoked", "Certificate Revoked");

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            var readerMock = new Mock<ICertificateDataReader>();
            readerMock.Setup(r => r.GetExpirationDateByRequestId("ord_0049_c"))
                .Throws(new ArgumentException("No certificate/CA request exists for the specified request ID."));

            var plugin = BuildV2Plugin(mock.Object, certDataReader: readerMock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            buffer.ToArray().Should().BeEmpty(
                "the gateway has never seen this order — creating a bodyless REVOKED row would " +
                "poison it (RevocationDate is never cleared by the gateway)");
        }

        [Fact]
        public async Task Synchronize_Issue0049_RevokedNoBody_ReaderThrowsUnexpectedException_SkipsRecord()
        {
            var mock = new Mock<ICERTInextClient>();
            var row = ReportRow("ord_0049_d", "Revoked", "Certificate Revoked");

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            var readerMock = new Mock<ICertificateDataReader>();
            readerMock.Setup(r => r.GetExpirationDateByRequestId("ord_0049_d"))
                .Throws(new InvalidOperationException("gateway database unavailable"));

            var plugin = BuildV2Plugin(mock.Object, certDataReader: readerMock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            buffer.ToArray().Should().BeEmpty(
                "an unexpected reader failure must not risk emitting a bodyless REVOKED record — " +
                "the revoke is only delayed to a later sync");
        }

        [Fact]
        public async Task Synchronize_Issue0049_RevokedNoBody_NoCertificateDataReaderInjected_SkipsRecord()
        {
            var mock = new Mock<ICERTInextClient>();
            var row = ReportRow("ord_0049_e", "Revoked", "Certificate Revoked");

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));

            // No certDataReader supplied — BuildV2Plugin defaults it to null.
            var plugin = BuildV2Plugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            buffer.ToArray().Should().BeEmpty(
                "with no reader available to consult, the plugin must not risk creating a " +
                "poisoned gateway row");
        }

        [Fact]
        public async Task Synchronize_Issue0049_GeneratedRow_NeverConsultsReader()
        {
            var mock = new Mock<ICERTInextClient>();
            var row = ReportRow("ord_0049_f", "Order Fulfilled", "Certificate Downloaded");

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(row));
            mock.Setup(c => c.ResolveAndDownloadCertificateV2Async("ord_0049_f", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CertificateDownloadResponse
                {
                    OrderId        = "ord_0049_f",
                    CertificatePem = MockCertificateData.FakePemCertificate
                });

            // Strict with no setups — any call at all fails the test. Confirms the issue-0049
            // guard is scoped to REVOKED-with-no-body and never touches the GENERATED path.
            var readerMock = new Mock<ICertificateDataReader>(MockBehavior.Strict);
            var plugin = BuildV2Plugin(mock.Object, certDataReader: readerMock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            var records = buffer.ToArray();
            records.Should().ContainSingle()
                .Which.Status.Should().Be((int)EndEntityStatus.GENERATED);
            records[0].Certificate.Should().StartWith("-----BEGIN CERTIFICATE-----");

            readerMock.VerifyNoOtherCalls();
        }

        [Fact]
        public async Task Synchronize_Issue0049_MixedBatch_NeverEmitsBodylessRevokedWithoutReaderConfirmation()
        {
            var mock = new Mock<ICERTInextClient>();
            var rowHoldsBody = ReportRow("ord_0049_mix_holds", "Revoked", "Certificate Revoked");
            var rowNoBody    = ReportRow("ord_0049_mix_nobody", "Revoked", "Certificate Revoked");
            var rowNoRow     = ReportRow("ord_0049_mix_norow", "Revoked", "Certificate Revoked");

            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnumerable(rowHoldsBody, rowNoBody, rowNoRow));

            var readerMock = new Mock<ICertificateDataReader>();
            readerMock.Setup(r => r.GetExpirationDateByRequestId("ord_0049_mix_holds"))
                .Returns(DateTime.UtcNow.AddDays(60));
            readerMock.Setup(r => r.GetExpirationDateByRequestId("ord_0049_mix_nobody"))
                .Returns((DateTime?)null);
            readerMock.Setup(r => r.GetExpirationDateByRequestId("ord_0049_mix_norow"))
                .Throws(new ArgumentException("no such request id"));

            var plugin = BuildV2Plugin(mock.Object, certDataReader: readerMock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            var records = buffer.ToArray();

            // Core invariant (issue 0049): no record with Status=REVOKED and no certificate
            // body may reach the gateway buffer unless the reader confirmed the gateway
            // already holds a body for that specific CARequestID.
            records.Should().NotContain(r =>
                r.Status == (int)EndEntityStatus.REVOKED && string.IsNullOrEmpty(r.Certificate)
                && r.CARequestID != "ord_0049_mix_holds");

            records.Should().ContainSingle(r => r.CARequestID == "ord_0049_mix_holds")
                .Which.Status.Should().Be((int)EndEntityStatus.REVOKED);
            records.Should().ContainSingle(r => r.CARequestID == "ord_0049_mix_nobody")
                .Which.Status.Should().Be((int)EndEntityStatus.FAILED);
            records.Should().NotContain(r => r.CARequestID == "ord_0049_mix_norow");
        }

        [Fact]
        public async Task GetSingleRecord_Issue0049_RevokedNoBody_GatewayHoldsBody_ReturnsRevoked()
        {
            var mock = NewMock();
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                    MockCertificateData.V2OrderId1, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse
                {
                    OrderId        = MockCertificateData.V2OrderId1,
                    Status         = "revoked",
                    ProductVariant = "dv"
                }));

            var readerMock = new Mock<ICertificateDataReader>();
            readerMock.Setup(r => r.GetExpirationDateByRequestId(MockCertificateData.V2OrderId1))
                .Returns(DateTime.UtcNow.AddDays(10));

            var plugin = BuildV2Plugin(mock.Object, certDataReader: readerMock.Object);
            var record = await plugin.GetSingleRecord(MockCertificateData.V2OrderId1);

            record.Status.Should().Be((int)EndEntityStatus.REVOKED);
            record.Certificate.Should().BeNullOrEmpty();
        }

        [Fact]
        public async Task GetSingleRecord_Issue0049_RevokedNoBody_GatewayRowHasNoBody_ReturnsFailed()
        {
            var mock = NewMock();
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                    MockCertificateData.V2OrderId1, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse
                {
                    OrderId        = MockCertificateData.V2OrderId1,
                    Status         = "revoked",
                    ProductVariant = "dv",
                    Revocation = new V2RevocationDetails
                    {
                        Status      = "Certificate Revoked",
                        Reason      = "cessation-of-operation",
                        ProcessedAt = DateTime.UtcNow
                    }
                }));

            var readerMock = new Mock<ICertificateDataReader>();
            readerMock.Setup(r => r.GetExpirationDateByRequestId(MockCertificateData.V2OrderId1))
                .Returns((DateTime?)null);

            var plugin = BuildV2Plugin(mock.Object, certDataReader: readerMock.Object);
            var record = await plugin.GetSingleRecord(MockCertificateData.V2OrderId1);

            record.Status.Should().Be((int)EndEntityStatus.FAILED);
            record.Certificate.Should().BeNullOrEmpty();
            record.RevocationDate.Should().BeNull();
            record.RevocationReason.Should().Be(0);
        }

        [Fact]
        public async Task GetSingleRecord_Issue0049_RevokedNoBody_NoGatewayRow_ReturnsFailed()
        {
            var mock = NewMock();
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                    MockCertificateData.V2OrderId1, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse
                {
                    OrderId = MockCertificateData.V2OrderId1,
                    Status  = "revoked"
                }));

            var readerMock = new Mock<ICertificateDataReader>();
            readerMock.Setup(r => r.GetExpirationDateByRequestId(MockCertificateData.V2OrderId1))
                .Throws(new ArgumentException("no such request id"));

            var plugin = BuildV2Plugin(mock.Object, certDataReader: readerMock.Object);
            var record = await plugin.GetSingleRecord(MockCertificateData.V2OrderId1);

            record.Should().NotBeNull(
                "GetSingleRecord cannot skip — it must return something even when the gateway " +
                "has no row for this order");
            record.Status.Should().Be((int)EndEntityStatus.FAILED);
            record.Certificate.Should().BeNullOrEmpty();
            record.RevocationDate.Should().BeNull();
        }

        [Fact]
        public async Task GetSingleRecord_Issue0049_RevokedNoBody_NoCertificateDataReaderInjected_ReturnsFailed()
        {
            var mock = NewMock();
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                    MockCertificateData.V2OrderId1, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse
                {
                    OrderId = MockCertificateData.V2OrderId1,
                    Status  = "revoked"
                }));

            // No certDataReader supplied — BuildV2Plugin defaults it to null.
            var plugin = BuildV2Plugin(mock.Object);
            var record = await plugin.GetSingleRecord(MockCertificateData.V2OrderId1);

            record.Status.Should().Be((int)EndEntityStatus.FAILED);
        }

        [Fact]
        public async Task GetSingleRecord_Issue0049_GeneratedRecord_NeverConsultsReader()
        {
            var mock = NewMock();
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(
                    MockCertificateData.V2OrderId1, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse
                {
                    OrderId        = MockCertificateData.V2OrderId1,
                    Status         = "issued",
                    ProductVariant = "dv"
                }));
            mock.Setup(c => c.ResolveAndDownloadCertificateV2Async(
                    MockCertificateData.V2OrderId1, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CertificateDownloadResponse
                {
                    OrderId        = MockCertificateData.V2OrderId1,
                    CertificatePem = MockCertificateData.FakePemCertificate
                });

            // Strict with no setups — confirms the issue-0049 guard never touches GENERATED.
            var readerMock = new Mock<ICertificateDataReader>(MockBehavior.Strict);
            var plugin = BuildV2Plugin(mock.Object, certDataReader: readerMock.Object);

            var record = await plugin.GetSingleRecord(MockCertificateData.V2OrderId1);

            record.Status.Should().Be((int)EndEntityStatus.GENERATED);
            readerMock.VerifyNoOtherCalls();
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
