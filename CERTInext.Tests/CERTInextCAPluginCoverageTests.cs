// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

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
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.Extensions.CAPlugin.CERTInext.Models;
using Keyfactor.PKI.Enums.EJBCA;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Coverage-group tests covering Groups A, B (Moq portions), and C.
    /// WireMock auth-failure branch tests are in CERTInextClientCoverageTests.
    /// </summary>
    public class CERTInextCAPluginCoverageTests
    {
        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

        private static Mock<ICERTInextClient> NewMock() =>
            new Mock<ICERTInextClient>(MockBehavior.Strict);

        private static Mock<ICertificateDataReader> NewReaderMock() =>
            new Mock<ICertificateDataReader>(MockBehavior.Strict);

        private static EnrollmentProductInfo MakeProductInfo(
            string profileId = MockCertificateData.ProfileIdTls,
            Dictionary<string, string> extras = null)
        {
            var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ProfileId"] = profileId
            };
            if (extras != null)
                foreach (var kv in extras)
                    parameters[kv.Key] = kv.Value;

            return new EnrollmentProductInfo
            {
                ProductID = profileId,
                ProductParameters = parameters
            };
        }

        private static async IAsyncEnumerable<LegacyGetCertificateResponse> AsyncEnum(
            IEnumerable<LegacyGetCertificateResponse> items)
        {
            foreach (var item in items)
            {
                await Task.Yield();
                yield return item;
            }
        }

        // =========================================================================
        // GROUP A — RenewOrReissueAsync + BuildEnrollmentResult + edge cases
        // =========================================================================

        // ---------------------------------------------------------------------------
        // A1a: PriorCertSN present, GetRequestIDBySerialNumber throws → new enroll
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task RenewOrReissue_FallsBackToNew_WhenGetRequestIDThrows()
        {
            var clientMock = NewMock();
            var readerMock = NewReaderMock();

            readerMock
                .Setup(r => r.GetRequestIDBySerialNumber(It.IsAny<string>()))
                .ThrowsAsync(new Exception("DB timeout"));

            clientMock
                .Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedEnrollResponse());

            var plugin = new CERTInextCAPlugin(clientMock.Object, readerMock.Object);

            var productInfo = MakeProductInfo(extras: new Dictionary<string, string>
            {
                ["PriorCertSN"] = "AABBCCDDEEFF"
            });

            var result = await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=test.example.com",
                san: null,
                productInfo: productInfo,
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.RenewOrReissue);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            clientMock.Verify(c => c.EnrollCertificateAsync(
                It.IsAny<EnrollCertificateRequest>(),
                It.IsAny<CancellationToken>()), Times.Once);
            clientMock.Verify(c => c.RenewCertificateAsync(
                It.IsAny<string>(),
                It.IsAny<RenewCertificateRequest>(),
                It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // A1b: PriorCertSN present, GetRequestIDBySerialNumber returns "" → new enroll
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task RenewOrReissue_FallsBackToNew_WhenGetRequestIDReturnsEmpty()
        {
            var clientMock = NewMock();
            var readerMock = NewReaderMock();

            readerMock
                .Setup(r => r.GetRequestIDBySerialNumber(It.IsAny<string>()))
                .ReturnsAsync(string.Empty);

            clientMock
                .Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedEnrollResponse());

            var plugin = new CERTInextCAPlugin(clientMock.Object, readerMock.Object);

            var productInfo = MakeProductInfo(extras: new Dictionary<string, string>
            {
                ["PriorCertSN"] = "AABBCCDDEEFF"
            });

            var result = await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=test.example.com",
                san: null,
                productInfo: productInfo,
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.RenewOrReissue);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            clientMock.Verify(c => c.EnrollCertificateAsync(
                It.IsAny<EnrollCertificateRequest>(),
                It.IsAny<CancellationToken>()), Times.Once);
        }

        // ---------------------------------------------------------------------------
        // A1c: PriorCertSN present, GetExpirationDateByRequestId returns null → new enroll
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task RenewOrReissue_FallsBackToNew_WhenExpiryIsNull()
        {
            var clientMock = NewMock();
            var readerMock = NewReaderMock();

            readerMock
                .Setup(r => r.GetRequestIDBySerialNumber(It.IsAny<string>()))
                .ReturnsAsync(MockCertificateData.CertId1);

            readerMock
                .Setup(r => r.GetExpirationDateByRequestId(MockCertificateData.CertId1))
                .Returns((DateTime?)null);

            clientMock
                .Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedEnrollResponse());

            var plugin = new CERTInextCAPlugin(clientMock.Object, readerMock.Object);

            var productInfo = MakeProductInfo(extras: new Dictionary<string, string>
            {
                ["PriorCertSN"] = "AABBCCDDEEFF"
            });

            var result = await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=test.example.com",
                san: null,
                productInfo: productInfo,
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.RenewOrReissue);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            // No renew API should be called when expiry is unknown
            clientMock.Verify(c => c.RenewCertificateAsync(
                It.IsAny<string>(),
                It.IsAny<RenewCertificateRequest>(),
                It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // A1d: PriorCertSN present, cert within renewal window → calls RenewCertificateAsync
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task RenewOrReissue_CallsRenewApi_WhenCertWithinRenewalWindow()
        {
            var clientMock = NewMock();
            var readerMock = NewReaderMock();

            // Expiry is 30 days in the future, renewal window is 90 days → within window
            DateTime expiry = DateTime.UtcNow.AddDays(30);

            readerMock
                .Setup(r => r.GetRequestIDBySerialNumber(It.IsAny<string>()))
                .ReturnsAsync(MockCertificateData.CertId1);

            readerMock
                .Setup(r => r.GetExpirationDateByRequestId(MockCertificateData.CertId1))
                .Returns(expiry);

            clientMock
                .Setup(c => c.RenewCertificateAsync(
                    MockCertificateData.CertId1,
                    It.IsAny<RenewCertificateRequest>(),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedEnrollResponse("cert-renewed-001"));

            var plugin = new CERTInextCAPlugin(clientMock.Object, readerMock.Object);

            var productInfo = MakeProductInfo(extras: new Dictionary<string, string>
            {
                ["PriorCertSN"] = "AABBCCDDEEFF",
                ["RenewalWindowDays"] = "90"
            });

            var result = await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=test.example.com",
                san: null,
                productInfo: productInfo,
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.RenewOrReissue);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            clientMock.Verify(c => c.RenewCertificateAsync(
                MockCertificateData.CertId1,
                It.IsAny<RenewCertificateRequest>(),
                It.IsAny<CancellationToken>()), Times.Once);
            clientMock.Verify(c => c.EnrollCertificateAsync(
                It.IsAny<EnrollCertificateRequest>(),
                It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // A1e: PriorCertSN present, cert already expired → new enroll
        // Semantics: useRenewalApi = expiry > now && expiry <= now + window.
        // A cert that has already expired (expiry in the past) does NOT satisfy the
        // first condition → falls back to new enroll (graceful degradation).
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task RenewOrReissue_FallsBackToNew_WhenCertOutsideRenewalWindow()
        {
            var clientMock = NewMock();
            var readerMock = NewReaderMock();

            // Already expired (200 days ago) → expiry > now is false → reissue/new
            DateTime expiry = DateTime.UtcNow.AddDays(-200);

            readerMock
                .Setup(r => r.GetRequestIDBySerialNumber(It.IsAny<string>()))
                .ReturnsAsync(MockCertificateData.CertId1);

            readerMock
                .Setup(r => r.GetExpirationDateByRequestId(MockCertificateData.CertId1))
                .Returns(expiry);

            clientMock
                .Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedEnrollResponse());

            var plugin = new CERTInextCAPlugin(clientMock.Object, readerMock.Object);

            var productInfo = MakeProductInfo(extras: new Dictionary<string, string>
            {
                ["PriorCertSN"] = "AABBCCDDEEFF",
                ["RenewalWindowDays"] = "90"
            });

            var result = await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=test.example.com",
                san: null,
                productInfo: productInfo,
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.RenewOrReissue);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            clientMock.Verify(c => c.EnrollCertificateAsync(
                It.IsAny<EnrollCertificateRequest>(),
                It.IsAny<CancellationToken>()), Times.Once);
            clientMock.Verify(c => c.RenewCertificateAsync(
                It.IsAny<string>(),
                It.IsAny<RenewCertificateRequest>(),
                It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // A1f: EnrollmentType.Renew (no PriorCertSN) → falls back to new enroll
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_Renew_FallsBackToNew_WhenNoPriorCertSnInParams()
        {
            var clientMock = NewMock();
            var readerMock = NewReaderMock();

            clientMock
                .Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedEnrollResponse());

            var plugin = new CERTInextCAPlugin(clientMock.Object, readerMock.Object);

            // No PriorCertSN parameter
            var result = await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=test.example.com",
                san: null,
                productInfo: MakeProductInfo(),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.Renew);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            clientMock.Verify(c => c.EnrollCertificateAsync(
                It.IsAny<EnrollCertificateRequest>(),
                It.IsAny<CancellationToken>()), Times.Once);
        }

        // ---------------------------------------------------------------------------
        // A2a: EnrollCertificateAsync returns Status="failed" → result Status == FAILED
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task BuildEnrollmentResult_ReturnsFailed_WhenCaReturnsFailedStatus()
        {
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(new EnrollCertificateResponse
                {
                    Id = "cert-fail-001",
                    Status = "failed",
                    Message = "CSR validation failed."
                });

            var plugin = new CERTInextCAPlugin(mock.Object);

            var result = await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=test.example.com",
                san: null,
                productInfo: MakeProductInfo(),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Status.Should().Be((int)EndEntityStatus.FAILED);
            result.CARequestID.Should().Be("cert-fail-001");
        }

        // ---------------------------------------------------------------------------
        // A2b: EnrollCertificateAsync returns Status="queued" (unknown) → FAILED
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task BuildEnrollmentResult_ReturnsFailed_WhenCaReturnsUnknownStatus()
        {
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(new EnrollCertificateResponse
                {
                    Id = "cert-queued-001",
                    Status = "queued"
                });

            var plugin = new CERTInextCAPlugin(mock.Object);

            var result = await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=test.example.com",
                san: null,
                productInfo: MakeProductInfo(),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            // "queued" maps to FAILED via StatusMapper default
            result.Status.Should().Be((int)EndEntityStatus.FAILED);
        }

        // ---------------------------------------------------------------------------
        // A3a: GetCertificateAsync returns Status="pending_approval" → throws "not in a revocable state"
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Revoke_Throws_WhenCertIsInNonRevocableState()
        {
            var mock = NewMock();
            mock.Setup(c => c.GetCertificateAsync(MockCertificateData.CertId2, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new LegacyGetCertificateResponse
                {
                    Id = MockCertificateData.CertId2,
                    Status = "pending_approval",
                    Subject = "CN=pending.example.com"
                });

            var plugin = new CERTInextCAPlugin(mock.Object);

            Func<Task> act = () => plugin.Revoke(MockCertificateData.CertId2, "AABB1122", revocationReason: 0);

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("*cannot be revoked*");
        }

        // ---------------------------------------------------------------------------
        // A4a: GetCertificateAsync throws generic Exception("Timeout") → rethrows
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task GetSingleRecord_Rethrows_WhenGenericExceptionOccurs()
        {
            var mock = NewMock();
            mock.Setup(c => c.GetCertificateAsync(MockCertificateData.CertId1, It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("Timeout"));

            var plugin = new CERTInextCAPlugin(mock.Object);

            Func<Task> act = () => plugin.GetSingleRecord(MockCertificateData.CertId1);

            await act.Should().ThrowAsync<Exception>().WithMessage("*Timeout*");
        }

        // ---------------------------------------------------------------------------
        // A5a: config.IgnoreExpired=true, expired + valid cert → only valid cert in output
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Synchronize_SkipsExpiredCerts_WhenIgnoreExpiredIsTrue()
        {
            var expiredCert = new LegacyGetCertificateResponse
            {
                Id = "cert-expired-111",
                Status = "issued",
                Certificate = MockCertificateData.FakePemCertificate,
                ProfileId = MockCertificateData.ProfileIdTls,
                ExpiresAt = DateTime.UtcNow.AddDays(-10) // already expired
            };

            // Valid cert: expiry well in the future so IgnoreExpired does NOT skip it
            var validCert = new LegacyGetCertificateResponse
            {
                Id = MockCertificateData.CertId1,
                Status = "issued",
                Certificate = MockCertificateData.FakePemCertificate,
                ProfileId = MockCertificateData.ProfileIdTls,
                ExpiresAt = DateTime.UtcNow.AddDays(365) // clearly not expired
            };

            var clientMock = NewMock();
            clientMock.Setup(c => c.ListCertificatesAsync(
                    It.IsAny<DateTime?>(),
                    It.IsAny<int>(),
                    It.IsAny<CancellationToken>()))
                .Returns(AsyncEnum(new List<LegacyGetCertificateResponse> { expiredCert, validCert }));

            var config = new CERTInextConfig { IgnoreExpired = true };
            var plugin = new CERTInextCAPlugin(clientMock.Object, config);

            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);
            await plugin.Synchronize(buffer, lastSync: null, fullSync: true, cancelToken: CancellationToken.None);
            // CompleteAdding() is called by Synchronize internally.

            var results = buffer.ToList();
            results.Should().HaveCount(1);
            results[0].CARequestID.Should().Be(MockCertificateData.CertId1);
        }

        // =========================================================================
        // GROUP B (Moq portion) — Status mapping variants via Synchronize + Revoke
        // =========================================================================

        // ---------------------------------------------------------------------------
        // B10a: Synchronize maps "active" and "expired" → both appear as GENERATED
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Synchronize_MapsActiveCert_AsGenerated()
        {
            var activeCert = new LegacyGetCertificateResponse
            {
                Id = "cert-active-001",
                Status = "active",
                Certificate = MockCertificateData.FakePemCertificate,
                ProfileId = MockCertificateData.ProfileIdTls
            };

            var expiredCert = new LegacyGetCertificateResponse
            {
                Id = "cert-expired-002",
                Status = "expired",
                Certificate = MockCertificateData.FakePemCertificate,
                ProfileId = MockCertificateData.ProfileIdTls,
                ExpiresAt = DateTime.UtcNow.AddDays(-1) // expired, but IgnoreExpired = false
            };

            var mock = NewMock();
            mock.Setup(c => c.ListCertificatesAsync(
                    It.IsAny<DateTime?>(),
                    It.IsAny<int>(),
                    It.IsAny<CancellationToken>()))
                .Returns(AsyncEnum(new List<LegacyGetCertificateResponse> { activeCert, expiredCert }));

            var plugin = new CERTInextCAPlugin(mock.Object); // IgnoreExpired = false by default

            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);
            await plugin.Synchronize(buffer, null, true, CancellationToken.None);
            // CompleteAdding() is called by Synchronize internally.

            var results = buffer.ToList();
            results.Should().HaveCount(2);
            results.All(r => r.Status == (int)EndEntityStatus.GENERATED).Should().BeTrue(
                "both 'active' and 'expired' should map to GENERATED");
        }

        // ---------------------------------------------------------------------------
        // B10b: Synchronize skips certs with "cancelled" and "rejected" (→ FAILED → skipped)
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Synchronize_SkipsCancelledAndRejectedCerts()
        {
            var cancelledCert = new LegacyGetCertificateResponse
            {
                Id = "cert-cancelled-001",
                Status = "cancelled",
                Certificate = null,
                ProfileId = MockCertificateData.ProfileIdTls
            };

            var rejectedCert = new LegacyGetCertificateResponse
            {
                Id = "cert-rejected-002",
                Status = "rejected",
                Certificate = null,
                ProfileId = MockCertificateData.ProfileIdTls
            };

            var validCert = MockCertificateData.IssuedCertRecord(MockCertificateData.CertId1);

            var mock = NewMock();
            mock.Setup(c => c.ListCertificatesAsync(
                    It.IsAny<DateTime?>(),
                    It.IsAny<int>(),
                    It.IsAny<CancellationToken>()))
                .Returns(AsyncEnum(new List<LegacyGetCertificateResponse> { cancelledCert, rejectedCert, validCert }));

            var plugin = new CERTInextCAPlugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);
            await plugin.Synchronize(buffer, null, true, CancellationToken.None);
            // CompleteAdding() is called by Synchronize internally.

            var results = buffer.ToList();
            results.Should().HaveCount(1);
            results[0].CARequestID.Should().Be(MockCertificateData.CertId1);
        }

        // ---------------------------------------------------------------------------
        // B10c: Revoke with CRL reason codes 6, 8, 9, 10 — extended coverage
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData(6u, "certificateHold")]
        [InlineData(8u, "removeFromCRL")]
        [InlineData(9u, "privilegeWithdrawn")]
        [InlineData(10u, "aACompromise")]
        public async Task Revoke_MapsExtendedCrlReasonCodes(uint reasonCode, string expectedReason)
        {
            var mock = NewMock();
            mock.Setup(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord());
            mock.Setup(c => c.RevokeCertificateAsync(
                    It.IsAny<string>(),
                    It.Is<RevokeCertificateRequest>(r => r.Reason == expectedReason),
                    It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            var plugin = new CERTInextCAPlugin(mock.Object);
            int result = await plugin.Revoke(MockCertificateData.CertId1, "serial", reasonCode);

            result.Should().Be((int)EndEntityStatus.REVOKED);
            mock.Verify(c => c.RevokeCertificateAsync(
                It.IsAny<string>(),
                It.Is<RevokeCertificateRequest>(r => r.Reason == expectedReason),
                It.IsAny<CancellationToken>()), Times.Once,
                $"CRL code {reasonCode} should map to '{expectedReason}'");
        }

        // ---------------------------------------------------------------------------
        // B10d: Synchronize with "totally-unknown-status" → maps to FAILED → skipped
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Synchronize_SkipsCertWithTotallyUnknownStatus()
        {
            var unknownCert = new LegacyGetCertificateResponse
            {
                Id = "cert-unknown-999",
                Status = "totally-unknown-status",
                Certificate = null,
                ProfileId = MockCertificateData.ProfileIdTls
            };

            var mock = NewMock();
            mock.Setup(c => c.ListCertificatesAsync(
                    It.IsAny<DateTime?>(),
                    It.IsAny<int>(),
                    It.IsAny<CancellationToken>()))
                .Returns(AsyncEnum(new List<LegacyGetCertificateResponse> { unknownCert }));

            var plugin = new CERTInextCAPlugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);
            await plugin.Synchronize(buffer, null, true, CancellationToken.None);
            // CompleteAdding() is called by Synchronize internally.

            buffer.ToList().Should().BeEmpty("unknown status maps to FAILED and should be skipped");
        }

        // =========================================================================
        // GROUP C — Annotations, Initialize, SAN builder, RevocationReason codes
        // =========================================================================

        // ---------------------------------------------------------------------------
        // C1a: GetCAConnectorAnnotations returns all expected keys
        // ---------------------------------------------------------------------------

        [Fact]
        public void GetCAConnectorAnnotations_ContainsAllExpectedKeys()
        {
            var mock = NewMock();
            var plugin = new CERTInextCAPlugin(mock.Object);

            var annotations = plugin.GetCAConnectorAnnotations();

            // Keys reflect the real CERTInext API configuration fields.
            // OAuthTokenUrl/OAuthClientId/OAuthClientSecret are the canonical names
            // (OAuth2* aliases resolve to the same string values via Constants.Config).
            var expectedKeys = new[]
            {
                "ApiUrl", "AccountNumber", "AuthMode", "ApiKey",
                "OAuthTokenUrl", "OAuthClientId", "OAuthClientSecret",
                "RequestorName", "RequestorEmail", "RequestorIsdCode", "RequestorMobileNumber",
                "SignerPlace", "SignerIp", "DefaultProductCode",
                "IgnoreExpired", "PageSize", "Enabled"
            };

            foreach (var key in expectedKeys)
            {
                annotations.Should().ContainKey(key, $"annotation '{key}' must be present");
            }
        }

        // ---------------------------------------------------------------------------
        // C1b: GetTemplateParameterAnnotations returns all expected keys
        // ---------------------------------------------------------------------------

        [Fact]
        public void GetTemplateParameterAnnotations_ContainsAllExpectedKeys()
        {
            var mock = NewMock();
            var plugin = new CERTInextCAPlugin(mock.Object);

            var annotations = plugin.GetTemplateParameterAnnotations();

            var expectedKeys = new[]
            {
                "ProductCode", "ProfileId", "ValidityYears", "ValidityDays",
                "AutoApprove", "RequesterName", "RequesterEmail", "RenewalWindowDays", "KeyType",
                // P2-B: four params that were in integration-manifest but missing from annotations
                "DomainName", "SignerName", "SignerPlace", "SignerIp"
            };

            foreach (var key in expectedKeys)
            {
                annotations.Should().ContainKey(key, $"template annotation '{key}' must be present");
            }
        }

        // ---------------------------------------------------------------------------
        // C2a: Initialize succeeds with valid ApiKey config
        // ---------------------------------------------------------------------------

        [Fact]
        public void Initialize_Succeeds_WithValidApiKeyConfig()
        {
            var configProviderMock = new Mock<IAnyCAPluginConfigProvider>(MockBehavior.Strict);
            var certReaderMock = NewReaderMock();

            configProviderMock.Setup(p => p.CAConnectionData)
                .Returns(new Dictionary<string, object>
                {
                    ["ApiUrl"] = "https://ca.example.com",
                    ["AuthMode"] = "ApiKey",
                    ["ApiKey"] = "test-api-key-value",
                    ["Enabled"] = true,
                    ["IgnoreExpired"] = false,
                    ["PageSize"] = 100
                });

            var plugin = new CERTInextCAPlugin();

            Action act = () => plugin.Initialize(configProviderMock.Object, certReaderMock.Object);

            act.Should().NotThrow();
        }

        // ---------------------------------------------------------------------------
        // C3a: Enroll passes ValidityDays, AutoApprove, RequesterName, RequesterEmail, KeyType
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_PassesAllEnrollmentParamsToRequest()
        {
            EnrollCertificateRequest capturedRequest = null;

            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(),
                    It.IsAny<CancellationToken>()))
                .Callback<EnrollCertificateRequest, CancellationToken>((req, _) => capturedRequest = req)
                .ReturnsAsync(MockCertificateData.IssuedEnrollResponse());

            var plugin = new CERTInextCAPlugin(mock.Object);

            var productInfo = MakeProductInfo(extras: new Dictionary<string, string>
            {
                ["ValidityDays"] = "365",
                ["AutoApprove"] = "true",
                ["RequesterName"] = "Jane Smith",
                ["RequesterEmail"] = "jane@example.com",
                ["KeyType"] = "RSA2048"
            });

            await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=test.example.com",
                san: new Dictionary<string, string[]> { ["dns"] = new[] { "test.example.com" } },
                productInfo: productInfo,
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            capturedRequest.Should().NotBeNull();
            capturedRequest!.ValidityDays.Should().Be(365);
            capturedRequest.RequesterName.Should().Be("Jane Smith");
            capturedRequest.RequesterEmail.Should().Be("jane@example.com");
            capturedRequest.KeyType.Should().Be("RSA2048");
        }

        // ---------------------------------------------------------------------------
        // C3b: Enroll with ValidityDays="not-a-number" → falls back to null/default
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_WithInvalidValidityDays_FallsBackToNull()
        {
            EnrollCertificateRequest capturedRequest = null;

            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(),
                    It.IsAny<CancellationToken>()))
                .Callback<EnrollCertificateRequest, CancellationToken>((req, _) => capturedRequest = req)
                .ReturnsAsync(MockCertificateData.IssuedEnrollResponse());

            var plugin = new CERTInextCAPlugin(mock.Object);

            var productInfo = MakeProductInfo(extras: new Dictionary<string, string>
            {
                ["ValidityDays"] = "not-a-number"
            });

            await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=test.example.com",
                san: null,
                productInfo: productInfo,
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            capturedRequest.Should().NotBeNull();
            // ValidityDays == 0 when parse fails, so request should have null
            capturedRequest!.ValidityDays.Should().BeNull(
                "invalid ValidityDays should fall back to null (use profile default)");
        }

        // ---------------------------------------------------------------------------
        // C4a: Enroll with SAN dict containing null value array → EnrollCertificateAsync still called
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_WithNullSanValueArray_StillCallsEnroll()
        {
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedEnrollResponse());

            var plugin = new CERTInextCAPlugin(mock.Object);

            // SAN dict has a key with a null value array — should not throw
            var san = new Dictionary<string, string[]>
            {
                ["dns"] = new[] { "test.example.com" },
                ["ip"] = null // null value array
            };

            var result = await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=test.example.com",
                san: san,
                productInfo: MakeProductInfo(),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            mock.Verify(c => c.EnrollCertificateAsync(
                It.IsAny<EnrollCertificateRequest>(),
                It.IsAny<CancellationToken>()), Times.Once);
        }

        // ---------------------------------------------------------------------------
        // C4b: Enroll with unknown SAN type "oid" → request SANs contains entry with Type="oid"
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_WithUnknownSanType_PassesThroughRawType()
        {
            EnrollCertificateRequest capturedRequest = null;

            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(),
                    It.IsAny<CancellationToken>()))
                .Callback<EnrollCertificateRequest, CancellationToken>((req, _) => capturedRequest = req)
                .ReturnsAsync(MockCertificateData.IssuedEnrollResponse());

            var plugin = new CERTInextCAPlugin(mock.Object);

            var san = new Dictionary<string, string[]>
            {
                ["oid"] = new[] { "1.2.3.4.5" }
            };

            await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=test.example.com",
                san: san,
                productInfo: MakeProductInfo(),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            capturedRequest.Should().NotBeNull();
            capturedRequest!.Sans.Should().NotBeNull();
            capturedRequest.Sans.Should().Contain(s => s.Type == "oid",
                "unknown SAN type should be passed through as-is");
        }

        // ---------------------------------------------------------------------------
        // C5a: GetSingleRecord maps each of the 10 known revocation reason strings
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData("unspecified", 0)]
        [InlineData("keyCompromise", 1)]
        [InlineData("caCompromise", 2)]
        [InlineData("affiliationChanged", 3)]
        [InlineData("superseded", 4)]
        [InlineData("cessationOfOperation", 5)]
        [InlineData("certificateHold", 6)]
        [InlineData("removeFromCRL", 8)]
        [InlineData("privilegeWithdrawn", 9)]
        [InlineData("aACompromise", 10)]
        public async Task GetSingleRecord_MapsRevocationReasonStringToCorrectCode(string reason, int expectedCode)
        {
            var certRecord = new LegacyGetCertificateResponse
            {
                Id = MockCertificateData.CertId3,
                Status = "revoked",
                Certificate = MockCertificateData.FakePemCertificate,
                ProfileId = MockCertificateData.ProfileIdTls,
                RevocationReason = reason,
                RevokedAt = DateTime.UtcNow.AddDays(-1)
            };

            var mock = NewMock();
            mock.Setup(c => c.GetCertificateAsync(MockCertificateData.CertId3, It.IsAny<CancellationToken>()))
                .ReturnsAsync(certRecord);

            var plugin = new CERTInextCAPlugin(mock.Object);
            var record = await plugin.GetSingleRecord(MockCertificateData.CertId3);

            record.RevocationReason.Should().Be(expectedCode,
                $"reason string '{reason}' should map to CRL code {expectedCode}");
        }
    }
}
