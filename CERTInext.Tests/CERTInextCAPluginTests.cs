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
    /// Unit tests for <see cref="CERTInextCAPlugin"/> IAnyCAPlugin logic.
    /// <see cref="ICERTInextClient"/> is mocked with Moq so no network calls are made.
    /// </summary>
    public class CERTInextCAPluginTests
    {
        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

        private static CERTInextCAPlugin BuildPlugin(ICERTInextClient client) =>
            new CERTInextCAPlugin(client);

        private static Mock<ICERTInextClient> NewMock() => new Mock<ICERTInextClient>(MockBehavior.Strict);

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

        /// <summary>Builds an async enumerable from a list for use in Moq setups.</summary>
        private static async IAsyncEnumerable<LegacyGetCertificateResponse> AsyncEnum(
            IEnumerable<LegacyGetCertificateResponse> items)
        {
            foreach (var item in items)
            {
                await Task.Yield();
                yield return item;
            }
        }

        // ---------------------------------------------------------------------------
        // Ping
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Ping_Succeeds_WhenClientPingAsyncDoesNotThrow()
        {
            var mock = NewMock();
            mock.Setup(c => c.PingAsync(It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            var plugin = BuildPlugin(mock.Object);

            await plugin.Ping();

            mock.Verify(c => c.PingAsync(It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task Ping_Rethrows_WhenClientPingThrows()
        {
            var mock = NewMock();
            mock.Setup(c => c.PingAsync(It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("Connection refused"));

            var plugin = BuildPlugin(mock.Object);

            Func<Task> act = () => plugin.Ping();

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("*CERTInext*Connection refused*");
        }

        // ---------------------------------------------------------------------------
        // GetProductIds
        // ---------------------------------------------------------------------------

        [Fact]
        public void GetProductIds_ReturnsActiveProfileIds()
        {
            var mock = NewMock();
            mock.Setup(c => c.GetProfilesAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.ActiveProfiles());

            var plugin = BuildPlugin(mock.Object);
            var ids = plugin.GetProductIds();

            ids.Should().HaveCount(2);
            ids.Should().Contain(MockCertificateData.ProfileIdTls);
            ids.Should().Contain(MockCertificateData.ProfileIdClient);
        }

        [Fact]
        public void GetProductIds_FiltersOutInactiveProfiles()
        {
            var mock = NewMock();
            mock.Setup(c => c.GetProfilesAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.MixedProfiles());

            var plugin = BuildPlugin(mock.Object);
            var ids = plugin.GetProductIds();

            ids.Should().NotContain("legacy-profile");
            ids.Should().HaveCount(2);
        }

        [Fact]
        public void GetProductIds_ReturnsEmptyList_WhenClientThrows()
        {
            var mock = NewMock();
            mock.Setup(c => c.GetProfilesAsync(It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("Unavailable"));

            var plugin = BuildPlugin(mock.Object);
            var ids = plugin.GetProductIds();

            ids.Should().BeEmpty();
        }

        // ---------------------------------------------------------------------------
        // ValidateCAConnectionInfo
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task ValidateCAConnectionInfo_Throws_WhenApiUrlMissing()
        {
            var mock = NewMock();
            var plugin = BuildPlugin(mock.Object);

            var info = new Dictionary<string, object>
            {
                ["AuthMode"] = "ApiKey",
                ["ApiKey"] = "some-key"
                // No ApiUrl
            };

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*ApiUrl*required*");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_Throws_WhenApiUrlIsNotUri()
        {
            var mock = NewMock();
            var plugin = BuildPlugin(mock.Object);

            var info = new Dictionary<string, object>
            {
                ["ApiUrl"] = "not-a-url",
                ["AuthMode"] = "ApiKey",
                ["ApiKey"] = "some-key"
            };

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*valid absolute URI*");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_Throws_WhenApiKeyMissingForApiKeyMode()
        {
            var mock = NewMock();
            var plugin = BuildPlugin(mock.Object);

            var info = new Dictionary<string, object>
            {
                ["ApiUrl"] = "https://ca.example.com",
                ["AuthMode"] = "ApiKey"
                // No ApiKey
            };

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*ApiKey*required*");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_Throws_WhenAuthModeIsBasicOrOtherUnsupported()
        {
            var mock = NewMock();
            var plugin = BuildPlugin(mock.Object);

            var info = new Dictionary<string, object>
            {
                ["ApiUrl"] = "https://ca.example.com",
                ["AccountNumber"] = "12345",
                ["AuthMode"] = "Basic"
                // Basic auth is not supported by the real CERTInext API
            };

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*AuthMode*must be one of*");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_Throws_WhenOAuthFieldsMissing()
        {
            var mock = NewMock();
            var plugin = BuildPlugin(mock.Object);

            var info = new Dictionary<string, object>
            {
                ["ApiUrl"] = "https://ca.example.com",
                ["AccountNumber"] = "12345",
                ["AuthMode"] = "OAuth"
                // Missing OAuthTokenUrl, OAuthClientId, OAuthClientSecret
            };

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*OAuthTokenUrl*required*");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_Throws_WhenAuthModeIsInvalid()
        {
            var mock = NewMock();
            var plugin = BuildPlugin(mock.Object);

            var info = new Dictionary<string, object>
            {
                ["ApiUrl"] = "https://ca.example.com",
                ["AuthMode"] = "CertificateBased"
            };

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*AuthMode*must be one of*");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_SkipsValidation_WhenDisabled()
        {
            var mock = NewMock();
            var plugin = BuildPlugin(mock.Object);

            var info = new Dictionary<string, object>
            {
                // No ApiUrl, no anything — but Enabled=false should skip all checks
                ["Enabled"] = false
            };

            // Should not throw
            await plugin.ValidateCAConnectionInfo(info);

            mock.VerifyNoOtherCalls();
        }

        // ---------------------------------------------------------------------------
        // ValidateProductInfo
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task ValidateProductInfo_Throws_WhenProfileIdMissing()
        {
            var mock = NewMock();
            var plugin = BuildPlugin(mock.Object);

            // Empty ProfileId
            var productInfo = new EnrollmentProductInfo
            {
                ProductID = string.Empty,
                ProductParameters = new Dictionary<string, string>()
            };

            var connInfo = new Dictionary<string, object>
            {
                ["ApiUrl"] = "https://ca.example.com",
                ["AuthMode"] = "ApiKey",
                ["ApiKey"] = "key"
            };

            Func<Task> act = () => plugin.ValidateProductInfo(productInfo, connInfo);

            await act.Should().ThrowAsync<AnyCAValidationException>()
                .WithMessage("*ProfileId*required*");
        }

        // ---------------------------------------------------------------------------
        // Enroll — New
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_New_CallsEnrollAsync_AndReturnsIssuedResult()
        {
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(
                    It.Is<EnrollCertificateRequest>(r => r.ProfileId == MockCertificateData.ProfileIdTls),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedEnrollResponse());

            var plugin = BuildPlugin(mock.Object);
            var productInfo = MakeProductInfo(MockCertificateData.ProfileIdTls);

            var result = await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=test.example.com",
                san: new Dictionary<string, string[]> { ["dns"] = new[] { "test.example.com" } },
                productInfo: productInfo,
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Should().NotBeNull();
            result.CARequestID.Should().Be(MockCertificateData.CertId1);
            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            result.Certificate.Should().Contain("BEGIN CERTIFICATE");

            mock.Verify(c => c.EnrollCertificateAsync(
                It.IsAny<EnrollCertificateRequest>(),
                It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task Enroll_New_ReturnsPendingStatus_WhenCaReturnsPendingApproval()
        {
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.PendingEnrollResponse());

            var plugin = BuildPlugin(mock.Object);

            var result = await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=test.example.com",
                san: null,
                productInfo: MakeProductInfo(),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
        }

        [Fact]
        public async Task Enroll_New_Throws_WhenProfileIdNotSet()
        {
            var mock = NewMock();
            var plugin = BuildPlugin(mock.Object);

            var productInfo = new EnrollmentProductInfo
            {
                ProductID = string.Empty,
                ProductParameters = new Dictionary<string, string>()
            };

            Func<Task> act = () => plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=test.example.com",
                san: null,
                productInfo: productInfo,
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("*ProfileId*required*");
        }

        [Fact]
        public async Task Enroll_Reissue_AlsoCallsEnrollAsync()
        {
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedEnrollResponse());

            var plugin = BuildPlugin(mock.Object);

            var result = await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=test.example.com",
                san: null,
                productInfo: MakeProductInfo(),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.Reissue);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            mock.Verify(c => c.EnrollCertificateAsync(
                It.IsAny<EnrollCertificateRequest>(),
                It.IsAny<CancellationToken>()), Times.Once);
        }

        // ---------------------------------------------------------------------------
        // Enroll — Renew (falls back to new when no PriorCertSN)
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_Renew_FallsBackToNewEnroll_WhenNoPriorCertSn()
        {
            var mock = NewMock();
            mock.Setup(c => c.EnrollCertificateAsync(
                    It.IsAny<EnrollCertificateRequest>(),
                    It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedEnrollResponse());

            var plugin = BuildPlugin(mock.Object);

            // RenewOrReissue with no PriorCertSN in parameters → falls back to new
            var result = await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=test.example.com",
                san: null,
                productInfo: MakeProductInfo(),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.RenewOrReissue);

            result.CARequestID.Should().Be(MockCertificateData.CertId1);
            mock.Verify(c => c.EnrollCertificateAsync(
                It.IsAny<EnrollCertificateRequest>(),
                It.IsAny<CancellationToken>()), Times.Once);
            mock.Verify(c => c.RenewCertificateAsync(
                It.IsAny<string>(),
                It.IsAny<RenewCertificateRequest>(),
                It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // GetSingleRecord
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task GetSingleRecord_ReturnsMappedCertificate_ForIssuedCert()
        {
            var mock = NewMock();
            mock.Setup(c => c.GetCertificateAsync(MockCertificateData.CertId1, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord());

            var plugin = BuildPlugin(mock.Object);
            var record = await plugin.GetSingleRecord(MockCertificateData.CertId1);

            record.Should().NotBeNull();
            record.CARequestID.Should().Be(MockCertificateData.CertId1);
            record.Status.Should().Be((int)EndEntityStatus.GENERATED);
            record.Certificate.Should().Contain("BEGIN CERTIFICATE");
            record.ProductID.Should().Be(MockCertificateData.ProfileIdTls);
        }

        [Fact]
        public async Task GetSingleRecord_ReturnsMappedCertificate_ForRevokedCert()
        {
            var mock = NewMock();
            mock.Setup(c => c.GetCertificateAsync(MockCertificateData.CertId3, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.RevokedCertRecord());

            var plugin = BuildPlugin(mock.Object);
            var record = await plugin.GetSingleRecord(MockCertificateData.CertId3);

            record.Status.Should().Be((int)EndEntityStatus.REVOKED);
            record.RevocationDate.Should().NotBeNull();
            record.RevocationReason.Should().Be(1); // keyCompromise = 1
        }

        [Fact]
        public async Task GetSingleRecord_Rethrows_WhenCertNotFound()
        {
            var mock = NewMock();
            mock.Setup(c => c.GetCertificateAsync("no-such-id", It.IsAny<CancellationToken>()))
                .ThrowsAsync(new KeyNotFoundException("Certificate 'no-such-id' was not found."));

            var plugin = BuildPlugin(mock.Object);

            Func<Task> act = () => plugin.GetSingleRecord("no-such-id");

            await act.Should().ThrowAsync<KeyNotFoundException>();
        }

        // ---------------------------------------------------------------------------
        // Revoke
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Revoke_CallsRevokeCertificateAsync_AndReturnsRevokedStatus()
        {
            var mock = NewMock();

            // GetCertificateAsync returns an issued cert first
            mock.Setup(c => c.GetCertificateAsync(MockCertificateData.CertId1, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord());

            mock.Setup(c => c.RevokeCertificateAsync(
                    MockCertificateData.CertId1,
                    It.IsAny<RevokeCertificateRequest>(),
                    It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            var plugin = BuildPlugin(mock.Object);
            int resultStatus = await plugin.Revoke(MockCertificateData.CertId1, "0A1B2C3D", revocationReason: 1);

            resultStatus.Should().Be((int)EndEntityStatus.REVOKED);

            mock.Verify(c => c.RevokeCertificateAsync(
                MockCertificateData.CertId1,
                It.Is<RevokeCertificateRequest>(r => r.Reason == "keyCompromise"),
                It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task Revoke_ReturnsAlreadyRevoked_WhenCertAlreadyRevoked()
        {
            var mock = NewMock();
            mock.Setup(c => c.GetCertificateAsync(MockCertificateData.CertId3, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.RevokedCertRecord());

            var plugin = BuildPlugin(mock.Object);
            int resultStatus = await plugin.Revoke(MockCertificateData.CertId3, "AABBCCDD", revocationReason: 0);

            resultStatus.Should().Be((int)EndEntityStatus.REVOKED);

            // Should NOT call RevokeCertificateAsync — cert is already revoked
            mock.Verify(c => c.RevokeCertificateAsync(
                It.IsAny<string>(),
                It.IsAny<RevokeCertificateRequest>(),
                It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Revoke_MapsAllCrlReasonCodes()
        {
            // Spot-check the CRL reason code → string mapping via a revoke call
            var testCases = new[]
            {
                (reason: 0u, expected: "unspecified"),
                (reason: 1u, expected: "keyCompromise"),
                (reason: 2u, expected: "caCompromise"),
                (reason: 3u, expected: "affiliationChanged"),
                (reason: 4u, expected: "superseded"),
                (reason: 5u, expected: "cessationOfOperation"),
            };

            foreach (var (reason, expected) in testCases)
            {
                var mock = NewMock();
                mock.Setup(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(MockCertificateData.IssuedCertRecord());
                mock.Setup(c => c.RevokeCertificateAsync(
                        It.IsAny<string>(),
                        It.Is<RevokeCertificateRequest>(r => r.Reason == expected),
                        It.IsAny<CancellationToken>()))
                    .Returns(Task.CompletedTask);

                var plugin = BuildPlugin(mock.Object);
                await plugin.Revoke(MockCertificateData.CertId1, "serial", reason);

                mock.Verify(c => c.RevokeCertificateAsync(
                    It.IsAny<string>(),
                    It.Is<RevokeCertificateRequest>(r => r.Reason == expected),
                    It.IsAny<CancellationToken>()), Times.Once,
                    $"Expected reason string '{expected}' for CRL code {reason}");
            }
        }

        // ---------------------------------------------------------------------------
        // Synchronize
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Synchronize_FullSync_AddsAllCertsToBuffer()
        {
            var certs = new List<LegacyGetCertificateResponse>
            {
                MockCertificateData.IssuedCertRecord(MockCertificateData.CertId1),
                MockCertificateData.IssuedCertRecord(MockCertificateData.CertId2)
            };

            var mock = NewMock();
            mock.Setup(c => c.ListCertificatesAsync(
                    null,
                    It.IsAny<int>(),
                    It.IsAny<CancellationToken>()))
                .Returns(AsyncEnum(certs));

            var plugin = BuildPlugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);
            var cts = new CancellationTokenSource();

            await plugin.Synchronize(buffer, lastSync: null, fullSync: true, cancelToken: cts.Token);
            buffer.CompleteAdding();

            var results = buffer.ToList();
            results.Should().HaveCount(2);
            results.Select(r => r.CARequestID).Should().Contain(MockCertificateData.CertId1);
            results.Select(r => r.CARequestID).Should().Contain(MockCertificateData.CertId2);
        }

        [Fact]
        public async Task Synchronize_DeltaSync_PassesLastSyncFilter()
        {
            var lastSync = new DateTime(2024, 5, 1, 0, 0, 0, DateTimeKind.Utc);
            var certs = new List<LegacyGetCertificateResponse>
            {
                MockCertificateData.IssuedCertRecord(MockCertificateData.CertId1)
            };

            DateTime? capturedIssuedAfter = null;
            var mock = NewMock();
            mock.Setup(c => c.ListCertificatesAsync(
                    It.IsAny<DateTime?>(),
                    It.IsAny<int>(),
                    It.IsAny<CancellationToken>()))
                .Returns((DateTime? ia, int ps, CancellationToken ct) =>
                {
                    capturedIssuedAfter = ia;
                    return AsyncEnum(certs);
                });

            var plugin = BuildPlugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);

            await plugin.Synchronize(buffer, lastSync: lastSync, fullSync: false, cancelToken: CancellationToken.None);
            buffer.CompleteAdding();

            capturedIssuedAfter.Should().Be(lastSync);
        }

        [Fact]
        public async Task Synchronize_FullSync_PassesNullIssuedAfter()
        {
            DateTime? capturedIssuedAfter = DateTime.MaxValue; // sentinel

            var mock = NewMock();
            mock.Setup(c => c.ListCertificatesAsync(
                    It.IsAny<DateTime?>(),
                    It.IsAny<int>(),
                    It.IsAny<CancellationToken>()))
                .Returns((DateTime? ia, int ps, CancellationToken ct) =>
                {
                    capturedIssuedAfter = ia;
                    return AsyncEnum(new List<LegacyGetCertificateResponse>());
                });

            var plugin = BuildPlugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);

            await plugin.Synchronize(buffer, lastSync: DateTime.UtcNow, fullSync: true, cancelToken: CancellationToken.None);
            buffer.CompleteAdding();

            capturedIssuedAfter.Should().BeNull("full sync should pass null issuedAfter");
        }

        [Fact]
        public async Task Synchronize_SkipsFailedCertificates()
        {
            var certs = new List<LegacyGetCertificateResponse>
            {
                MockCertificateData.IssuedCertRecord(MockCertificateData.CertId1),
                new LegacyGetCertificateResponse
                {
                    Id = "cert-failed",
                    Status = "failed",
                    Certificate = null,
                    ProfileId = MockCertificateData.ProfileIdTls
                }
            };

            var mock = NewMock();
            mock.Setup(c => c.ListCertificatesAsync(
                    It.IsAny<DateTime?>(),
                    It.IsAny<int>(),
                    It.IsAny<CancellationToken>()))
                .Returns(AsyncEnum(certs));

            var plugin = BuildPlugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);

            await plugin.Synchronize(buffer, lastSync: null, fullSync: true, cancelToken: CancellationToken.None);
            buffer.CompleteAdding();

            var results = buffer.ToList();
            results.Should().HaveCount(1);
            results[0].CARequestID.Should().Be(MockCertificateData.CertId1);
        }

        [Fact]
        public async Task Synchronize_HonoursCancellation()
        {
            var cts = new CancellationTokenSource();

            // Make the enumerable check the token mid-iteration
            async IAsyncEnumerable<LegacyGetCertificateResponse> SlowEnum(
                [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
            {
                yield return MockCertificateData.IssuedCertRecord(MockCertificateData.CertId1);
                cts.Cancel();
                ct.ThrowIfCancellationRequested();
                yield return MockCertificateData.IssuedCertRecord(MockCertificateData.CertId2);
            }

            var mock = NewMock();
            mock.Setup(c => c.ListCertificatesAsync(
                    It.IsAny<DateTime?>(),
                    It.IsAny<int>(),
                    It.IsAny<CancellationToken>()))
                .Returns((DateTime? ia, int ps, CancellationToken ct) => SlowEnum(ct));

            var plugin = BuildPlugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);

            Func<Task> act = () =>
                plugin.Synchronize(buffer, lastSync: null, fullSync: true, cancelToken: cts.Token);

            await act.Should().ThrowAsync<OperationCanceledException>();
        }

        [Fact]
        public async Task Synchronize_MapsRevokedCertificates_Correctly()
        {
            var certs = new List<LegacyGetCertificateResponse>
            {
                MockCertificateData.RevokedCertRecord(MockCertificateData.CertId3)
            };

            var mock = NewMock();
            mock.Setup(c => c.ListCertificatesAsync(
                    It.IsAny<DateTime?>(),
                    It.IsAny<int>(),
                    It.IsAny<CancellationToken>()))
                .Returns(AsyncEnum(certs));

            var plugin = BuildPlugin(mock.Object);
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);

            await plugin.Synchronize(buffer, lastSync: null, fullSync: true, cancelToken: CancellationToken.None);
            buffer.CompleteAdding();

            var results = buffer.ToList();
            results.Should().HaveCount(1);
            results[0].Status.Should().Be((int)EndEntityStatus.REVOKED);
            results[0].RevocationDate.Should().NotBeNull();
        }
    }
}
