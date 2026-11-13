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
using System.Reflection;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Finding 5: on a DCV-enabled deployment a renewal that is waiting on DNS-01 validation cannot
    /// reach GENERATED inside the synchronous pickup window — the renew path never runs DCV in the
    /// call, only sync-driven DCV does. Pickup (~55s by default) must therefore be skipped for such
    /// a renewal (pending result carrying the new order number), while every renewal that can still
    /// issue promptly keeps the pickup benefit. A failure of the DCV-state check must never fail the
    /// renewal (the order is already placed — issue 0077).
    /// </summary>
    [Collection(LoggingStateCollection.Name)]
    public class RenewalPickupDcvTests
    {
        private const string PriorOrder = "ORD-PRIOR-001";
        private const string NewOrder = "ORD-RENEW-002";
        private const string Domain = "renew.example.com";

        private sealed class CapturingLoggerProvider : ILoggerProvider
        {
            public ConcurrentQueue<(LogLevel Level, string Message)> Entries { get; } = new();
            public ILogger CreateLogger(string categoryName) => new CapturingLogger(Entries);
            public void Dispose() { }

            private sealed class CapturingLogger : ILogger
            {
                private readonly ConcurrentQueue<(LogLevel, string)> _entries;
                public CapturingLogger(ConcurrentQueue<(LogLevel, string)> entries) => _entries = entries;
                public IDisposable BeginScope<TState>(TState state) => null;
                public bool IsEnabled(LogLevel logLevel) => true;
                public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
                    Func<TState, Exception, string> formatter) => _entries.Enqueue((logLevel, formatter(state, exception)));
            }
        }

        // One pickup poll, 1s apart: the smallest real pickup window (InitialDelaySeconds is a
        // fixed 5s), so the "pickup still runs" cases cost ~6s each.
        private static CERTInextConfig Config(bool dcvEnabled = false) => new CERTInextConfig
        {
            PickupRetries = 1,
            PickupDelayInSeconds = 1,
            DcvEnabled = dcvEnabled,
            DcvPropagationDelaySeconds = 1,
            DcvTimeoutMinutes = 1,
            DcvWaitForChallengeSeconds = 0,
            DcvWaitForIssuanceSeconds = 0
        };

        private static Mock<ICertificateDataReader> Reader()
        {
            var reader = new Mock<ICertificateDataReader>();
            reader.Setup(r => r.GetRequestIDBySerialNumber(It.IsAny<string>())).ReturnsAsync(PriorOrder);
            reader.Setup(r => r.GetExpirationDateByRequestId(PriorOrder)).Returns(DateTime.UtcNow.AddDays(30));
            return reader;
        }

        private static Mock<ICERTInextClient> RenewedOrderMock()
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            mock.Setup(c => c.RenewCertificateAsync(PriorOrder, It.IsAny<RenewCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.PendingEnrollResponse(NewOrder));
            return mock;
        }

        private static void SetupPickupIssues(Mock<ICERTInextClient> mock) =>
            mock.Setup(c => c.GetCertificateAsync(NewOrder, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord(NewOrder));

        private static EnrollmentProductInfo ProductInfo() => new EnrollmentProductInfo
        {
            ProductID = MockCertificateData.ProfileIdTls,
            ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ProfileId"] = MockCertificateData.ProfileIdTls,
                ["PriorCertSN"] = "AABB",
                ["RenewalWindowDays"] = "90"
            }
        };

        private static async Task<(EnrollmentResult Result, IReadOnlyList<(LogLevel Level, string Message)> Logs)> RenewAsync(
            Mock<ICERTInextClient> mock, Mock<ICertificateDataReader> reader, CERTInextConfig config, bool withDcvFactory)
        {
            var provider = new CapturingLoggerProvider();
            var factory = LoggerFactory.Create(b => b.AddProvider(provider).SetMinimumLevel(LogLevel.Trace));
            try
            {
                LogHandler.Factory = factory;
                // Constructed after the swap so the plugin's per-instance logger resolves through it.
                CERTInextCAPlugin plugin;
#if SUPPORTS_DCV
                if (withDcvFactory)
                {
                    plugin = new CERTInextCAPlugin(mock.Object, new FakeDomainValidatorFactory(new FakeDomainValidator()), config);
                    // The DCV test constructor takes no certificate-data reader; inject it directly.
                    typeof(CERTInextCAPlugin)
                        .GetField("_certificateDataReader", BindingFlags.Instance | BindingFlags.NonPublic)!
                        .SetValue(plugin, reader.Object);
                }
                else
#endif
                {
                    plugin = new CERTInextCAPlugin(mock.Object, reader.Object, config);
                }

                var result = await plugin.Enroll(
                    MockCertificateData.FakeCsrPem, $"CN={Domain}",
                    new Dictionary<string, string[]> { ["dns"] = new[] { Domain } },
                    ProductInfo(), RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

                // Guard: the renewal API path (not the new-enroll fallback) produced the order.
                reader.Verify(r => r.GetExpirationDateByRequestId(PriorOrder), Times.Once);
                return (result, provider.Entries.ToList());
            }
            finally
            {
                LogHandler.Factory = Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance;
                factory.Dispose();
            }
        }

        [Fact]
        public async Task Renewal_DcvDisabled_PickupStillRuns_AndNeverChecksDcvState()
        {
            var mock = RenewedOrderMock();
            SetupPickupIssues(mock);

            var (result, _) = await RenewAsync(mock, Reader(), Config(dcvEnabled: false), withDcvFactory: false);

            result.CARequestID.Should().Be(NewOrder);
            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            result.Certificate.Should().NotBeNullOrEmpty();
            mock.Verify(c => c.GetCertificateAsync(NewOrder, It.IsAny<CancellationToken>()), Times.Once);
            mock.Verify(c => c.TrackOrderAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

#if SUPPORTS_DCV
        [Fact]
        public async Task Renewal_PendingDnsDcvDomain_SkipsPickup_ReturnsPendingWithNewOrderNumber()
        {
            var mock = RenewedOrderMock();
            mock.Setup(c => c.TrackOrderAsync(NewOrder, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.DcvPendingTrackResponse(NewOrder, Domain));

            var (result, logs) = await RenewAsync(mock, Reader(), Config(dcvEnabled: true), withDcvFactory: true);

            result.CARequestID.Should().Be(NewOrder);
            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            result.Certificate.Should().BeNull();
            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never,
                "an order waiting on DNS-01 cannot issue inside the pickup window");
            logs.Should().Contain(l => l.Level == LogLevel.Information
                    && l.Message.Contains(NewOrder) && l.Message.Contains("pickup skipped"),
                "the skip must be explained at Information");
        }

        [Fact]
        public async Task Renewal_DcvEnabled_NoPendingDcv_PickupStillRuns()
        {
            // Domain validation reused from the prior order: every domain already validated.
            var mock = RenewedOrderMock();
            mock.Setup(c => c.TrackOrderAsync(NewOrder, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.DcvVerifiedTrackResponse(NewOrder, Domain));
            SetupPickupIssues(mock);

            var (result, _) = await RenewAsync(mock, Reader(), Config(dcvEnabled: true), withDcvFactory: true);

            result.CARequestID.Should().Be(NewOrder);
            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            result.Certificate.Should().NotBeNullOrEmpty();
            mock.Verify(c => c.GetCertificateAsync(NewOrder, It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task Renewal_DcvEnabled_NoDomainVerificationBlock_PickupStillRuns()
        {
            // CERTInext has not exposed domainVerification (e.g. OV/EV or not yet materialized):
            // nothing is known to be pending DNS-01, so keep the pickup benefit.
            var track = MockCertificateData.DcvPendingTrackResponse(NewOrder, Domain);
            track.OrderDetails.DomainVerification = null;
            var mock = RenewedOrderMock();
            mock.Setup(c => c.TrackOrderAsync(NewOrder, It.IsAny<CancellationToken>())).ReturnsAsync(track);
            SetupPickupIssues(mock);

            var (result, _) = await RenewAsync(mock, Reader(), Config(dcvEnabled: true), withDcvFactory: true);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            mock.Verify(c => c.GetCertificateAsync(NewOrder, It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task Renewal_DcvEnabled_PendingDomainOnNonDnsMethod_PickupStillRuns()
        {
            // Only DNS-01 is something the sync-DCV path can complete; a domain assigned to HTTP or
            // e-mail validation is out of this check's scope.
            var track = MockCertificateData.DcvPendingTrackResponse(NewOrder, Domain);
            track.OrderDetails.DomainVerification.RawDomainEntries[Domain] = JsonSerializer.SerializeToElement(
                new DomainVerificationDetail
                {
                    DcvMethod = Constants.Dcv.MethodHttpFile,
                    DcvStatus = Constants.Dcv.StatusPending,
                    Status = "1"
                });
            var mock = RenewedOrderMock();
            mock.Setup(c => c.TrackOrderAsync(NewOrder, It.IsAny<CancellationToken>())).ReturnsAsync(track);
            SetupPickupIssues(mock);

            var (result, _) = await RenewAsync(mock, Reader(), Config(dcvEnabled: true), withDcvFactory: true);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            mock.Verify(c => c.GetCertificateAsync(NewOrder, It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task Renewal_DcvEnabled_TerminalOrderWithStalePendingDomain_PickupStillRuns()
        {
            // A cancelled/rejected order can keep a stale dcvStatus="0"; pickup surfaces FAILED
            // quickly, so it must not be skipped (mirrors the terminal guard in PerformDcvIfNeededAsync).
            var track = MockCertificateData.DcvPendingTrackResponse(NewOrder, Domain);
            track.OrderDetails.OrderStatusId = "5";
            var mock = RenewedOrderMock();
            mock.Setup(c => c.TrackOrderAsync(NewOrder, It.IsAny<CancellationToken>())).ReturnsAsync(track);
            mock.Setup(c => c.GetCertificateAsync(NewOrder, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new LegacyGetCertificateResponse { Id = NewOrder, Status = "rejected" });

            var (result, _) = await RenewAsync(mock, Reader(), Config(dcvEnabled: true), withDcvFactory: true);

            result.CARequestID.Should().Be(NewOrder);
            mock.Verify(c => c.GetCertificateAsync(NewOrder, It.IsAny<CancellationToken>()), Times.Once);
        }

        [Theory]
        [InlineData("exception")]
        [InlineData("notfound")]
        [InlineData("canceled")]
        public async Task Renewal_DcvStateCheckThrows_DoesNotThrow_FallsBackToPickup(string kind)
        {
            Exception ex = kind switch
            {
                "notfound" => new KeyNotFoundException($"Order '{NewOrder}' was not found in CERTInext."),
                "canceled" => new TaskCanceledException("The request was canceled due to the configured HttpClient.Timeout"),
                _ => new Exception("CERTInext error during 'track order' (HTTP 500)")
            };
            var mock = RenewedOrderMock();
            mock.Setup(c => c.TrackOrderAsync(NewOrder, It.IsAny<CancellationToken>())).ThrowsAsync(ex);
            SetupPickupIssues(mock);

            var (result, logs) = await RenewAsync(mock, Reader(), Config(dcvEnabled: true), withDcvFactory: true);

            // Falls back to today's behavior: pickup runs and the order is returned, never a throw.
            result.CARequestID.Should().Be(NewOrder);
            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            mock.Verify(c => c.GetCertificateAsync(NewOrder, It.IsAny<CancellationToken>()), Times.Once);
            logs.Should().Contain(l => l.Level == LogLevel.Warning && l.Message.Contains(NewOrder),
                "the swallowed DCV-state check failure must be logged as a Warning naming the order");
        }
#endif
    }
}
