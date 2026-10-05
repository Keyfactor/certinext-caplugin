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
    /// Issue 0077 (DCV build): the in-call DCV / issuance wait in <c>EnrollNewAsync</c> runs after
    /// the order has been placed. A failure in it (TrackOrder or VerifyDcv error, or the internal
    /// DcvTimeoutMinutes cancellation) used to escape Enroll, failing the enrollment while a paid
    /// order existed at CERTInext. It must now log a Warning naming the order and return the pending
    /// result carrying the order number so the sync-DCV retry path finishes the order.
    /// Only compiled on the <c>-p:DcvSupport=true</c> build (see CERTInext.Tests.csproj).
    /// </summary>
    [Collection(LoggingStateCollection.Name)]
    public class PostPlacementDcvFailureTests
    {
        private const string Order = MockCertificateData.DcvOrderId;
        private const string Domain = MockCertificateData.DcvDomain;

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

        private static CERTInextConfig DcvConfig() => new CERTInextConfig
        {
            DcvEnabled = true,
            DcvPropagationDelaySeconds = 1,
            DcvTimeoutMinutes = 1,
            DcvWaitForChallengeSeconds = 0,
            DcvWaitForIssuanceSeconds = 0,
            PickupRetries = 0
        };

        private static Mock<ICERTInextClient> PlacedOrderMock()
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            mock.Setup(c => c.EnrollCertificateAsync(It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.PendingEnrollResponse(Order));
            return mock;
        }

        private static async Task<(EnrollmentResult Result, IReadOnlyList<(LogLevel Level, string Message)> Logs)> EnrollAsync(
            Mock<ICERTInextClient> mock, FakeDomainValidator validator)
        {
            var provider = new CapturingLoggerProvider();
            var factory = LoggerFactory.Create(b => b.AddProvider(provider).SetMinimumLevel(LogLevel.Trace));
            try
            {
                LogHandler.Factory = factory;
                // Constructed after the swap so the plugin's per-instance logger resolves through it.
                var plugin = new CERTInextCAPlugin(mock.Object, new FakeDomainValidatorFactory(validator), DcvConfig());

                var result = await plugin.Enroll(
                    MockCertificateData.FakeCsrPem, $"CN={Domain}",
                    new Dictionary<string, string[]> { ["dns"] = new[] { Domain } },
                    new EnrollmentProductInfo
                    {
                        ProductID = MockCertificateData.ProfileIdTls,
                        ProductParameters = new Dictionary<string, string> { ["ProfileId"] = MockCertificateData.ProfileIdTls }
                    },
                    RequestFormat.PKCS10, EnrollmentType.New);
                return (result, provider.Entries.ToList());
            }
            finally
            {
                LogHandler.Factory = Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance;
                factory.Dispose();
            }
        }

        private static void AssertPendingWithOrder(EnrollmentResult result, IReadOnlyList<(LogLevel Level, string Message)> logs)
        {
            result.CARequestID.Should().Be(Order);
            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            result.Certificate.Should().BeNull();
            logs.Should().Contain(l => l.Level == LogLevel.Warning && l.Message.Contains(Order) && l.Message.Contains("after order"),
                "the swallowed DCV failure must be logged as a Warning naming the order");
        }

        [Fact]
        public async Task Enroll_DcvTrackOrderThrows_ReturnsPendingWithOrderNumber()
        {
            var mock = PlacedOrderMock();
            mock.Setup(c => c.TrackOrderAsync(Order, It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("CERTInext error during 'track order' (HTTP 500)"));

            var (result, logs) = await EnrollAsync(mock, new FakeDomainValidator());

            AssertPendingWithOrder(result, logs);
        }

        [Fact]
        public async Task Enroll_DcvTrackOrderNotFound_ReturnsPendingWithOrderNumber()
        {
            var mock = PlacedOrderMock();
            mock.Setup(c => c.TrackOrderAsync(Order, It.IsAny<CancellationToken>()))
                .ThrowsAsync(new KeyNotFoundException($"Order '{Order}' was not found in CERTInext."));

            var (result, logs) = await EnrollAsync(mock, new FakeDomainValidator());

            AssertPendingWithOrder(result, logs);
        }

        [Fact]
        public async Task Enroll_DcvVerifyThrows_ReturnsPendingWithOrderNumber_AndCleansUpStagedRecord()
        {
            var mock = PlacedOrderMock();
            mock.Setup(c => c.TrackOrderAsync(Order, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.DcvPendingTrackResponse(Order, Domain));
            mock.Setup(c => c.GetDcvAsync(Order, Domain, Constants.Dcv.MethodDnsTxt, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.DcvTokenResponse());
            mock.Setup(c => c.VerifyDcvAsync(Order, Domain, Constants.Dcv.MethodDnsTxt, It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("VerifyDcv HTTP 503"));
            var validator = new FakeDomainValidator();

            var (result, logs) = await EnrollAsync(mock, validator);

            AssertPendingWithOrder(result, logs);
            validator.StagedRecords.Should().ContainSingle();
            validator.CleanedUpKeys.Should().ContainSingle("the staged TXT record is still removed on failure");
        }

        [Fact]
        public async Task Enroll_DcvTimeoutCancellation_ReturnsPendingWithOrderNumber()
        {
            // Enroll has no caller token: an OperationCanceledException out of the DCV block is the
            // internal DcvTimeoutMinutes token (or a spurious HTTP-timeout TaskCanceledException) and
            // must not fail an enrollment whose order already exists.
            var mock = PlacedOrderMock();
            mock.Setup(c => c.TrackOrderAsync(Order, It.IsAny<CancellationToken>()))
                .ThrowsAsync(new TaskCanceledException("The request was canceled due to the configured HttpClient.Timeout"));

            var (result, logs) = await EnrollAsync(mock, new FakeDomainValidator());

            AssertPendingWithOrder(result, logs);
        }
    }
}
