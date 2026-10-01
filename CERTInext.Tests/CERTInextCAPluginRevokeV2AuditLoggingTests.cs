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
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Review finding (A): V2 revoke denials must leave an audit record (CARequestID, product
    /// family, HTTP status, EMS code) even though the denial is surfaced via an exception rather
    /// than a normal return. Pins the plugin-level (<see cref="CERTInextCAPlugin.Revoke"/> →
    /// internal <c>RevokeV2Async</c>) log lines for: 404 (not found/not revokable), 422 ("not in a
    /// revocable state" pre-flight and the general 422 denial), and both outcomes of the
    /// unspecified-reason → cessation-of-operation retry.
    ///
    /// Uses the same <see cref="LogHandler.Factory"/>-swap capture seam as
    /// <c>CERTInextCAPluginAuditLoggingTests</c> (the plugin's <c>_logger</c> is a per-instance
    /// field resolved at construction time, unlike <c>CERTInextClient.Logger</c>, which is
    /// <c>static readonly</c> and not swappable after first use — see that class's remarks for
    /// why client-level V2 log content isn't independently assertable in this harness).
    /// </summary>
    [Collection("LogHandlerFactory-NoParallel")]
    public class CERTInextCAPluginRevokeV2AuditLoggingTests
    {
        private sealed class CapturingLoggerProvider : ILoggerProvider
        {
            public ConcurrentQueue<string> Messages { get; } = new();
            public ILogger CreateLogger(string categoryName) => new CapturingLogger(Messages);
            public void Dispose() { }

            private sealed class CapturingLogger : ILogger
            {
                private readonly ConcurrentQueue<string> _messages;
                public CapturingLogger(ConcurrentQueue<string> messages) => _messages = messages;
                public IDisposable BeginScope<TState>(TState state) => null;
                public bool IsEnabled(LogLevel logLevel) => true;
                public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
                    Func<TState, Exception, string> formatter)
                    => _messages.Enqueue(formatter(state, exception));
            }
        }

        private static CERTInextConfig V2Config() => new CERTInextConfig
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
            PickupRetries     = 0
        };

        /// <summary>
        /// Runs <c>plugin.Revoke(orderId, hexSerial, reason)</c> against a capturing logger
        /// factory and returns every rendered log line plus whatever the call threw (the revoke
        /// is always expected to fail or succeed deterministically per test).
        /// </summary>
        private static async Task<(ConcurrentQueue<string> Messages, Exception Thrown)> CaptureRevokeLogMessagesAsync(
            Mock<ICERTInextClient> mock, string orderId, uint reason)
        {
            var provider = new CapturingLoggerProvider();
            var factory = LoggerFactory.Create(b => b.AddProvider(provider).SetMinimumLevel(LogLevel.Trace));
            Exception thrown = null;
            try
            {
                LogHandler.Factory = factory;
                var plugin = new CERTInextCAPlugin(mock.Object, V2Config());
                try
                {
                    await plugin.Revoke(orderId, "AABBCC", reason);
                }
                catch (Exception ex)
                {
                    thrown = ex;
                }
            }
            finally
            {
                LogHandler.Factory = Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance;
                factory.Dispose();
            }

            return (provider.Messages, thrown);
        }

        private static string FindLine(ConcurrentQueue<string> messages, string marker, params string[] mustContain)
        {
            foreach (var m in messages)
            {
                if (!m.Contains(marker)) continue;
                bool allMatch = true;
                foreach (var s in mustContain)
                {
                    if (!m.Contains(s)) { allMatch = false; break; }
                }
                if (allMatch) return m;
            }
            return null;
        }

        // ---------------------------------------------------------------------------
        // 404 — "not found or not in a revokable state"
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task RevokeV2_404Denial_LogsWarningWithAuditFields()
        {
            string orderId = "audit-404-" + Guid.NewGuid().ToString("N");
            var mock = new Mock<ICERTInextClient>(MockBehavior.Loose);
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(orderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse { OrderId = orderId, Status = "issued" }));
            mock.Setup(c => c.RevokeOrderV2Async(
                    Constants.ApiV2.FamilySsl, orderId, It.IsAny<V2RevokeRequest>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new System.Collections.Generic.KeyNotFoundException(
                    $"V2 order '{orderId}' in family '{Constants.ApiV2.FamilySsl}' not found or not in a revokable state. EMS-913"));

            var (messages, thrown) = await CaptureRevokeLogMessagesAsync(mock, orderId, 4u);

            thrown.Should().BeOfType<InvalidOperationException>();
            string line = FindLine(messages, orderId, "V2 revocation denied", "HttpStatus=404");
            line.Should().NotBeNull("a 404 revoke denial must be audited with an explicit HTTP status");
            line.Should().Contain("EmsCode=EMS-913");
            line.Should().Contain(Constants.ApiV2.FamilySsl);
        }

        // ---------------------------------------------------------------------------
        // Not-GENERATED pre-flight rejection
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task RevokeV2_NotGenerated_LogsErrorWithCurrentStatus()
        {
            string orderId = "audit-notgen-" + Guid.NewGuid().ToString("N");
            var mock = new Mock<ICERTInextClient>(MockBehavior.Loose);
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(orderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse { OrderId = orderId, Status = "pending-dcv" }));

            var (messages, thrown) = await CaptureRevokeLogMessagesAsync(mock, orderId, 4u);

            thrown.Should().NotBeNull();
            thrown.Message.Should().Contain("cannot be revoked");
            string line = FindLine(messages, orderId, "not in a revocable state", "Status=pending-dcv");
            line.Should().NotBeNull("a not-GENERATED revoke rejection must be audited with the current CA status");
            line.Should().Contain(Constants.ApiV2.FamilySsl);

            // RevokeOrderV2Async must never have been called for a certificate that was never issued.
            mock.Verify(c => c.RevokeOrderV2Async(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<V2RevokeRequest>(), It.IsAny<CancellationToken>()),
                Times.Never);
        }

        // ---------------------------------------------------------------------------
        // General 422 denial (not the retry-eligible "Invalid Revoke Reason ID" case)
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task RevokeV2_Generic422Denial_LogsWarningWithAuditFields()
        {
            string orderId = "audit-422-" + Guid.NewGuid().ToString("N");
            var mock = new Mock<ICERTInextClient>(MockBehavior.Loose);
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(orderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse { OrderId = orderId, Status = "issued" }));
            mock.Setup(c => c.RevokeOrderV2Async(
                    Constants.ApiV2.FamilySsl, orderId, It.IsAny<V2RevokeRequest>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new InvalidOperationException("V2 revoke rejected. EMS-969 Revoke reason ID missing"));

            var (messages, thrown) = await CaptureRevokeLogMessagesAsync(mock, orderId, 4u);

            thrown.Should().BeOfType<InvalidOperationException>();
            thrown.Message.Should().Contain("EMS-969");
            string line = FindLine(messages, orderId, "V2 revocation denied", "HttpStatus=422");
            line.Should().NotBeNull("a non-retry-eligible 422 revoke denial must be audited");
            line.Should().Contain("EmsCode=EMS-969");
        }

        // ---------------------------------------------------------------------------
        // Unspecified-reason retry: success and failure outcomes both log.
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task RevokeV2_UnspecifiedReasonRetry_Success_LogsRetriedTrue()
        {
            string orderId = "audit-retry-ok-" + Guid.NewGuid().ToString("N");
            var mock = new Mock<ICERTInextClient>(MockBehavior.Loose);
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(orderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse { OrderId = orderId, Status = "issued" }));
            mock.Setup(c => c.RevokeOrderV2Async(
                    Constants.ApiV2.FamilySsl, orderId, It.IsAny<V2RevokeRequest>(), It.IsAny<CancellationToken>()))
                .Returns((string family, string id, V2RevokeRequest req, CancellationToken ct) =>
                {
                    if (req.Reason == Constants.RevocationReasonV2.Unspecified)
                        throw new InvalidOperationException("V2 revoke rejected. Unprocessable Entity: Invalid Revoke Reason ID");
                    return Task.CompletedTask;
                });

            var (messages, thrown) = await CaptureRevokeLogMessagesAsync(mock, orderId, 0u);

            thrown.Should().BeNull();
            string retryWarn = FindLine(messages, orderId, "retrying once with 'cessation-of-operation'", "HttpStatus=422");
            retryWarn.Should().NotBeNull("the first rejection must be audited before the retry is attempted");
            string completeLine = FindLine(messages, orderId, "V2 revocation complete", "RetriedFromUnspecified=True");
            completeLine.Should().NotBeNull("a successful retry must be reflected in the completion audit line");
        }

        [Fact]
        public async Task RevokeV2_UnspecifiedReasonRetry_Failure_LogsErrorAndRethrows()
        {
            string orderId = "audit-retry-fail-" + Guid.NewGuid().ToString("N");
            var mock = new Mock<ICERTInextClient>(MockBehavior.Loose);
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(orderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse { OrderId = orderId, Status = "issued" }));
            mock.Setup(c => c.RevokeOrderV2Async(
                    Constants.ApiV2.FamilySsl, orderId, It.IsAny<V2RevokeRequest>(), It.IsAny<CancellationToken>()))
                .Returns((string family, string id, V2RevokeRequest req, CancellationToken ct) =>
                {
                    if (req.Reason == Constants.RevocationReasonV2.Unspecified)
                        throw new InvalidOperationException("V2 revoke rejected. Unprocessable Entity: Invalid Revoke Reason ID");
                    throw new InvalidOperationException("V2 revoke rejected. EMS-931 Order not in issued state");
                });

            var (messages, thrown) = await CaptureRevokeLogMessagesAsync(mock, orderId, 0u);

            thrown.Should().BeOfType<InvalidOperationException>();
            thrown.Message.Should().Contain("EMS-931");
            string retryFailLine = FindLine(messages, orderId, "V2 revocation retry (cessation-of-operation) failed");
            retryFailLine.Should().NotBeNull("a failed retry attempt must leave its own audit record, not just surface via the exception");

            // The retry failure must not be misreported as a successful completion.
            FindLine(messages, orderId, "V2 revocation complete").Should().BeNull();
        }
    }
}
