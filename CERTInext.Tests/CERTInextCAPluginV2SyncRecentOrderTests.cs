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
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Issue 0090: the V2 sync (full or incremental) must not emit a pending or issued order created
    /// within the grace window (default 120 s plus a clock margin), because the gateway would insert
    /// a row with that CARequestID and the in-flight enrollment's own save would then fail on the
    /// unique (CA, CARequestID) index. A held-back issued order is not downloaded either. Revoked
    /// and failed rows and unparseable dates are unaffected.
    ///
    /// Log capture swaps <see cref="LogHandler.Factory"/> (same seam and same non-parallel
    /// collection as <see cref="V2UccNonDnsSanLoggingTests"/>); assertions only consider messages
    /// carrying this test's unique order-id marker, except the summary line, which is checked
    /// positively only.
    /// </summary>
    [Collection("LogHandlerFactory-NoParallel")]
    public class CERTInextCAPluginV2SyncRecentOrderTests
    {
        private static readonly int Margin = Constants.ApiV2.SyncRecentOrderClockMarginSeconds;
        private static readonly int DefaultGrace = Constants.ApiV2.DefaultSyncRecentOrderGraceSeconds;

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
                    => _messages.Enqueue(logLevel + "|" + formatter(state, exception));
            }
        }

        private static string NewId() => "ord_0090_" + Guid.NewGuid().ToString("N");

        private static OrderReportEntryV2 Row(
            string id, string orderStatus, string certificateStatus, string orderDate) =>
            new OrderReportEntryV2
            {
                OrderNumber       = id,
                OrderStatus       = orderStatus,
                CertificateStatus = certificateStatus,
                DomainName        = "example.com",
                ProductCode       = "842",
                OrderDate         = orderDate
            };

        private static string Ago(double seconds) =>
            DateTime.UtcNow.AddSeconds(-seconds).ToString("yyyy-MM-ddTHH:mm:ss'Z'");

        private static async IAsyncEnumerable<OrderReportEntryV2> Rows(params OrderReportEntryV2[] rows)
        {
            foreach (var r in rows) yield return r;
            await Task.CompletedTask;
        }

        private static CERTInextCAPlugin BuildPlugin(ICERTInextClient client, int? graceSeconds = null)
        {
            var config = new CERTInextConfig
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
                PickupRetries     = 0
            };
            if (graceSeconds.HasValue)
                config.SyncRecentOrderGraceSeconds = graceSeconds.Value;

            // A reader that says the gateway already holds a body keeps revoked rows from tripping
            // the bodyless-REVOKED guard, which is not what these tests are about.
            var reader = new Mock<ICertificateDataReader>();
            reader.Setup(r => r.GetExpirationDateByRequestId(It.IsAny<string>())).Returns(DateTime.UtcNow.AddDays(30));
            return new CERTInextCAPlugin(client, config, reader.Object);
        }

        private static Mock<ICERTInextClient> ClientReturning(params OrderReportEntryV2[] rows)
        {
            var mock = new Mock<ICERTInextClient>();
            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(() => Rows(rows));
            return mock;
        }

        /// <summary>Runs a sync with the logger factory swapped; returns emitted records and captured log lines.</summary>
        private static async Task<(AnyCAPluginCertificate[] Records, List<string> Log)> SyncAsync(
            ICERTInextClient client, int? graceSeconds, bool fullSync, string marker)
        {
            var provider = new CapturingLoggerProvider();
            var factory = LoggerFactory.Create(b => b.AddProvider(provider).SetMinimumLevel(LogLevel.Trace));
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);
            try
            {
                LogHandler.Factory = factory;
                var plugin = BuildPlugin(client, graceSeconds); // constructed after the swap
                await plugin.Synchronize(buffer, DateTime.UtcNow.AddHours(-1), fullSync, CancellationToken.None);
            }
            finally
            {
                LogHandler.Factory = Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance;
                factory.Dispose();
            }

            var log = provider.Messages
                .Where(m => m != null && (m.Contains(marker) || m.Contains("V2 synchronization complete")))
                .ToList();
            return (buffer.ToArray(), log);
        }

        // ---------------------------------------------------------------------------
        // Skip / emit decisions through Synchronize
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Incremental_PendingAndRecent_IsNotEmitted_LogsIdAgeAndCountsInSummary()
        {
            string id = NewId();
            var mock = ClientReturning(Row(id, "Order Accepted", "Approved by System", Ago(30)));

            var (records, log) = await SyncAsync(mock.Object, null, fullSync: false, marker: id);

            records.Should().BeEmpty("a pending order created 30 s ago may still be saving in its enrollment");
            log.Should().Contain(m => m.StartsWith("Information|") && m.Contains($"CARequestID={id}")
                                      && m.Contains("AgeSeconds=") && m.Contains($"GraceSeconds={DefaultGrace}"),
                "each hold-back is logged at Info with the order id and its age");
            log.Should().Contain(m => m.Contains("V2 synchronization complete") && m.Contains("RecentOrdersDeferred=1"),
                "the sync summary counts held-back orders");
        }

        [Fact]
        public async Task Incremental_PendingAndOlderThanWindow_IsEmitted()
        {
            string id = NewId();
            var mock = ClientReturning(Row(id, "Order Accepted", "Approved by System", Ago(DefaultGrace + Margin + 30)));

            var (records, log) = await SyncAsync(mock.Object, null, fullSync: false, marker: id);

            records.Should().ContainSingle();
            records[0].CARequestID.Should().Be(id);
            records[0].Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            log.Should().NotContain(m => m.Contains($"CARequestID={id}") && m.Contains("holding back"));
        }

        private static void SetupDownload(Mock<ICERTInextClient> mock, string id) =>
            mock.Setup(c => c.ResolveAndDownloadCertificateV2Async(id, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CertificateDownloadResponse
                {
                    OrderId = id, CertificatePem = MockCertificateData.FakePemCertificate
                });

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task IssuedAndRecent_IsHeldBack_NoDownloadCall(bool fullSync)
        {
            string id = NewId();
            var mock = ClientReturning(Row(id, "Order Fulfilled", "Certificate Downloaded", Ago(10)));
            SetupDownload(mock, id);

            var (records, log) = await SyncAsync(mock.Object, null, fullSync, marker: id);

            records.Should().BeEmpty("an issued order created 10 s ago may still be saving in its enrollment");
            mock.Verify(c => c.ResolveAndDownloadCertificateV2Async(id, It.IsAny<CancellationToken>()), Times.Never,
                "a held-back issued order must not cost a certificate download");
            log.Should().Contain(m => m.StartsWith("Information|") && m.Contains($"CARequestID={id}")
                                      && m.Contains("holding back"));
            log.Should().Contain(m => m.Contains("V2 synchronization complete") && m.Contains("RecentOrdersDeferred=1"));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task IssuedAndOlderThanWindow_IsEmitted_WithCertificate(bool fullSync)
        {
            string id = NewId();
            var mock = ClientReturning(
                Row(id, "Order Fulfilled", "Certificate Downloaded", Ago(DefaultGrace + Margin + 30)));
            SetupDownload(mock, id);

            var (records, _) = await SyncAsync(mock.Object, null, fullSync, marker: id);

            records.Should().ContainSingle();
            records[0].CARequestID.Should().Be(id);
            records[0].Status.Should().Be((int)EndEntityStatus.GENERATED);
            records[0].Certificate.Should().NotBeNullOrEmpty();
            mock.Verify(c => c.ResolveAndDownloadCertificateV2Async(id, It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task Incremental_IssuedFoundViaTrackFallback_AndRecent_IsHeldBack_NoDownloadCall()
        {
            string id = NewId();
            var mock = ClientReturning(Row(id, "Something New", "Also New", Ago(20)));
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(id, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse
                {
                    OrderId = id, Status = "issued", Domain = "example.com"
                }));
            SetupDownload(mock, id);

            var (records, _) = await SyncAsync(mock.Object, null, fullSync: false, marker: id);

            records.Should().BeEmpty();
            mock.Verify(c => c.ResolveAndDownloadCertificateV2Async(id, It.IsAny<CancellationToken>()), Times.Never);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task RevokedAndRecent_IsEmitted(bool fullSync)
        {
            string id = NewId();
            var mock = ClientReturning(Row(id, "Revoked", "Certificate Revoked", Ago(10)));

            var (records, _) = await SyncAsync(mock.Object, null, fullSync, marker: id);

            records.Should().ContainSingle();
            records[0].Status.Should().Be((int)EndEntityStatus.REVOKED);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task FailedAndRecent_IsUnaffected_StillSkippedAsTerminal_NotCountedAsHeldBack(bool fullSync)
        {
            string id = NewId();
            var mock = ClientReturning(Row(id, "Order Cancelled", null, Ago(10)));

            var (records, log) = await SyncAsync(mock.Object, null, fullSync, marker: id);

            records.Should().BeEmpty("a failed/cancelled order is skipped exactly as before");
            log.Should().NotContain(m => m.Contains("RecentOrdersDeferred=1"));
        }

        [Fact]
        public async Task FullSync_PendingAndRecent_IsHeldBack()
        {
            string id = NewId();
            var mock = ClientReturning(Row(id, "Order Accepted", "Approved by System", Ago(5)));

            var (records, log) = await SyncAsync(mock.Object, null, fullSync: true, marker: id);

            records.Should().BeEmpty("a full sync can also race an in-flight enrollment");
            log.Should().Contain(m => m.StartsWith("Information|") && m.Contains($"CARequestID={id}")
                                      && m.Contains("holding back"));
            log.Should().Contain(m => m.Contains("V2 synchronization complete") && m.Contains("RecentOrdersDeferred=1"));
        }

        [Fact]
        public async Task FullSync_PendingAndOlderThanWindow_IsEmitted()
        {
            string id = NewId();
            var mock = ClientReturning(Row(id, "Order Accepted", "Approved by System", Ago(DefaultGrace + Margin + 30)));

            var (records, _) = await SyncAsync(mock.Object, null, fullSync: true, marker: id);

            records.Should().ContainSingle();
            records[0].Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
        }

        [Fact]
        public async Task FullSync_MixedPage_HoldsBackOnlyTheRecentPendingAndIssued()
        {
            string recentPending = NewId(), recentIssued = NewId(), oldPending = NewId(), oldIssued = NewId(), revoked = NewId();
            int old = DefaultGrace + Margin + 60;
            var mock = ClientReturning(
                Row(recentPending, "Order Accepted", "Approved by System", Ago(8)),
                Row(recentIssued, "Order Fulfilled", "Certificate Downloaded", Ago(9)),
                Row(oldPending, "Order Accepted", "Approved by System", Ago(old)),
                Row(oldIssued, "Order Fulfilled", "Certificate Downloaded", Ago(old)),
                Row(revoked, "Revoked", "Certificate Revoked", Ago(8)));
            SetupDownload(mock, recentIssued);
            SetupDownload(mock, oldIssued);

            var (records, _) = await SyncAsync(mock.Object, null, fullSync: true, marker: recentPending);

            records.Select(r => r.CARequestID).Should().BeEquivalentTo(new[] { oldPending, oldIssued, revoked });
            mock.Verify(c => c.ResolveAndDownloadCertificateV2Async(recentIssued, It.IsAny<CancellationToken>()), Times.Never);
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        [InlineData("not-a-date")]
        [InlineData("14/99/2026 25:61")]
        public async Task Incremental_PendingWithMissingOrUnparseableDate_FailsOpen_IsEmitted(string orderDate)
        {
            string id = NewId();
            var mock = ClientReturning(Row(id, "Order Accepted", "Approved by System", orderDate));

            var (records, _) = await SyncAsync(mock.Object, null, fullSync: false, marker: id);

            records.Should().ContainSingle("without a trustworthy order date the row is emitted as before");
            records[0].CARequestID.Should().Be(id);
        }

        [Fact]
        public async Task Incremental_PendingFoundViaTrackFallback_AndRecent_IsNotEmitted()
        {
            string id = NewId();
            // Unrecognised display strings force the live TrackOrder fallback, which says pending.
            var mock = ClientReturning(Row(id, "Something New", "Also New", Ago(20)));
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(id, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse
                {
                    OrderId = id, Status = "pending-approval", Domain = "example.com"
                }));

            var (records, _) = await SyncAsync(mock.Object, null, fullSync: false, marker: id);

            records.Should().BeEmpty();
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task GraceZero_DisablesTheHoldBack_PendingAndIssued(bool fullSync)
        {
            string pending = NewId(), issued = NewId();
            var mock = ClientReturning(
                Row(pending, "Order Accepted", "Approved by System", Ago(5)),
                Row(issued, "Order Fulfilled", "Certificate Downloaded", Ago(5)));
            SetupDownload(mock, issued);

            var (records, _) = await SyncAsync(mock.Object, graceSeconds: 0, fullSync: fullSync, marker: pending);

            records.Select(r => r.CARequestID).Should().BeEquivalentTo(new[] { pending, issued },
                "SyncRecentOrderGraceSeconds=0 restores the old behaviour");
        }

        [Fact]
        public async Task Incremental_GraceConfigured_UsesConfiguredWindow()
        {
            string heldId = NewId();
            string emittedId = NewId();
            // Window = 10 s grace + margin. 5 s old is inside it; 30 s old is outside it (but
            // would be inside the 120 s default, so this proves the setting is honoured).
            var mock = ClientReturning(
                Row(heldId, "Order Accepted", "Approved by System", Ago(5)),
                Row(emittedId, "Order Accepted", "Approved by System", Ago(30)));

            var (records, _) = await SyncAsync(mock.Object, graceSeconds: 10, fullSync: false, marker: heldId);

            records.Select(r => r.CARequestID).Should().Equal(emittedId);
        }

        // ---------------------------------------------------------------------------
        // The decision and config helpers
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData(0, true)]      // order created this instant
        [InlineData(119, true)]
        [InlineData(124, true)]    // inside grace + margin
        [InlineData(126, false)]   // just past grace + margin
        [InlineData(3600, false)]
        [InlineData(-3, true)]     // CA clock slightly ahead, within the margin
        [InlineData(-60, false)]   // CA clock far ahead: untrustworthy, fail open
        public void ShouldDeferRecentOrderV2_Pending_AgeBoundaries(double ageSeconds, bool expectDefer)
        {
            var now = new DateTime(2026, 10, 15, 12, 0, 0, DateTimeKind.Utc);

            bool deferred = CERTInextCAPlugin.ShouldDeferRecentOrderV2(
                (int)EndEntityStatus.EXTERNALVALIDATION, now.AddSeconds(-ageSeconds), now, DefaultGrace, out double age);

            deferred.Should().Be(expectDefer);
            age.Should().BeApproximately(ageSeconds, 0.001);
        }

        [Theory]
        [InlineData(0, true)]      // order created this instant
        [InlineData(119, true)]
        [InlineData(124, true)]    // inside grace + margin
        [InlineData(126, false)]   // just past grace + margin
        [InlineData(3600, false)]
        [InlineData(-3, true)]     // CA clock slightly ahead, within the margin
        [InlineData(-60, false)]   // CA clock far ahead: untrustworthy, fail open
        public void ShouldDeferRecentOrderV2_Issued_AgeBoundaries(double ageSeconds, bool expectDefer)
        {
            var now = new DateTime(2026, 10, 15, 12, 0, 0, DateTimeKind.Utc);

            bool deferred = CERTInextCAPlugin.ShouldDeferRecentOrderV2(
                (int)EndEntityStatus.GENERATED, now.AddSeconds(-ageSeconds), now, DefaultGrace, out double age);

            deferred.Should().Be(expectDefer);
            age.Should().BeApproximately(ageSeconds, 0.001);
        }

        [Fact]
        public void ShouldDeferRecentOrderV2_GraceZero_NeverDeferred()
        {
            var now = new DateTime(2026, 10, 15, 12, 0, 0, DateTimeKind.Utc);

            CERTInextCAPlugin.ShouldDeferRecentOrderV2(
                    (int)EndEntityStatus.EXTERNALVALIDATION, now.AddSeconds(-1), now, 0, out _)
                .Should().BeFalse();
        }

        [Theory]
        [InlineData((int)EndEntityStatus.REVOKED)]
        [InlineData((int)EndEntityStatus.FAILED)]
        public void ShouldDeferRecentOrderV2_RevokedAndFailed_NeverDeferred(int disposition)
        {
            var now = new DateTime(2026, 10, 15, 12, 0, 0, DateTimeKind.Utc);

            CERTInextCAPlugin.ShouldDeferRecentOrderV2(disposition, now.AddSeconds(-1), now, DefaultGrace, out _)
                .Should().BeFalse();
        }

        [Fact]
        public void ShouldDeferRecentOrderV2_NoOrderDate_FailsOpen()
        {
            CERTInextCAPlugin.ShouldDeferRecentOrderV2(
                    (int)EndEntityStatus.EXTERNALVALIDATION, null, DateTime.UtcNow, DefaultGrace, out _)
                .Should().BeFalse();
        }

        [Theory]
        [InlineData(null, 120)]
        [InlineData(120, 120)]
        [InlineData(45, 45)]
        [InlineData(0, 0)]
        [InlineData(-1, 120)]
        public void GetV2RecentOrderGraceSeconds_ZeroDisables_NegativeFallsBackToDefault(int? configured, int expected)
        {
            var config = new CERTInextConfig();
            if (configured.HasValue) config.SyncRecentOrderGraceSeconds = configured.Value;

            CERTInextCAPlugin.GetV2RecentOrderGraceSeconds(config).Should().Be(expected);
        }

        [Fact]
        public void Annotations_SyncRecentOrderGraceSeconds_PresentWithDefault()
        {
            var annotations = CERTInextCAPluginConfig.GetCAConnectorAnnotations();

            annotations.Should().ContainKey(Constants.Config.SyncRecentOrderGraceSeconds);
            annotations[Constants.Config.SyncRecentOrderGraceSeconds].DefaultValue.Should().Be(DefaultGrace);
            annotations[Constants.Config.SyncRecentOrderGraceSeconds].Type.Should().Be("Number");
        }
    }
}
