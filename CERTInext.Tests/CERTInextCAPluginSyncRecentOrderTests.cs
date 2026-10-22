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
    /// Issue 0090 (V1): Synchronize, full and incremental, must not emit a pending or issued order
    /// created within the grace window (default 120 s plus a clock margin), because the gateway would
    /// insert a row with that CARequestID and the in-flight enrollment's own save would then fail on
    /// the unique (CA, CARequestID) index. Revoked and failed orders, unparseable dates and a
    /// disabled window are unaffected.
    ///
    /// Log capture swaps <see cref="LogHandler.Factory"/>, so the class is in the non-parallel logging
    /// collection; assertions only consider messages carrying this test's unique order-id marker,
    /// except the summary line.
    /// </summary>
    [Collection(LoggingStateCollection.Name)]
    public class CERTInextCAPluginSyncRecentOrderTests
    {
        private static readonly int Margin = Constants.Api.SyncRecentOrderClockMarginSeconds;
        private static readonly int DefaultGrace = Constants.Api.DefaultSyncRecentOrderGraceSeconds;
        private static readonly DateTime Now = new DateTime(2026, 10, 15, 12, 0, 0, DateTimeKind.Utc);

        private const int Pending = (int)EndEntityStatus.EXTERNALVALIDATION;
        private const int Issued = (int)EndEntityStatus.GENERATED;

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

        /// <summary>A listing row as the V1 order report produces it (no body).</summary>
        private static LegacyGetCertificateResponse Row(string id, string status, double? ageSeconds) =>
            new LegacyGetCertificateResponse
            {
                Id = id,
                Status = status,
                Certificate = null,
                ProfileId = MockCertificateData.ProfileIdTls,
                Subject = "example.com",
                OrderDate = ageSeconds.HasValue ? DateTime.UtcNow.AddSeconds(-ageSeconds.Value) : (DateTime?)null
            };

        private static async IAsyncEnumerable<LegacyGetCertificateResponse> Rows(
            IEnumerable<LegacyGetCertificateResponse> rows)
        {
            foreach (var r in rows)
            {
                await Task.Yield();
                yield return r;
            }
        }

        /// <summary>Strict client mock: any call other than the listing (and setups added by the test) fails.</summary>
        private static Mock<ICERTInextClient> ClientReturning(
            params LegacyGetCertificateResponse[] rows)
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            mock.Setup(c => c.ListCertificatesAsync(
                    It.IsAny<DateTime?>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(() => Rows(rows));
            return mock;
        }

        private static void SetupDownload(Mock<ICERTInextClient> mock, string id) =>
            mock.Setup(c => c.GetCertificateAsync(id, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.IssuedCertRecord(id));

        /// <summary>Runs a sync with the logger factory swapped; returns emitted records and captured log lines.</summary>
        private static async Task<(AnyCAPluginCertificate[] Records, List<string> Log)> SyncAsync(
            ICERTInextClient client, int? graceSeconds, bool fullSync, string marker,
            DateTime? lastSync = null)
        {
            var provider = new CapturingLoggerProvider();
            var factory = LoggerFactory.Create(b => b.AddProvider(provider).SetMinimumLevel(LogLevel.Trace));
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);
            try
            {
                LogHandler.Factory = factory;
                var config = new CERTInextConfig { PickupRetries = 0 };
                if (graceSeconds.HasValue)
                    config.SyncRecentOrderGraceSeconds = graceSeconds.Value;
                // Constructed after the swap so the plugin's per-instance logger resolves through it.
                var plugin = new CERTInextCAPlugin(client, config);
                await plugin.Synchronize(
                    buffer, lastSync ?? DateTime.UtcNow.AddHours(-1), fullSync, CancellationToken.None);
            }
            finally
            {
                LogHandler.Factory = Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance;
                factory.Dispose();
            }

            var log = provider.Messages
                .Where(m => m != null && (m.Contains(marker) || m.Contains("CERTInext synchronization complete")))
                .ToList();
            return (buffer.ToArray(), log);
        }

        // ---------------------------------------------------------------------------
        // Through Synchronize
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task PendingAndRecent_IsNotEmitted_LogsIdAgeAndCountsInSummary(bool fullSync)
        {
            string id = NewId();
            var mock = ClientReturning(Row(id, "pending_approval", ageSeconds: 30));

            var (records, log) = await SyncAsync(mock.Object, null, fullSync, marker: id);

            records.Should().BeEmpty("a pending order created 30 s ago may still be saving in its enrollment");
            log.Should().Contain(m => m.StartsWith("Information|") && m.Contains($"CARequestID={id}")
                                      && m.Contains("AgeSeconds=") && m.Contains($"GraceSeconds={DefaultGrace}"),
                "each hold-back is logged at Info with the order id and its age");
            log.Should().Contain(m => m.Contains("CERTInext synchronization complete") && m.Contains("RecentOrderDeferred=1"),
                "the sync summary counts held-back orders");
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task IssuedAndRecent_IsNotEmitted_AndNothingIsDownloaded(bool fullSync)
        {
            string id = NewId();
            // Strict mock with no GetCertificateAsync setup: any download/track call would throw
            // inside the per-order catch and be counted as an error, so verify it never happens.
            var mock = ClientReturning(Row(id, "issued", ageSeconds: 10));

            var (records, log) = await SyncAsync(mock.Object, null, fullSync, marker: id);

            records.Should().BeEmpty("an issued order created 10 s ago may still be saving in its enrollment");
            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never,
                "a held-back issued order must not trigger a certificate download or track call");
            log.Should().Contain(m => m.StartsWith("Information|") && m.Contains($"CARequestID={id}"));
            log.Should().Contain(m => m.Contains("CERTInext synchronization complete")
                                      && m.Contains("RecentOrderDeferred=1") && m.Contains("Errors=0"));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task PendingAndOlderThanWindow_IsEmitted(bool fullSync)
        {
            string id = NewId();
            var mock = ClientReturning(Row(id, "pending_approval", ageSeconds: DefaultGrace + Margin + 30));

            var (records, log) = await SyncAsync(mock.Object, null, fullSync, marker: id);

            records.Should().ContainSingle();
            records[0].CARequestID.Should().Be(id);
            records[0].Status.Should().Be(Pending);
            log.Should().NotContain(m => m.Contains($"CARequestID={id}") && m.Contains("holding back"));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task IssuedAndOlderThanWindow_IsEmitted_WithBodyFetchedAsBefore(bool fullSync)
        {
            string id = NewId();
            var mock = ClientReturning(Row(id, "issued", ageSeconds: DefaultGrace + Margin + 30));
            SetupDownload(mock, id);

            var (records, _) = await SyncAsync(mock.Object, null, fullSync, marker: id);

            records.Should().ContainSingle();
            records[0].Status.Should().Be(Issued);
            records[0].Certificate.Should().Be(MockCertificateData.FakePemCertificate);
            mock.Verify(c => c.GetCertificateAsync(id, It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task RevokedAndRecent_IsAlwaysEmitted()
        {
            string id = NewId();
            var mock = ClientReturning(Row(id, "revoked", ageSeconds: 5));
            mock.Setup(c => c.GetCertificateAsync(id, It.IsAny<CancellationToken>()))
                .ReturnsAsync(MockCertificateData.RevokedCertRecord(id));

            var (records, log) = await SyncAsync(mock.Object, null, fullSync: false, marker: id);

            records.Should().ContainSingle();
            records[0].Status.Should().Be((int)EndEntityStatus.REVOKED);
            log.Should().NotContain(m => m.Contains($"CARequestID={id}") && m.Contains("holding back"));
        }

        [Fact]
        public async Task FailedAndRecent_IsNotHeldBack_AndKeepsItsExistingSkip()
        {
            string id = NewId();
            var mock = ClientReturning(Row(id, "failed", ageSeconds: 5));

            var (records, log) = await SyncAsync(mock.Object, null, fullSync: false, marker: id);

            records.Should().BeEmpty("a failed order has never been emitted (existing behavior)");
            log.Should().Contain(m => m.Contains("CERTInext synchronization complete")
                                      && m.Contains("Skipped=1") && m.Contains("RecentOrderDeferred=0"),
                "a failed order is skipped as before, not counted as held back");
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task MissingOrderDate_IsEmitted_FailOpen(bool fullSync)
        {
            string id = NewId();
            var mock = ClientReturning(Row(id, "pending_approval", ageSeconds: null));

            var (records, _) = await SyncAsync(mock.Object, null, fullSync, marker: id);

            records.Should().ContainSingle("an unparseable or missing date must not hold an order back");
            records[0].CARequestID.Should().Be(id);
        }

        [Fact]
        public async Task FutureOrderDate_BeyondMargin_IsEmitted_FailOpen()
        {
            string id = NewId();
            var mock = ClientReturning(Row(id, "pending_approval", ageSeconds: -(Margin + 60)));

            var (records, _) = await SyncAsync(mock.Object, null, fullSync: false, marker: id);

            records.Should().ContainSingle("an order dated well in the future means the CA clock is untrustworthy");
        }

        [Fact]
        public async Task ZeroGrace_DisablesTheHold()
        {
            string idPending = NewId();
            string idIssued = NewId();
            var mock = ClientReturning(
                Row(idPending, "pending_approval", ageSeconds: 1),
                Row(idIssued, "issued", ageSeconds: 1));
            SetupDownload(mock, idIssued);

            var (records, log) = await SyncAsync(mock.Object, graceSeconds: 0, fullSync: false, marker: idPending);

            records.Select(r => r.CARequestID).Should().BeEquivalentTo(new[] { idPending, idIssued });
            log.Should().Contain(m => m.Contains("CERTInext synchronization complete") && m.Contains("RecentOrderDeferred=0"));
        }

        [Fact]
        public async Task NegativeGrace_UsesTheDefault()
        {
            string id = NewId();
            var mock = ClientReturning(Row(id, "pending_approval", ageSeconds: 30));

            var (records, _) = await SyncAsync(mock.Object, graceSeconds: -1, fullSync: false, marker: id);

            records.Should().BeEmpty("a negative setting falls back to the 120 s default, under which 30 s is recent");
        }

        [Fact]
        public async Task ConfiguredGrace_IsHonoured()
        {
            string recent = NewId();
            string older = NewId();
            var mock = ClientReturning(
                Row(recent, "pending_approval", ageSeconds: 8),
                Row(older, "pending_approval", ageSeconds: 10 + Margin + 5));

            var (records, _) = await SyncAsync(mock.Object, graceSeconds: 10, fullSync: false, marker: recent);

            records.Select(r => r.CARequestID).Should().BeEquivalentTo(new[] { older },
                "with a 10 s window an order 8 s old is held while one older than 10 s + margin is emitted");
        }

        [Fact]
        public async Task MixedPage_HoldsOnlyTheRecentOnes()
        {
            string idRecentPending = NewId();
            string idRecentIssued = NewId();
            string idOldPending = NewId();
            string idOldIssued = NewId();
            var mock = ClientReturning(
                Row(idRecentPending, "pending_approval", 15),
                Row(idRecentIssued, "issued", 15),
                Row(idOldPending, "pending_approval", 3600),
                Row(idOldIssued, "issued", 3600));
            SetupDownload(mock, idOldIssued);

            var (records, log) = await SyncAsync(mock.Object, null, fullSync: false, marker: idRecentPending);

            records.Select(r => r.CARequestID).Should().BeEquivalentTo(new[] { idOldPending, idOldIssued });
            log.Should().Contain(m => m.Contains("CERTInext synchronization complete") && m.Contains("RecentOrderDeferred=2"));
        }

        // ---------------------------------------------------------------------------
        // Next-pass coverage: the listing filter is day-granular (UTC), so an incremental pass
        // must look back far enough that an order held at the previous pass is still listed.
        // ---------------------------------------------------------------------------

        private static async Task<DateTime?> CapturedIssuedAfterAsync(int? graceSeconds, DateTime lastSync, bool fullSync)
        {
            DateTime? captured = DateTime.MaxValue; // sentinel
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            mock.Setup(c => c.ListCertificatesAsync(
                    It.IsAny<DateTime?>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns((DateTime? ia, int ps, CancellationToken ct) =>
                {
                    captured = ia;
                    return Rows(new List<LegacyGetCertificateResponse>());
                });
            await SyncAsync(mock.Object, graceSeconds, fullSync, marker: "none", lastSync: lastSync);
            return captured;
        }

        [Fact]
        public async Task Incremental_ListingLooksBackByTheHoldWindow_SoAMidnightOrderIsRelisted()
        {
            // Previous pass started 00:00:10 UTC; an order created 23:58:30 the day before was held back there.
            var lastSync = new DateTime(2026, 10, 16, 0, 0, 10, DateTimeKind.Utc);

            var issuedAfter = await CapturedIssuedAfterAsync(graceSeconds: null, lastSync, fullSync: false);

            issuedAfter.Should().NotBeNull();
            issuedAfter.Should().BeBefore(new DateTime(2026, 10, 16, 0, 0, 0, DateTimeKind.Utc),
                "orderDateFrom is the UTC day of issuedAfter, so it must fall on the previous day to relist a 23:58:30 order");
            issuedAfter.Should().BeOnOrBefore(lastSync.AddSeconds(-(DefaultGrace + Margin)));
        }

        [Fact]
        public async Task Incremental_ZeroGrace_PassesLastSyncUnchanged()
        {
            var lastSync = new DateTime(2026, 10, 16, 0, 0, 10, DateTimeKind.Utc);

            var issuedAfter = await CapturedIssuedAfterAsync(graceSeconds: 0, lastSync, fullSync: false);

            issuedAfter.Should().Be(lastSync);
        }

        [Fact]
        public async Task FullSync_PassesNullIssuedAfter_EvenWithTheHoldActive()
        {
            var issuedAfter = await CapturedIssuedAfterAsync(
                graceSeconds: null, new DateTime(2026, 10, 16, 0, 0, 10, DateTimeKind.Utc), fullSync: true);

            issuedAfter.Should().BeNull();
        }

        // ---------------------------------------------------------------------------
        // Pure decision logic and boundaries
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData(Pending, 0, true)]
        [InlineData(Pending, 30, true)]
        [InlineData(Issued, 0, true)]
        [InlineData(Issued, 30, true)]
        [InlineData((int)EndEntityStatus.REVOKED, 30, false)]
        [InlineData((int)EndEntityStatus.FAILED, 30, false)]
        public void Gate_ByDispositionAndAge(int disposition, double ageSeconds, bool expectedHeld)
        {
            CERTInextCAPlugin.ShouldDeferRecentOrder(
                    disposition, Now.AddSeconds(-ageSeconds), Now, DefaultGrace, out _)
                .Should().Be(expectedHeld);
        }

        [Theory]
        [InlineData(Pending)]
        [InlineData(Issued)]
        public void Gate_AgeBoundary_IsExclusiveAtGracePlusMargin(int disposition)
        {
            double limit = DefaultGrace + Margin;

            CERTInextCAPlugin.ShouldDeferRecentOrder(
                disposition, Now.AddSeconds(-(limit - 0.001)), Now, DefaultGrace, out _)
                .Should().BeTrue("just inside the window is still held");
            CERTInextCAPlugin.ShouldDeferRecentOrder(
                disposition, Now.AddSeconds(-limit), Now, DefaultGrace, out _)
                .Should().BeFalse("exactly grace + margin old is emitted");
            CERTInextCAPlugin.ShouldDeferRecentOrder(
                disposition, Now.AddSeconds(-(limit + 0.001)), Now, DefaultGrace, out _)
                .Should().BeFalse();
        }

        [Fact]
        public void Gate_FutureDate_WithinMarginIsHeld_BeyondMarginFailsOpen()
        {
            CERTInextCAPlugin.ShouldDeferRecentOrder(
                Pending, Now.AddSeconds(Margin), Now, DefaultGrace, out double ageAtMargin)
                .Should().BeTrue("dated up to the margin ahead counts as age zero");
            ageAtMargin.Should().BeApproximately(-Margin, 0.0001);

            CERTInextCAPlugin.ShouldDeferRecentOrder(
                Pending, Now.AddSeconds(Margin + 0.001), Now, DefaultGrace, out _)
                .Should().BeFalse("further ahead than the margin is a clock disagreement: emit as today");
        }

        [Fact]
        public void Gate_MissingDate_FailsOpen()
        {
            CERTInextCAPlugin.ShouldDeferRecentOrder(Pending, null, Now, DefaultGrace, out double age)
                .Should().BeFalse();
            age.Should().Be(0);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        public void Gate_NonPositiveGrace_Disables(int grace)
        {
            CERTInextCAPlugin.ShouldDeferRecentOrder(Pending, Now, Now, grace, out _).Should().BeFalse();
        }

        [Theory]
        [InlineData(null, 120)]
        [InlineData(0, 0)]
        [InlineData(45, 45)]
        [InlineData(-1, 120)]
        [InlineData(-9999, 120)]
        public void EffectiveGrace_DefaultZeroNegative(int? configured, int expected)
        {
            var config = new CERTInextConfig();
            if (configured.HasValue) config.SyncRecentOrderGraceSeconds = configured.Value;

            CERTInextCAPlugin.GetSyncRecentOrderGraceSeconds(config).Should().Be(expected);
        }

        [Fact]
        public void Config_DefaultsAndAnnotation()
        {
            new CERTInextConfig().SyncRecentOrderGraceSeconds.Should().Be(120);

            var annotations = CERTInextCAPluginConfig.GetCAConnectorAnnotations();
            annotations.Should().ContainKey(Constants.Config.SyncRecentOrderGraceSeconds);
            annotations[Constants.Config.SyncRecentOrderGraceSeconds].DefaultValue.Should().Be(120);
            annotations[Constants.Config.SyncRecentOrderGraceSeconds].Type.Should().Be("Number");
        }

        [Fact]
        public void IssuedAfter_ShiftsBackByWindowPlusSlack_AndLeavesNullAndDisabledAlone()
        {
            var lastSync = new DateTime(2026, 10, 16, 0, 0, 10, DateTimeKind.Utc);

            CERTInextCAPlugin.GetSyncIssuedAfter(lastSync, 120)
                .Should().Be(lastSync.AddSeconds(-(120 + Margin + Constants.Api.SyncRecentOrderLookbackSlackSeconds)));
            CERTInextCAPlugin.GetSyncIssuedAfter(lastSync, 0).Should().Be(lastSync);
            CERTInextCAPlugin.GetSyncIssuedAfter(null, 120).Should().BeNull();
        }
    }
}
