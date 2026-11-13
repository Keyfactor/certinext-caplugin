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
//
// Opt-in, read-only-by-default sweep over an arbitrary UTC date/time window of the V2 orders
// report (GET /api/certinext/v2/reports/orders). Takes an explicit, caller-supplied window and
// lists every order it finds in it — a general-purpose tool for manually auditing/cleaning up a
// date range after a batch of live-API work (e.g. a day's worth of V2 lifecycle tests).
//
// Env:
//   CERTINEXT_V2_SWEEP_FROM / CERTINEXT_V2_SWEEP_TO — UTC ISO-8601 timestamps, e.g.
//     2026-09-30T00:00:00Z. Both required; the test skips (does not default to any window) if
//     either is unset.
//   CERTINEXT_V2_SWEEP_CANCEL_IDS — optional, comma-separated V2 order IDs. When unset, this
//     test only LISTS orders in the window (orderId, domain, status, productCode, orderDate) —
//     fully read-only. When set, it additionally cancels exactly those IDs, but only if each one
//     is actually found in the listed window and is not already in a terminal state
//     (cancelled/revoked/rejected). No bulk "cancel everything" mode exists here deliberately.
//
// Terminal state is decided by Track Order's own `status` field (via
// CERTInextClient.ResolveAndTrackOrderV2WithFamilyAsync), not the orders report's human-readable
// orderStatus/certificateStatus display strings. Exactly one cancel attempt per id; never
// retried, matching every other cleanup/sweep helper in this project
// (V2FullLifecycleTests.CleanupOrderAsync, etc.).
//
// The V2 orders report only filters by calendar date (YYYY-MM-DD) server-side — this test
// requests the covering date range, then re-applies the caller's precise sub-day window
// client-side against each row's own orderDate.
//
// Gating: requires the CERTINEXT_V2_OPS_TESTS=1 opt-in (listed in
// IntegrationTestFixture._optInOnlyFlags, read from the real process environment before
// V2EnvHelper.LoadAndPromote() runs) — this sweep can cancel real sandbox orders, so it needs an
// explicit go/no-go, shared with the other opt-in V2 ops/diagnostic tests.
//
// Logging: every domain value is passed through CERTInextClient.ApplyLoggingRedaction (same
// default-off PII posture as every other V2 live test in this repo) before being written via
// ITestOutputHelper.
//
// Run (list-only):
//   set -a; . ~/.env_certinext; set +a
//   export CERTINEXT_V2_OPS_TESTS=1
//   export CERTINEXT_V2_SWEEP_FROM=2026-09-25T00:00:00Z
//   export CERTINEXT_V2_SWEEP_TO=2026-10-01T00:00:00Z
//   dotnet test CERTInext.IntegrationTests/CERTInext.IntegrationTests.csproj -c Release -p:DcvSupport=false \
//     --filter "FullyQualifiedName~Sweep_ListRecentOrders_ByWindow" --logger "console;verbosity=detailed"
//
// Add CERTINEXT_V2_SWEEP_CANCEL_IDS=12345,67890 to also cancel those two specific orders (only
// if each is found in the window and is not already terminal).
namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using System.Threading.Tasks;
    using FluentAssertions;
    using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
    using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
    using Xunit;
    using Xunit.Abstractions;

    public class V2OrderWindowSweepTests : IClassFixture<IntegrationTestFixture>
    {
        private const string OptInFlag = "CERTINEXT_V2_OPS_TESTS";

        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;

        private readonly bool _armed;
        private readonly string _v2ApiUrl;
        private readonly string _v2ClientId;
        private readonly string _v2ClientSecret;
        private readonly bool _v2Enabled;

        public V2OrderWindowSweepTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;

            // Read the opt-in flag from the real process environment BEFORE promoting the V2 env
            // file (mirrors PrivatePkiV2LiveTests) — a value left in ~/.env_certinext_v2 must
            // never arm this file. IntegrationTestFixture's own _optInOnlyFlags list already
            // keeps ~/.env_certinext from arming it either.
            _armed = Environment.GetEnvironmentVariable(OptInFlag)?.Trim() == "1";

            var env = V2EnvHelper.LoadAndPromote();
            _v2ApiUrl = V2EnvHelper.GetEnv(env, "CERTINEXT_API_URL");
            _v2ClientId = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_ID");
            _v2ClientSecret = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_SECRET");

            _v2Enabled = !string.IsNullOrWhiteSpace(V2EnvHelper.GetEnv(env, "CERTINEXT_USE_V2_API"))
                         && !string.IsNullOrWhiteSpace(_v2ApiUrl)
                         && !string.IsNullOrWhiteSpace(_v2ClientId)
                         && !string.IsNullOrWhiteSpace(_v2ClientSecret);
        }

        private CERTInextClient BuildV2Client() => new CERTInextClient(new CERTInextConfig
        {
            ApiUrl = _v2ApiUrl,
            UseV2Api = true,
            OAuthClientId = _v2ClientId,
            OAuthClientSecret = _v2ClientSecret,
            RequestorName = _fixture.IsConfigured ? _fixture.Config.RequestorName : "Keyfactor Test",
            RequestorEmail = _fixture.IsConfigured ? _fixture.Config.RequestorEmail : "test@example.com",
            SignerIp = "127.0.0.1",
            SignerPlace = "Gateway Lab",
            PageSize = 100
        });

        /// <summary>
        /// Redacts emails/other personal data before any row reaches ITestOutputHelper — same
        /// default-off PII posture as every other V2 live test in this repo (see
        /// CERTInextClient.ApplyLoggingRedaction; reachable here via
        /// InternalsVisibleTo("CERTInext.IntegrationTests")). Domain names themselves are not
        /// touched by this redaction.
        /// </summary>
        private static string RedactForLog(string value) =>
            CERTInextClient.ApplyLoggingRedaction(value, logSensitiveRequestData: false);

        [SkippableFact]
        public async Task Sweep_ListRecentOrders_ByWindow_DryRun_ThenCancelExplicitIds()
        {
            Skip.If(!_armed,
                $"{OptInFlag}=1 not set in the real process environment — this sweep can cancel real sandbox " +
                "orders when CERTINEXT_V2_SWEEP_CANCEL_IDS is set, and requires an explicit go/no-go. Skipping.");
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            string fromRaw = Environment.GetEnvironmentVariable("CERTINEXT_V2_SWEEP_FROM");
            string toRaw = Environment.GetEnvironmentVariable("CERTINEXT_V2_SWEEP_TO");
            Skip.If(string.IsNullOrWhiteSpace(fromRaw) || string.IsNullOrWhiteSpace(toRaw),
                "CERTINEXT_V2_SWEEP_FROM and CERTINEXT_V2_SWEEP_TO (UTC ISO-8601) must both be set — this sweep " +
                "does not default to any particular window. Skipping.");

            const DateTimeStyles utcStyles = DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal;

            if (!DateTime.TryParse(fromRaw, CultureInfo.InvariantCulture, utcStyles, out DateTime fromUtc))
                throw new ArgumentException($"CERTINEXT_V2_SWEEP_FROM='{fromRaw}' is not a parseable UTC ISO-8601 timestamp.");
            if (!DateTime.TryParse(toRaw, CultureInfo.InvariantCulture, utcStyles, out DateTime toUtc))
                throw new ArgumentException($"CERTINEXT_V2_SWEEP_TO='{toRaw}' is not a parseable UTC ISO-8601 timestamp.");
            if (toUtc <= fromUtc)
                throw new ArgumentException($"CERTINEXT_V2_SWEEP_TO ({toUtc:O}) must be after CERTINEXT_V2_SWEEP_FROM ({fromUtc:O}).");

            var cancelIds = (Environment.GetEnvironmentVariable("CERTINEXT_V2_SWEEP_CANCEL_IDS") ?? string.Empty)
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            // The V2 orders report only filters by calendar date (YYYY-MM-DD) server-side —
            // request the covering date range, then apply the caller's precise sub-day window
            // client-side against each row's own orderDate.
            string apiFrom = fromUtc.Date.ToString("yyyy-MM-dd");
            string apiTo = toUtc.Date.AddDays(1).ToString("yyyy-MM-dd");

            _output.WriteLine("=== V2 order window sweep ===");
            _output.WriteLine($"Window: {fromUtc:O} .. {toUtc:O} (UTC). Report query date range: {apiFrom}..{apiTo}.");
            _output.WriteLine(cancelIds.Count > 0
                ? $"Cancel targets (CERTINEXT_V2_SWEEP_CANCEL_IDS): {string.Join(", ", cancelIds)}"
                : "No CERTINEXT_V2_SWEEP_CANCEL_IDS set — list-only dry run; nothing will be cancelled.");

            using CERTInextClient client = BuildV2Client();

            var rowsInWindow = new List<OrderReportEntryV2>();
            int rowsScanned = 0;

            await foreach (var row in client.ListOrdersV2Async(apiFrom, apiTo, pageSize: 100))
            {
                rowsScanned++;

                bool parsed = DateTime.TryParse(row.OrderDate, CultureInfo.InvariantCulture, utcStyles, out DateTime rowDate);

                // A row with an unparseable/missing orderDate is kept rather than silently
                // dropped — this is a read-only listing, so erring toward showing more (and
                // flagging the parse miss) beats erring toward hiding a row the operator
                // actually wanted to see.
                if (parsed && (rowDate < fromUtc || rowDate > toUtc))
                    continue;

                rowsInWindow.Add(row);

                _output.WriteLine(
                    $"LISTED | OrderId={row.OrderNumber ?? "<none>"} Domain={RedactForLog(row.DomainName)} " +
                    $"Status={row.OrderStatus ?? "<none>"}/{row.CertificateStatus ?? "<none>"} " +
                    $"ProductCode={row.ProductCode ?? "<none>"} OrderDate={row.OrderDate ?? "<none>"}" +
                    (parsed ? string.Empty : " (orderDate unparseable — kept anyway)"));
            }

            _output.WriteLine($"Report rows scanned (date-range query): {rowsScanned}. Rows within the precise window: {rowsInWindow.Count}.");

            bool anyCancelFailed = false;
            var matchedCancelIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (string targetId in cancelIds)
            {
                var row = rowsInWindow.FirstOrDefault(r => string.Equals(r.OrderNumber, targetId, StringComparison.OrdinalIgnoreCase));
                if (row == null)
                {
                    _output.WriteLine(
                        $"SUMMARY | OrderId={targetId} Cancel=SKIPPED (not found in the listed window — " +
                        "not touching an order outside it)");
                    continue;
                }

                matchedCancelIds.Add(targetId);

                try
                {
                    var (family, status) = await client.ResolveAndTrackOrderV2WithFamilyAsync(targetId);

                    bool terminal =
                        string.Equals(status.Status, Constants.ApiV2.StatusCancelled, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(status.Status, Constants.ApiV2.StatusRevoked, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(status.Status, Constants.ApiV2.StatusRejected, StringComparison.OrdinalIgnoreCase);

                    string cancelOutcome;
                    if (terminal)
                    {
                        cancelOutcome = $"SKIPPED (already {status.Status})";
                    }
                    else
                    {
                        try
                        {
                            var outcome = await client.CancelOrderV2Async(
                                family, targetId,
                                "V2 order-window sweep — explicitly listed in CERTINEXT_V2_SWEEP_CANCEL_IDS.");
                            cancelOutcome = outcome.ToString();
                        }
                        catch (Exception cancelEx)
                        {
                            anyCancelFailed = true;
                            cancelOutcome = $"FAILED ({cancelEx.GetType().Name}: {cancelEx.Message})";
                        }
                    }

                    _output.WriteLine(
                        $"SUMMARY | OrderId={targetId} Domain={RedactForLog(row.DomainName)} " +
                        $"StatusBefore={status.Status ?? "<none>"} Cancel={cancelOutcome}");
                }
                catch (Exception ex)
                {
                    anyCancelFailed = true;
                    _output.WriteLine(
                        $"SUMMARY | OrderId={targetId} Domain={RedactForLog(row.DomainName)} " +
                        $"Cancel=FAILED (could not resolve product family/status: {ex.GetType().Name}: {ex.Message})");
                }
            }

            _output.WriteLine("");
            _output.WriteLine(
                $"SUMMARY | Sweep complete. RowsScanned={rowsScanned} RowsInWindow={rowsInWindow.Count} " +
                $"CancelTargets={cancelIds.Count} CancelsMatched={matchedCancelIds.Count}");

            anyCancelFailed.Should().BeFalse(
                "one or more explicitly-listed orders could not be cancelled (or could not have their " +
                "status/family resolved) during the sweep — see the FAILED outcome(s) logged above; this " +
                "sweep does not retry a failed cancel automatically.");
        }
    }
}
