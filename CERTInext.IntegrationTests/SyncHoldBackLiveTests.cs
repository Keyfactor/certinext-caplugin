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
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.Extensions.CAPlugin.CERTInext.Models;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.OpenSsl;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Live evidence for the issue 0090 sync hold-back (V1): <c>Synchronize</c> must not emit a pending or
    /// issued order younger than <c>SyncRecentOrderGraceSeconds</c> (default 120) plus the clock margin,
    /// and the NEXT INCREMENTAL pass must release it. Each scenario drives the real
    /// <see cref="CERTInextCAPlugin.Synchronize"/> with a real <see cref="BlockingCollection{T}"/> and an
    /// explicit <c>lastSync</c> against the sandbox, and inspects what was emitted for an order the test
    /// itself placed. Calls on the plugin's client are recorded through a pass-through proxy so "no
    /// certificate download for a held order" is verified, not assumed.
    ///
    /// Opt-in: <c>CERTINEXT_SYNC_HOLDBACK=1</c> as a REAL environment variable (places up to 2 sandbox orders;
    /// needs <c>CERTINEXT_DCV_DOMAIN</c>, the base domain for unique per-run test names; no DCV is performed,
    /// the sandbox issues without it). Every order is revoked (or rejected if never issued) afterwards.
    /// Only incremental passes are run: a full-history sync against the shared sandbox account is unbounded
    /// and slow, so the <c>fullSync</c> path stays covered by unit tests only.
    /// Output goes through <see cref="TestOutputScrub"/>; only allow-listed plugin log lines are retained.
    /// </summary>
    public class SyncHoldBackLiveTests : IClassFixture<IntegrationTestFixture>
    {
        private const string OptInFlag = "CERTINEXT_SYNC_HOLDBACK";
        private const string MaxTodayRowsFlag = "CERTINEXT_SYNC_HOLDBACK_MAX_ROWS";
        private const int DefaultMaxTodayRows = 400;

        private static readonly int Grace = Constants.Api.DefaultSyncRecentOrderGraceSeconds;
        private static readonly int Margin = Constants.Api.SyncRecentOrderClockMarginSeconds;

        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;

        public SyncHoldBackLiveTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;
        }

        private void W(string s) => _output.WriteLine(TestOutputScrub.Scrub(s));

        // ---------------------------------------------------------------------------
        // Recording client proxy (pass-through)
        // ---------------------------------------------------------------------------

        internal sealed class ClientCall
        {
            public DateTime At;
            public string Method;
            public string StringArg;   // order id for per-order calls
            public DateTime? DateArg;  // issuedAfter for the listing
        }

        /// <summary>Forwards every <see cref="ICERTInextClient"/> call to the live client and records it.</summary>
        public class RecordingProxy : DispatchProxy
        {
            internal ICERTInextClient Inner;
            internal ConcurrentQueue<ClientCall> Calls;

            protected override object Invoke(MethodInfo targetMethod, object[] args)
            {
                var call = new ClientCall { At = DateTime.UtcNow, Method = targetMethod.Name };
                if (args != null)
                {
                    call.StringArg = args.OfType<string>().FirstOrDefault();
                    if (targetMethod.Name == nameof(ICERTInextClient.ListCertificatesAsync))
                        call.DateArg = args.Length > 0 && args[0] is DateTime d ? d : (DateTime?)null;
                }
                Calls.Enqueue(call);
                try
                {
                    return targetMethod.Invoke(Inner, args);
                }
                catch (TargetInvocationException ex) when (ex.InnerException != null)
                {
                    ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
                    throw;
                }
            }
        }

        // ---------------------------------------------------------------------------
        // Log capture (allow-listed plugin / client lines only)
        // ---------------------------------------------------------------------------

        internal sealed class LogLine
        {
            public DateTime At;
            public LogLevel Level;
            public string Text;
        }

        private sealed class CapturingLogger : ILogger
        {
            public ConcurrentQueue<LogLine> Lines { get; } = new ConcurrentQueue<LogLine>();

            public IDisposable BeginScope<TState>(TState state) => null;
            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
                Func<TState, Exception, string> formatter)
            {
                // Decide from the unformatted template so payload dumps are never even rendered.
                if (!(state is IReadOnlyList<KeyValuePair<string, object>> kvs)) return;
                string fmt = kvs.FirstOrDefault(k => k.Key == "{OriginalFormat}").Value as string ?? string.Empty;
                if (!(fmt.StartsWith("Sync:", StringComparison.Ordinal)
                      || fmt.StartsWith("Starting CERTInext synchronization", StringComparison.Ordinal)
                      || fmt.StartsWith("CERTInext synchronization complete", StringComparison.Ordinal)
                      || fmt.StartsWith("CERTInext API call:", StringComparison.Ordinal)))
                    return;
                string text;
                try { text = formatter(state, exception); } catch { return; }
                Lines.Enqueue(new LogLine { At = DateTime.UtcNow, Level = logLevel, Text = text });
            }
        }

        /// <summary>Routes every category to one capturing logger (the full LoggerFactory package is not referenced here).</summary>
        private sealed class CapturingFactory : ILoggerFactory
        {
            public CapturingLogger Logger { get; } = new CapturingLogger();
            public ILogger CreateLogger(string categoryName) => Logger;
            public void AddProvider(ILoggerProvider provider) { }
            public void Dispose() { }
        }

        // ---------------------------------------------------------------------------
        // Harness: logging swap, recording client, created-order registry
        // ---------------------------------------------------------------------------

        private sealed class Harness : IDisposable
        {
            public CapturingLogger Log;
            public ConcurrentQueue<ClientCall> Calls = new ConcurrentQueue<ClientCall>();
            public ICERTInextClient RecordingClient;
            public List<string> CreatedOrders = new List<string>();

            private ILoggerFactory _factory;
            private IDisposable _clientLoggerOverride;

            public static Harness Create(CERTInextClient liveClient)
            {
                var h = new Harness();
                var factory = new CapturingFactory();
                h.Log = factory.Logger;
                h._factory = factory;
                LogHandler.Factory = h._factory;                       // plugin logger resolves at construction
                h._clientLoggerOverride = CERTInextClient.OverrideLoggerForTests(h._factory.CreateLogger("client"));

                var proxy = DispatchProxy.Create<ICERTInextClient, RecordingProxy>();
                var rp = (RecordingProxy)(object)proxy;
                rp.Inner = liveClient;
                rp.Calls = h.Calls;
                h.RecordingClient = proxy;
                return h;
            }

            public void Dispose()
            {
                _clientLoggerOverride?.Dispose();
                LogHandler.Factory = Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance;
                _factory?.Dispose();
            }
        }

        // ---------------------------------------------------------------------------
        // Live helpers
        // ---------------------------------------------------------------------------

        private CERTInextConfig BuildConfig(int? graceSeconds)
        {
            var c = _fixture.Config;
            var cfg = new CERTInextConfig
            {
                ApiUrl                = c.ApiUrl,
                AuthMode              = c.AuthMode,
                ApiKey                = c.ApiKey,
                AccountNumber         = c.AccountNumber,
                GroupNumber           = c.GroupNumber,
                OrganizationNumber    = c.OrganizationNumber,
                RequestorName         = c.RequestorName,
                RequestorEmail        = c.RequestorEmail,
                RequestorIsdCode      = c.RequestorIsdCode,
                RequestorMobileNumber = c.RequestorMobileNumber,
                SignerPlace           = c.SignerPlace,
                SignerIp              = c.SignerIp,
                DefaultProductCode    = c.DefaultProductCode,
                PageSize              = c.PageSize,
                DcvEnabled            = false,
            };
            if (graceSeconds.HasValue)
                cfg.SyncRecentOrderGraceSeconds = graceSeconds.Value; // otherwise the shipped default is exercised
            return cfg;
        }

        private sealed class Placed
        {
            public string Domain;
            public string OrderNumber;
            public DateTime T0Utc;       // local UTC just before the placement call
            public DateTime TRespUtc;    // local UTC when the placement call (place + TrackOrder) returned
            public DateTime? CaOrderDateUtc;
            public string CaOrderDateRaw;
        }

        private sealed class Probe
        {
            public DateTime AtUtc;
            public int Rows;
            public OrderReportEntry Mine;
            public Dictionary<string, int> StatusCounts = new Dictionary<string, int>();
        }

        private static string DayOf(DateTime utc) => utc.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

        /// <summary>One raw GetOrderReport listing from the UTC day of <paramref name="day"/> (read-only).</summary>
        private async Task<Probe> ProbeAsync(CERTInextClient client, DateTime day, string domain)
        {
            var p = new Probe { AtUtc = DateTime.UtcNow };
            await foreach (var e in client.ListOrdersAsync(orderDateFrom: DayOf(day), pageSize: 100))
            {
                p.Rows++;
                string key = $"{e.CertificateStatusId}/{e.CertificateStatus}";
                p.StatusCounts[key] = p.StatusCounts.TryGetValue(key, out var n) ? n + 1 : 1;
                if (domain != null && string.Equals(e.DomainName, domain, StringComparison.OrdinalIgnoreCase))
                    p.Mine = e;
            }
            return p;
        }

        private static DateTime? ParseCaDate(string raw) =>
            !string.IsNullOrWhiteSpace(raw)
            && DateTime.TryParse(raw, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d)
                ? d : (DateTime?)null;

        private static bool IsCertGenerated(OrderReportEntry e) =>
            e != null && (e.CertificateStatusId == "20" || e.CertificateStatusId == "9");

        private static bool MapsToIssued(OrderReportEntry e) =>
            e != null && StatusMapper.CertificateStatusIdToRequestDisposition(e.CertificateStatusId) == (int)EndEntityStatus.GENERATED;

        /// <summary>Places the order and fills <paramref name="placed"/> (so a concurrent observer can already read Domain).</summary>
        private async Task<Placed> PlaceOrderAsync(CERTInextClient client, Placed placed)
        {
            string domain = placed.Domain;
            string productCode = string.IsNullOrWhiteSpace(_fixture.Config.DefaultProductCode)
                ? Constants.Products.DvSsl : _fixture.Config.DefaultProductCode;
            string csr = KeyAlgorithms.GenerateCsrPem(domain, KeyAlgorithms.For("RSA-2048")); // BouncyCastle
            var req = new EnrollCertificateRequest
            {
                ProfileId     = productCode,
                Csr           = csr,
                ValidityYears = 1,
                Subject       = $"CN={domain}",
                Sans          = new List<SanEntry> { new SanEntry { Type = "dns", Value = domain } },
                Comment       = "Issue 0090 sync hold-back live test (sandbox)."
            };

            placed.T0Utc = DateTime.UtcNow;
            var resp = await client.EnrollCertificateAsync(req);   // GenerateOrderSSL + TrackOrder, as Enroll makes them
            placed.TRespUtc = DateTime.UtcNow;
            Assert.False(string.IsNullOrWhiteSpace(resp.Id), "placement returned no order number");
            Assert.True(placed.OrderNumber == null || placed.OrderNumber == resp.Id,
                "order number seen in the listing during placement differs from the placement response");
            placed.OrderNumber = resp.Id;
            return placed;
        }

        private static string RunId() => DateTime.UtcNow.ToString("MMddHHmmss", CultureInfo.InvariantCulture);

        private string BaseDomainOrSkip()
        {
            IntegrationSkip.IfNotConfigured(_fixture);
            Skip.If(Environment.GetEnvironmentVariable(OptInFlag) != "1",
                $"Opt-in: set {OptInFlag}=1 as a real environment variable (places live sandbox orders).");
            string dcvDomain = Environment.GetEnvironmentVariable("CERTINEXT_DCV_DOMAIN");
            Skip.If(string.IsNullOrWhiteSpace(dcvDomain), "CERTINEXT_DCV_DOMAIN is required (base domain for unique test names).");
            return dcvDomain;
        }

        /// <summary>
        /// A sync pass lists the whole UTC day and refetches every issued row; refuse to start on a day that is
        /// already crowded, so the timed windows are not eaten by foreign rows.
        /// </summary>
        private async Task PreflightAsync(CERTInextClient client)
        {
            var p = await ProbeAsync(client, DateTime.UtcNow, null);
            W($"preflight: {p.Rows} order rows listed for UTC day {DayOf(DateTime.UtcNow)}: " +
              string.Join(", ", p.StatusCounts.OrderByDescending(k => k.Value).Select(k => $"{k.Key} x{k.Value}")));
            int max = int.TryParse(Environment.GetEnvironmentVariable(MaxTodayRowsFlag), out var m) ? m : DefaultMaxTodayRows;
            Assert.True(p.Rows <= max,
                $"{p.Rows} rows already listed today (cap {max}, override with {MaxTodayRowsFlag}); each pass would refetch the issued ones, which would distort the timing windows.");
        }

        // ---------------------------------------------------------------------------
        // Sync pass runner
        // ---------------------------------------------------------------------------

        private sealed class Pass
        {
            public string Name;
            public DateTime StartUtc, EndUtc;
            public DateTime LastSyncUtc;
            public List<DateTime?> IssuedAfterSeen = new List<DateTime?>();
            public List<AnyCAPluginCertificate> Emitted = new List<AnyCAPluginCertificate>();
            public List<LogLine> Log = new List<LogLine>();
            public List<ClientCall> Calls = new List<ClientCall>();
            public string Error;
        }

        private static async Task<Pass> RunPassAsync(string name, CERTInextCAPlugin plugin, Harness h, DateTime lastSyncUtc)
        {
            var pass = new Pass { Name = name, LastSyncUtc = lastSyncUtc, StartUtc = DateTime.UtcNow };
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(boundedCapacity: 10_000);

            var syncTask = Task.Run(async () =>
            {
                try
                {
                    await plugin.Synchronize(buffer, lastSyncUtc, fullSync: false, cancelToken: CancellationToken.None);
                }
                catch (Exception ex)
                {
                    pass.Error = TestOutputScrub.Describe(ex);
                }
                finally
                {
                    if (!buffer.IsAddingCompleted) buffer.CompleteAdding();
                }
            });

            foreach (var rec in buffer.GetConsumingEnumerable())
                pass.Emitted.Add(rec);
            await syncTask;
            pass.EndUtc = DateTime.UtcNow;

            pass.Log = h.Log.Lines.Where(l => l.At >= pass.StartUtc && l.At <= pass.EndUtc.AddMilliseconds(50)).ToList();
            pass.Calls = h.Calls.Where(c => c.At >= pass.StartUtc && c.At <= pass.EndUtc.AddMilliseconds(50)).ToList();
            pass.IssuedAfterSeen = pass.Calls
                .Where(c => c.Method == nameof(ICERTInextClient.ListCertificatesAsync))
                .Select(c => c.DateArg).ToList();
            return pass;
        }

        private static bool Mine(LogLine l, string id) => l.Text.Contains(id);

        private static LogLine HoldLine(Pass p, string id) =>
            p.Log.FirstOrDefault(l => Mine(l, id) && l.Text.StartsWith("Sync: holding back", StringComparison.Ordinal));

        private static LogLine ProcessingLine(Pass p, string id) =>
            p.Log.FirstOrDefault(l => Mine(l, id) && l.Text.StartsWith("Sync: processing order", StringComparison.Ordinal));

        private static LogLine SummaryLine(Pass p) =>
            p.Log.LastOrDefault(l => l.Text.StartsWith("CERTInext synchronization complete", StringComparison.Ordinal));

        private static int SummaryInt(Pass p, string key)
        {
            var m = Regex.Match(SummaryLine(p)?.Text ?? string.Empty, key + @"=(\d+)");
            return m.Success ? int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture) : -1;
        }

        private static string F(double x) => x.ToString("0.0", CultureInfo.InvariantCulture);

        private void Describe(Pass p, Placed o, OrderReportEntry listedBefore)
        {
            string id = o.OrderNumber;
            DateTime? ca = o.CaOrderDateUtc;
            string SinceOrder(DateTime t) => ca.HasValue ? $"t+{F((t - ca.Value).TotalSeconds)}s" : "t+?";
            var proc = ProcessingLine(p, id);
            var hold = HoldLine(p, id);
            string holdAge = hold == null ? "-" : Regex.Match(hold.Text, @"AgeSeconds=([0-9.\-]+)").Groups[1].Value;
            var mine = p.Emitted.Where(r => r.CARequestID == id).ToList();
            var calls = p.Calls.Where(c => c.StringArg == id).Select(c => c.Method).ToList();
            var paths = p.Log.Where(l => l.Text.StartsWith("CERTInext API call:", StringComparison.Ordinal))
                .Select(l => Regex.Match(l.Text, @"Path=(\w+)").Groups[1].Value)
                .GroupBy(x => x).Select(g => $"{g.Key}x{g.Count()}");

            W($"--- pass {p.Name}: start {SinceOrder(p.StartUtc)}, end {SinceOrder(p.EndUtc)} (took {F((p.EndUtc - p.StartUtc).TotalSeconds)}s)");
            W($"    lastSync={p.LastSyncUtc:HH:mm:ss.fff}Z; issuedAfter passed to listing=" +
              $"{string.Join(",", p.IssuedAfterSeen.Select(d => d.HasValue ? d.Value.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") : "null"))}" +
              $" => orderDateFrom={string.Join(",", p.IssuedAfterSeen.Select(d => d.HasValue ? DayOf(d.Value.ToUniversalTime()) : "none"))}");
            W($"    plugin trace for the order: {(proc == null ? "(none)" : TestOutputScrub.Scrub(proc.Text))}");
            W($"    separate listing probe around the pass: {(listedBefore == null ? "(not listed)" : listedBefore.CertificateStatusId + "/" + listedBefore.CertificateStatus)}");
            W($"    order row processed at {(proc == null ? "(not seen in listing)" : SinceOrder(proc.At) + " => age " + F((proc.At - (ca ?? proc.At)).TotalSeconds) + "s")}; " +
              $"hold-back log={(hold == null ? "no" : "yes (AgeSeconds=" + holdAge + ")")}");
            W($"    emitted: total={p.Emitted.Count}, this order={(mine.Count == 0 ? "NO" : "YES x" + mine.Count)}" +
              (mine.Count > 0 ? $" (status={mine[0].Status}, bodyBytes={mine[0].Certificate?.Length ?? 0})" : string.Empty));
            W($"    client calls for this order id during pass: [{string.Join(", ", calls)}]");
            W($"    HTTP paths during pass: {string.Join(", ", paths)}");
            W($"    summary: {TestOutputScrub.Scrub(SummaryLine(p)?.Text ?? "(none)")}");
            if (p.Error != null) W($"    SYNC ERROR: {p.Error}");
        }

        // ---------------------------------------------------------------------------
        // Cleanup
        // ---------------------------------------------------------------------------

        private async Task<string> RejectOrderAsync(CERTInextClient client, string orderNumber)
        {
            var m = typeof(CERTInextClient).GetMethod("BuildMetaAsync", BindingFlags.NonPublic | BindingFlags.Instance)
                ?? throw new InvalidOperationException("BuildMetaAsync not found");
            var metaTask = m.Invoke(client, new object[] { CancellationToken.None }) as Task<RequestMeta>
                ?? throw new InvalidOperationException("BuildMetaAsync returned no task");
            var meta = await metaTask;
            string body = JsonSerializer.Serialize(new
            {
                meta,
                orderDetails = new { orderNumber, rejectRemarks = "sync hold-back live test cleanup" }
            });
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(120) };
            using var resp = await http.PostAsync(_fixture.Config.ApiUrl.TrimEnd('/') + "/" + Constants.Api.RejectOrderPath,
                new StringContent(body, Encoding.UTF8, "application/json"));
            string content = await resp.Content.ReadAsStringAsync();
            try
            {
                using var doc = JsonDocument.Parse(content);
                var metaEl = doc.RootElement.GetProperty("meta");
                string Get(string k) => metaEl.TryGetProperty(k, out var v) ? v.ToString() : "";
                return $"HTTP {(int)resp.StatusCode} status={Get("status")} errorCode={Get("errorCode")} errorMessage={Get("errorMessage")}";
            }
            catch
            {
                return $"HTTP {(int)resp.StatusCode} (unparsed body, {content?.Length ?? 0} chars)";
            }
        }

        /// <summary>Revokes each created order once it is issued (waits up to 90 s), else RejectOrder; then verifies.</summary>
        private async Task CleanupAsync(CERTInextClient client, IReadOnlyList<string> orders)
        {
            W("=== cleanup ===");
            if (orders.Count == 0) { W("no orders created"); return; }
            foreach (var id in orders)
            {
                try
                {
                    int st = 0;
                    var deadline = DateTime.UtcNow.AddSeconds(90);
                    while (true)
                    {
                        var t = await client.TrackOrderAsync(id);
                        int.TryParse(t.OrderDetails?.CertificateStatusId, out st);
                        if (st == Constants.CertificateStatusId.CertificateGenerated
                            || st == Constants.CertificateStatusId.CertificateDownloaded
                            || st == Constants.CertificateStatusId.CertificateRevoked
                            || DateTime.UtcNow >= deadline) break;
                        await Task.Delay(TimeSpan.FromSeconds(4));
                    }

                    if (st == Constants.CertificateStatusId.CertificateRevoked)
                        W($"cleanup {id}: already revoked");
                    else if (st == Constants.CertificateStatusId.CertificateGenerated
                             || st == Constants.CertificateStatusId.CertificateDownloaded)
                    {
                        await client.RevokeCertificateAsync(id, new RevokeCertificateRequest
                        {
                            Reason = Constants.RevocationReason.CessationOfOperation,
                            Comment = "sync hold-back live test cleanup"
                        });
                        W($"cleanup {id}: revoke accepted (was certificateStatusId={st})");
                    }
                    else
                    {
                        W($"cleanup {id}: RejectOrder (was certificateStatusId={st}) -> {await RejectOrderAsync(client, id)}");
                    }
                }
                catch (Exception ex)
                {
                    W($"cleanup {id}: FAILED -> {TestOutputScrub.Describe(ex)}");
                }
                await Task.Delay(TimeSpan.FromSeconds(2));
            }

            await Task.Delay(TimeSpan.FromSeconds(8));
            foreach (var id in orders)
            {
                try
                {
                    var after = await client.TrackOrderAsync(id);
                    W($"verify {id}: orderStatusId={after.OrderDetails?.OrderStatusId} ({after.OrderDetails?.OrderStatus}), " +
                      $"certificateStatusId={after.OrderDetails?.CertificateStatusId} ({after.OrderDetails?.CertificateStatus})");
                }
                catch (Exception ex)
                {
                    W($"verify {id}: TrackOrder failed -> {TestOutputScrub.Describe(ex)}");
                }
            }
        }

        private void ReportSkew(Placed o)
        {
            if (!o.CaOrderDateUtc.HasValue) { W("skew: CA orderDate not available"); return; }
            var ca = o.CaOrderDateUtc.Value;
            // The CA stamps whole seconds (truncated) at some instant in [t0, tResp] on its clock; so
            // caClock - localClock lies in [ca - tResp, ca + 1s - t0].
            W($"skew: CA orderDate raw='{o.CaOrderDateRaw}' (read as UTC); local t0={o.T0Utc:HH:mm:ss.fff}Z, tResp={o.TRespUtc:HH:mm:ss.fff}Z " +
              $"(placement took {F((o.TRespUtc - o.T0Utc).TotalSeconds)}s); caOrderDate - t0 = {F((ca - o.T0Utc).TotalSeconds)}s; " +
              $"caOrderDate - tResp = {F((ca - o.TRespUtc).TotalSeconds)}s; CA-minus-local clock offset bounds " +
              $"[{F((ca - o.TRespUtc).TotalSeconds)}s, {F((ca.AddSeconds(1) - o.T0Utc).TotalSeconds)}s]");
        }

        // ---------------------------------------------------------------------------
        // 1. Control
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task Control_GraceZero_ImmediateIncrementalSync_EmitsTheFreshOrder()
        {
            string baseDomain = BaseDomainOrSkip();
            var client = _fixture.Client;
            await PreflightAsync(client);

            using var h = Harness.Create(client);
            var plugin = new CERTInextCAPlugin(h.RecordingClient, BuildConfig(graceSeconds: 0));
            string domain = $"shbc-{RunId()}.{baseDomain}".ToLowerInvariant();
            var failures = new List<string>();

            try
            {
                var o = await PlaceOrderAsync(client, new Placed { Domain = domain });
                h.CreatedOrders.Add(o.OrderNumber);
                W($"control: order {o.OrderNumber} placed; grace=0");

                var probe = await ProbeAsync(client, o.T0Utc, domain);
                o.CaOrderDateRaw = probe.Mine?.OrderDate;
                o.CaOrderDateUtc = ParseCaDate(o.CaOrderDateRaw);
                ReportSkew(o);

                var pass = await RunPassAsync("control", plugin, h, lastSyncUtc: o.T0Utc.AddSeconds(-60));
                Describe(pass, o, probe.Mine);

                var mine = pass.Emitted.Where(r => r.CARequestID == o.OrderNumber).ToList();
                if (mine.Count != 1) failures.Add($"control: expected the fresh order to be emitted once with grace=0, got {mine.Count}");
                if (HoldLine(pass, o.OrderNumber) != null) failures.Add("control: hold-back log appeared although grace=0");
                if (SummaryInt(pass, "RecentOrderDeferred") != 0) failures.Add($"control: RecentOrderDeferred={SummaryInt(pass, "RecentOrderDeferred")}, expected 0");
                if (pass.Error != null) failures.Add("control: sync error " + pass.Error);
            }
            finally
            {
                await CleanupAsync(client, h.CreatedOrders);
            }

            Assert.True(failures.Count == 0, string.Join(Environment.NewLine, failures));
        }

        // ---------------------------------------------------------------------------
        // 2-5. Hold (pending), hold (issued), release on the next incremental pass
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task HoldBack_PendingThenIssuedAreHeld_AndNextIncrementalPassReleasesTheOrder()
        {
            string baseDomain = BaseDomainOrSkip();
            var client = _fixture.Client;
            await PreflightAsync(client);

            using var h = Harness.Create(client);
            var plugin = new CERTInextCAPlugin(h.RecordingClient, BuildConfig(graceSeconds: null)); // shipped default
            string domain = $"shbh-{RunId()}.{baseDomain}".ToLowerInvariant();
            var failures = new List<string>();
            var timeline = new List<string>();

            try
            {
                var o = new Placed { Domain = domain };
                var lastSync0 = DateTime.UtcNow.AddSeconds(-60);

                // ---- Pass A0: while GenerateOrderSSL is still in flight (the real enrollment race) ----
                // Poll the listing by the unique domain; if the order shows up before the placement call
                // returns and is not yet issued, run an incremental pass right then.
                var placeTask = Task.Run(() => PlaceOrderAsync(client, o));
                Pass passA0 = null;
                OrderReportEntry seenInFlight = null;
                while (!placeTask.IsCompleted)
                {
                    var pr = await ProbeAsync(client, DateTime.UtcNow, domain);
                    if (pr.Mine != null && !string.IsNullOrWhiteSpace(pr.Mine.OrderNumber))
                    {
                        seenInFlight = pr.Mine;
                        break;
                    }
                    await Task.Delay(TimeSpan.FromMilliseconds(500));
                }
                if (seenInFlight != null && !placeTask.IsCompleted && !MapsToIssued(seenInFlight))
                {
                    o.OrderNumber = seenInFlight.OrderNumber;   // verified against the placement response afterwards
                    h.CreatedOrders.Add(o.OrderNumber);
                    passA0 = await RunPassAsync("A0 (pending, placement still in flight)", plugin, h, lastSync0);
                }
                await placeTask;
                string id = o.OrderNumber;
                if (!h.CreatedOrders.Contains(id)) h.CreatedOrders.Add(id);
                W($"hold-back: order {id} placed; grace={Grace}s margin={Margin}s; " +
                  (seenInFlight == null ? "order was NOT visible in the listing before the placement response"
                    : $"order first visible in the listing before the response with status {seenInFlight.CertificateStatusId}/{seenInFlight.CertificateStatus}") +
                  (passA0 == null ? "; pass A0 not run" : "; pass A0 ran during placement"));

                // ---- Pass A: first incremental pass, immediately after the placement response ----
                // (before any other listing call, so the status is whatever the CA shows right now).
                var passA = await RunPassAsync("A (first after response, young)", plugin, h, passA0?.EndUtc ?? lastSync0);

                // Now fetch the CA's orderDate (skew + age math); Describe needs it.
                Probe probe = null;
                for (int i = 0; i < 20; i++)
                {
                    probe = await ProbeAsync(client, o.T0Utc, domain);
                    if (probe.Mine != null) break;
                    await Task.Delay(TimeSpan.FromSeconds(1.5));
                }
                Assert.True(probe?.Mine != null, "order never appeared in the listing within 30 s of placement");
                o.CaOrderDateRaw = probe.Mine.OrderDate;
                o.CaOrderDateUtc = ParseCaDate(o.CaOrderDateRaw);
                Assert.True(o.CaOrderDateUtc.HasValue, "could not parse the CA orderDate");
                var ca = o.CaOrderDateUtc.Value;
                ReportSkew(o);
                if (passA0 != null)
                {
                    Describe(passA0, o, probe.Mine);
                    if (passA0.Emitted.Any(r => r.CARequestID == id)) failures.Add("A0: young order was emitted while placement was in flight");
                    if (HoldLine(passA0, id) == null) failures.Add("A0: no 'holding back recent order' log line for the order");
                    if (SummaryInt(passA0, "RecentOrderDeferred") < 1) failures.Add("A0: sync summary does not count a deferred order");
                    if (passA0.Calls.Any(c => c.StringArg == id)) failures.Add("A0: client was called for the held order");
                    if (passA0.Error != null) failures.Add("A0: sync error " + passA0.Error);
                    var trace0 = ProcessingLine(passA0, id)?.Text ?? string.Empty;
                    W($"    A0 status as the plugin saw it: {(trace0.Contains($"mappedStatus={(int)EndEntityStatus.EXTERNALVALIDATION},") ? "PENDING (EXTERNALVALIDATION)" : "not pending: " + TestOutputScrub.Scrub(trace0))}");
                    timeline.Add($"A0 pass start t+{F((passA0.StartUtc - ca).TotalSeconds)}s  emitted={(passA0.Emitted.Any(r => r.CARequestID == id) ? "yes" : "no")}  (placement response at t+{F((o.TRespUtc - ca).TotalSeconds)}s)");
                }
                Describe(passA, o, probe.Mine);

                if (passA.Emitted.Any(r => r.CARequestID == id)) failures.Add("A: young order was emitted");
                var holdA = HoldLine(passA, id);
                if (holdA == null) failures.Add("A: no 'holding back recent order' log line for the order");
                if (SummaryInt(passA, "RecentOrderDeferred") < 1) failures.Add("A: sync summary does not count a deferred order");
                if (passA.Error != null) failures.Add("A: sync error " + passA.Error);
                if ((passA.StartUtc - ca).TotalSeconds >= Grace + Margin) failures.Add("A: pass started too late to be a young-order test");
                timeline.Add($"A  pass start t+{F((passA.StartUtc - ca).TotalSeconds)}s  emitted={(passA.Emitted.Any(r => r.CARequestID == id) ? "yes" : "no")}");

                // ---- Pass B: issued, still young --------------------------------------------
                Probe probeB = null;
                var waitDeadline = ca.AddSeconds(110);
                while (DateTime.UtcNow < waitDeadline)
                {
                    probeB = await ProbeAsync(client, o.T0Utc, domain);
                    if (IsCertGenerated(probeB.Mine)) break;
                    await Task.Delay(TimeSpan.FromSeconds(3));
                }
                W($"before pass B: listing shows {probeB?.Mine?.CertificateStatusId}/{probeB?.Mine?.CertificateStatus} at t+{F((DateTime.UtcNow - ca).TotalSeconds)}s");
                if (!MapsToIssued(probeB?.Mine))
                    failures.Add("B: order did not reach an issued status in the listing within 110 s; issued-hold not testable");

                var passB = await RunPassAsync("B (issued)", plugin, h, lastSyncUtc: passA.EndUtc);
                Describe(passB, o, probeB?.Mine);

                if (passB.Emitted.Any(r => r.CARequestID == id)) failures.Add("B: young issued order was emitted");
                if (HoldLine(passB, id) == null) failures.Add("B: no 'holding back recent order' log line for the order");
                if (SummaryInt(passB, "RecentOrderDeferred") < 1) failures.Add("B: sync summary does not count a deferred order");
                var downloadCallsB = passB.Calls.Where(c => c.StringArg == id).ToList();
                if (downloadCallsB.Count > 0)
                    failures.Add("B: client was called for the held order: " + string.Join(",", downloadCallsB.Select(c => c.Method)));
                if (passB.Error != null) failures.Add("B: sync error " + passB.Error);
                if ((passB.StartUtc - ca).TotalSeconds >= Grace + Margin)
                    failures.Add($"B: pass started at age {F((passB.StartUtc - ca).TotalSeconds)}s, not under {Grace + Margin}s; hold not exercised");
                timeline.Add($"B  pass start t+{F((passB.StartUtc - ca).TotalSeconds)}s  emitted={(passB.Emitted.Any(r => r.CARequestID == id) ? "yes" : "no")}");

                // ---- Pass C: release on the next incremental pass ----------------------------
                var releaseAt = ca.AddSeconds(135);
                var wait = releaseAt - DateTime.UtcNow;
                if (wait > TimeSpan.Zero) await Task.Delay(wait);
                var probeC = await ProbeAsync(client, o.T0Utc, domain);
                var passC = await RunPassAsync("C (release)", plugin, h, lastSyncUtc: passB.EndUtc);
                Describe(passC, o, probeC.Mine);

                var mineC = passC.Emitted.Where(r => r.CARequestID == id).ToList();
                if (mineC.Count != 1) failures.Add($"C: expected the order to be emitted once on the next incremental pass, got {mineC.Count}");
                else
                {
                    if (mineC[0].Status != (int)EndEntityStatus.GENERATED)
                        failures.Add($"C: emitted with status {mineC[0].Status}, expected GENERATED ({(int)EndEntityStatus.GENERATED})");
                    if (string.IsNullOrWhiteSpace(mineC[0].Certificate))
                        failures.Add("C: emitted without a certificate body");
                    else
                    {
                        try
                        {
                            // The plugin hands the gateway whatever the CA returned: PEM-armored or bare base64 DER.
                            string body = mineC[0].Certificate;
                            bool armored = body.Contains("-----BEGIN");
                            Org.BouncyCastle.X509.X509Certificate cert = armored
                                ? new PemReader(new StringReader(body)).ReadObject() as Org.BouncyCastle.X509.X509Certificate
                                : new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(
                                    Convert.FromBase64String(Regex.Replace(body, @"\s+", string.Empty)));
                            if (cert == null) failures.Add("C: certificate body is not a parseable X.509 certificate");
                            else W($"    C: body parses as X.509 with BouncyCastle (armored={armored}, chars={body.Length}); serial={cert.SerialNumber.ToString(16)}");
                        }
                        catch (Exception ex)
                        {
                            failures.Add("C: certificate body did not parse: " + TestOutputScrub.Describe(ex));
                        }
                    }
                }
                if (HoldLine(passC, id) != null) failures.Add("C: order was still held back after the grace window");
                if (!passC.Calls.Any(c => c.StringArg == id && c.Method == nameof(ICERTInextClient.GetCertificateAsync)))
                    failures.Add("C: no certificate fetch for the released issued order");
                if (passC.Error != null) failures.Add("C: sync error " + passC.Error);
                if (passC.LastSyncUtc != passB.EndUtc) failures.Add("C: lastSync was not the end of the previous pass");
                timeline.Add($"C  pass start t+{F((passC.StartUtc - ca).TotalSeconds)}s  emitted={(mineC.Count > 0 ? "yes" : "no")}");

                W("=== timeline (t = seconds since the CA orderDate) ===");
                foreach (var line in timeline) W(line);
            }
            finally
            {
                await CleanupAsync(client, h.CreatedOrders);
            }

            Assert.True(failures.Count == 0, string.Join(Environment.NewLine, failures));
        }
    }
}
