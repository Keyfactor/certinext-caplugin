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
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Measurement experiment (issue 0090, V2 side): does the V2 API hold order placement open
    /// the way V1 <c>GenerateOrderSSL</c> does in production (response returned 19 s / 100 s after
    /// the order already exists and is issued), and how long is the window between "order visible
    /// to a CA Sync" and "plugin Enroll returns the CARequestID to the gateway"?
    ///
    /// V2 order placement is three calls: POST create (returns orderId, order sits in
    /// <c>pending-csr</c>), PUT /csr, then GET track (+ download / pickup poll).  The plugin's real
    /// <c>Enroll</c> is driven end to end; a <see cref="TimingClientProxy"/> wraps the real client
    /// and timestamps every plugin-to-CA call, so the numbers are the plugin's own call pattern.
    /// Two independent clients run beside it:
    /// <list type="bullet">
    ///   <item>a listing poller (the call Synchronize makes: <c>/reports/orders</c>) every ~1.5 s,
    ///     which finds the order by its unique domain BEFORE the place response returns;</item>
    ///   <item>an order tracker (GET track) every ~1 s, started the instant the place response lands.</item>
    /// </list>
    /// Opt-in: <c>CERTINEXT_V2_LATENCY_EXPERIMENT=1</c> as a REAL environment variable.
    /// Optional: <c>CERTINEXT_V2_LATENCY_COUNT</c> (default 7, max 12),
    /// <c>CERTINEXT_V2_LATENCY_SPACING_SECONDS</c> (default 30),
    /// <c>CERTINEXT_V2_LATENCY_DOMAIN_MODE</c> (<c>unique</c> = fresh subdomain of
    /// CERTINEXT_DCV_DOMAIN per order [default]; <c>reuse</c> = CERTINEXT_DCV_DOMAIN itself).
    /// Credentials come from ~/.env_certinext_v2. Raw CSV goes to <c>experiment-results/</c>.
    /// No order numbers or timings are tied to personal data; emails are never printed.
    /// </summary>
    public class V2PlaceOrderLatencyExperimentTests : IClassFixture<IntegrationTestFixture>
    {
        private const string OptInFlag = "CERTINEXT_V2_LATENCY_EXPERIMENT";
        private const int MaxOrders = 12;
        private static readonly TimeSpan ListPollInterval = TimeSpan.FromSeconds(1.5);
        private static readonly TimeSpan TrackPollInterval = TimeSpan.FromSeconds(1.0);
        private const int MaxListPollsInFlight = 2;

        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;
        private readonly Stopwatch _clock = Stopwatch.StartNew();

        private readonly string _apiUrl;
        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly string _productCode;
        private readonly string _baseDomain;
        private readonly string _requestorName;
        private readonly string _requestorEmail;
        private readonly string _groupNumber;
        private readonly bool _v2Enabled;

        public V2PlaceOrderLatencyExperimentTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;

            var env = V2EnvHelper.LoadAndPromote();
            _apiUrl = V2EnvHelper.GetEnv(env, "CERTINEXT_API_URL");
            _clientId = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_ID");
            _clientSecret = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_SECRET");
            _productCode = V2EnvHelper.GetEnv(env, "CERTINEXT_PRODUCT_CODE", "842");
            _baseDomain = V2EnvHelper.GetEnv(env, "CERTINEXT_DCV_DOMAIN", string.Empty);
            _requestorName = V2EnvHelper.GetEnv(env, "CERTINEXT_REQUESTOR_NAME", "Keyfactor Integration Test");
            _requestorEmail = V2EnvHelper.GetEnv(env, "CERTINEXT_REQUESTOR_EMAIL", "test@example.com");
            _groupNumber = V2EnvHelper.GetEnv(env, "CERTINEXT_GROUP_NUMBER", string.Empty);
            _v2Enabled = !string.IsNullOrWhiteSpace(V2EnvHelper.GetEnv(env, "CERTINEXT_USE_V2_API"))
                         && !string.IsNullOrWhiteSpace(_apiUrl)
                         && !string.IsNullOrWhiteSpace(_clientId)
                         && !string.IsNullOrWhiteSpace(_clientSecret);
        }

        private double Now => _clock.Elapsed.TotalSeconds;

        private static readonly Regex EmailRx = new(@"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", RegexOptions.Compiled);

        /// <summary>Strips anything email-shaped and caps length; used for every line that leaves the test.</summary>
        private static string Scrub(string s)
        {
            if (string.IsNullOrEmpty(s)) return s ?? string.Empty;
            s = EmailRx.Replace(s, "<email>");
            return s.Length > 400 ? s.Substring(0, 400) + "..." : s;
        }

        private static string Describe(Exception ex) => Scrub($"{ex.GetType().Name}: {ex.Message}");

        private void W(string s) => _output.WriteLine(Scrub(s));

        // ---------------------------------------------------------------------------
        // Timing proxy: wraps the real client, timestamps every plugin-to-CA call
        // ---------------------------------------------------------------------------

        public sealed class CallRecord
        {
            public string Name;
            public double Start;
            public double End;
            public string Error;
            public double DurationMs => (End - Start) * 1000.0;
        }

        /// <summary>DispatchProxy over <see cref="ICERTInextClient"/> recording start/end of every async call.</summary>
        public class TimingClientProxy : DispatchProxy
        {
            internal ICERTInextClient Inner;
            internal Func<double> Clock;
            internal ConcurrentQueue<CallRecord> Calls = new();
            internal Action<string, object> OnResult;

            protected override object Invoke(MethodInfo targetMethod, object[] args)
            {
                double start = Clock();
                object ret;
                try
                {
                    ret = targetMethod.Invoke(Inner, args);
                }
                catch (TargetInvocationException tie)
                {
                    Calls.Enqueue(new CallRecord { Name = targetMethod.Name, Start = start, End = Clock(), Error = Describe(tie.InnerException ?? tie) });
                    throw tie.InnerException ?? tie;
                }

                if (ret is Task t)
                {
                    Type rt = targetMethod.ReturnType;
                    if (rt.IsGenericType && rt.GetGenericTypeDefinition() == typeof(Task<>))
                    {
                        var m = typeof(TimingClientProxy).GetMethod(nameof(WrapTaskT), BindingFlags.NonPublic | BindingFlags.Instance)
                            ?.MakeGenericMethod(rt.GetGenericArguments()[0]);
                        return m?.Invoke(this, new object[] { t, targetMethod.Name, start });
                    }
                    return WrapTask(t, targetMethod.Name, start);
                }
                return ret; // sync members and IAsyncEnumerable pass straight through, untimed
            }

            private async Task WrapTask(Task t, string name, double start)
            {
                try { await t.ConfigureAwait(false); Calls.Enqueue(new CallRecord { Name = name, Start = start, End = Clock() }); }
                catch (Exception ex) { Calls.Enqueue(new CallRecord { Name = name, Start = start, End = Clock(), Error = Describe(ex) }); throw; }
            }

            private async Task<T> WrapTaskT<T>(Task<T> t, string name, double start)
            {
                try
                {
                    T r = await t.ConfigureAwait(false);
                    Calls.Enqueue(new CallRecord { Name = name, Start = start, End = Clock() });
                    OnResult?.Invoke(name, r);
                    return r;
                }
                catch (Exception ex)
                {
                    Calls.Enqueue(new CallRecord { Name = name, Start = start, End = Clock(), Error = Describe(ex) });
                    throw;
                }
            }
        }

        // ---------------------------------------------------------------------------
        // Observations
        // ---------------------------------------------------------------------------

        private sealed class TrackObs
        {
            public double Sent;
            public double Recv;
            public string Status;
            public string Error;
        }

        private sealed class ListObs
        {
            public double Start;
            public double End;
            public int Rows;
            public string OrderNumber;
            public string OrderStatus;
            public string CertStatus;
            public string Error;
            public bool Matched => OrderNumber != null;
            public string Combined => $"{OrderStatus}|{CertStatus}";
        }

        private sealed class Trial
        {
            public int Index;
            public string Domain;
            public string OrderId;
            public DateTime T0Utc;
            public double T0;
            public double TPlaceResp = double.NaN;
            public double TCsrResp = double.NaN;
            public double TEnrollEnd = double.NaN;
            public double PlaceMs = double.NaN, CsrMs = double.NaN, DownloadMs = double.NaN;
            public List<double> TrackCallMs = new();
            public string EnrollStatus = string.Empty;
            public bool EnrollHasCert;
            public string EnrollMessage = string.Empty;
            public string CreateRespStatus = string.Empty;
            public double FirstSeenList = double.NaN, FirstSeenListLower = double.NaN;
            public string FirstSeenListStatus = string.Empty;
            public double TrackFirstObsRecv = double.NaN;
            public string TrackFirstObsStatus = string.Empty;
            public string StatusAfterCsr = string.Empty;
            public double TIssuedTrack = double.NaN, TIssuedTrackLower = double.NaN;
            public double TIssuedList = double.NaN;
            public string TrackSeq = string.Empty;
            public string ListSeq = string.Empty;
            public int ListPolls, ListErrors, TrackPolls, TrackErrors;
            public double ListPollMedianS = double.NaN;
            public string CleanupNote = string.Empty;
            public string Error = string.Empty;
            // One extra GET /certificate fired by the tracker the first time track reports 'issued'
            // (while the CSR PUT may still be in flight): does 'issued' mean the cert is downloadable?
            public double DlProbeAt = double.NaN, DlProbeMs = double.NaN;
            public string DlProbeResult = string.Empty;
        }

        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

        private static string F(double x) => double.IsNaN(x) ? "" : x.ToString("0.00", CultureInfo.InvariantCulture);

        private static double Median(IEnumerable<double> xs)
        {
            var a = xs.Where(x => !double.IsNaN(x)).OrderBy(x => x).ToArray();
            if (a.Length == 0) return double.NaN;
            return a.Length % 2 == 1 ? a[a.Length / 2] : (a[a.Length / 2 - 1] + a[a.Length / 2]) / 2.0;
        }

        private static string RepoRoot()
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir != null && !File.Exists(Path.Combine(dir.FullName, "certinext-caplugin.sln")))
                dir = dir.Parent;
            return dir?.FullName ?? Directory.GetCurrentDirectory();
        }

        /// <summary>RSA-2048 PKCS#10 CSR, BouncyCastle only.</summary>
        private static string GenerateCsrPem(string commonName)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            var keyPair = keyGen.GenerateKeyPair();
            var csr = new Pkcs10CertificationRequest("SHA256withRSA", new X509Name($"CN={commonName}"),
                keyPair.Public, null, keyPair.Private);
            return "-----BEGIN CERTIFICATE REQUEST-----\n"
                + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                + "\n-----END CERTIFICATE REQUEST-----";
        }

        private CERTInextConfig BuildConfig() => new CERTInextConfig
        {
            ApiUrl = _apiUrl,
            UseV2Api = true,
            OAuthClientId = _clientId,
            OAuthClientSecret = _clientSecret,
            RequestorName = _requestorName,
            RequestorEmail = _requestorEmail,
            RequestorIsdCode = "1",
            RequestorMobileNumber = "0000000000",
            SignerPlace = "Gateway Lab",
            SignerIp = "127.0.0.1",
            GroupNumber = _groupNumber,
            PageSize = 100,
            DcvEnabled = false
        };

        private static bool IsIssuedListing(ListObs o) =>
            o.CertStatus != null &&
            (o.CertStatus.IndexOf("Generated", StringComparison.OrdinalIgnoreCase) >= 0
             || o.CertStatus.IndexOf("Downloaded", StringComparison.OrdinalIgnoreCase) >= 0);

        private static bool IsIssuedTrack(string status) =>
            string.Equals(status, Constants.ApiV2.StatusIssued, StringComparison.OrdinalIgnoreCase);

        // ---------------------------------------------------------------------------
        // The experiment
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task V2PlaceOrder_Latency_And_ExposureWindow_Experiment()
        {
            Skip.If(!_v2Enabled, "V2 credentials not configured in ~/.env_certinext_v2 (CERTINEXT_USE_V2_API, API_URL, CLIENT_ID, CLIENT_SECRET).");
            Skip.If(Environment.GetEnvironmentVariable(OptInFlag) != "1",
                $"Opt-in: set {OptInFlag}=1 as a real environment variable (places live sandbox orders).");
            Skip.If(string.IsNullOrWhiteSpace(_baseDomain), "CERTINEXT_DCV_DOMAIN is required (base domain for test CNs).");

            int count = int.TryParse(Environment.GetEnvironmentVariable("CERTINEXT_V2_LATENCY_COUNT"), out int c) ? c : 7;
            count = Math.Max(1, Math.Min(MaxOrders, count));
            double spacing = double.TryParse(Environment.GetEnvironmentVariable("CERTINEXT_V2_LATENCY_SPACING_SECONDS"),
                NumberStyles.Float, CultureInfo.InvariantCulture, out double sp) ? sp : 30;
            bool reuse = string.Equals(Environment.GetEnvironmentVariable("CERTINEXT_V2_LATENCY_DOMAIN_MODE"),
                "reuse", StringComparison.OrdinalIgnoreCase);

            string runId = DateTime.UtcNow.ToString("MMddHHmm", CultureInfo.InvariantCulture);
            var cfg = BuildConfig();

            // Independent clients: listing poller (stands in for the sync pod) and order tracker.
            using var listClient = new CERTInextClient(cfg);
            using var trackClient = new CERTInextClient(cfg);
            using var realClient = new CERTInextClient(cfg);
            using var cleanupClient = new CERTInextClient(cfg);
            var cleanupPlugin = new CERTInextCAPlugin(cleanupClient, cfg);

            W($"V2 latency experiment run {runId}: product={_productCode}, mode={(reuse ? "reuse" : "unique")}, " +
              $"count={count}, spacingS={F(spacing)}, pickupRetries={cfg.GetEffectivePickupRetries()}");

            var trials = new List<Trial>();
            double lastT0 = double.NegativeInfinity;
            try
            {
                for (int i = 0; i < count; i++)
                {
                    var t = new Trial
                    {
                        Index = i + 1,
                        Domain = reuse ? _baseDomain : $"v2lat-{runId}-{i + 1:D2}.{_baseDomain}".ToLowerInvariant()
                    };
                    trials.Add(t);

                    double wait = lastT0 + spacing - Now;
                    if (wait > 0) await Task.Delay(TimeSpan.FromSeconds(wait));

                    try
                    {
                        await RunTrialAsync(t, cfg, realClient, listClient, trackClient, reuse);
                        lastT0 = t.T0;
                    }
                    catch (Exception ex)
                    {
                        t.Error = (t.Error.Length > 0 ? t.Error + "; " : "") + "trial: " + Describe(ex);
                        lastT0 = t.T0 > 0 ? t.T0 : Now;
                    }
                    finally
                    {
                        t.CleanupNote = await CleanupAsync(cleanupPlugin, t.OrderId);
                    }
                    LogTrial(t);
                }
            }
            finally
            {
                WriteCsv(runId, trials);
                WriteSummary(trials);
            }
        }

        private async Task RunTrialAsync(Trial t, CERTInextConfig cfg, CERTInextClient realClient,
            CERTInextClient listClient, CERTInextClient trackClient, bool reuse)
        {
            // Everything not under test happens before t0.
            string csr = GenerateCsrPem(t.Domain);
            string today = DateTime.UtcNow.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            string tomorrow = DateTime.UtcNow.AddDays(1).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

            // reuse mode: orders already on the base domain today are excluded from "mine".
            var snapshot = new HashSet<string>(StringComparer.Ordinal);
            if (reuse)
            {
                await foreach (var e in listClient.ListOrdersV2Async(today, tomorrow, 100))
                    if (string.Equals(e.DomainName, t.Domain, StringComparison.OrdinalIgnoreCase) && e.OrderNumber != null)
                        snapshot.Add(e.OrderNumber);
            }
            bool Mine(OrderReportEntryV2 e) =>
                string.Equals(e.DomainName, t.Domain, StringComparison.OrdinalIgnoreCase)
                && e.OrderNumber != null && !snapshot.Contains(e.OrderNumber);

            var proxy = DispatchProxy.Create<ICERTInextClient, TimingClientProxy>();
            var tp = (TimingClientProxy)(object)proxy;
            tp.Inner = realClient;
            tp.Clock = () => Now;

            var trackObs = new ConcurrentQueue<TrackObs>();
            var listObs = new ConcurrentQueue<ListObs>();
            using var stopAll = new CancellationTokenSource();
            Task trackerTask = Task.CompletedTask;
            string orderIdFromCreate = null;

            // The instant the place response lands, start tracking the order with the independent client.
            tp.OnResult = (name, result) =>
            {
                if (name == "PlaceOrderV2Async" && result is V2CreateOrderResponse cr && orderIdFromCreate == null)
                {
                    orderIdFromCreate = cr.OrderId;
                    t.CreateRespStatus = cr.Status ?? string.Empty;
                    trackerTask = Task.Run(async () =>
                    {
                        while (!stopAll.IsCancellationRequested)
                        {
                            var o = new TrackObs { Sent = Now };
                            try
                            {
                                var s = await trackClient.TrackOrderV2Async(Constants.ApiV2.FamilySsl, cr.OrderId);
                                o.Status = s.Status;
                            }
                            catch (Exception ex) { o.Error = Describe(ex); }
                            o.Recv = Now;
                            trackObs.Enqueue(o);
                            if (o.Error == null && IsIssuedTrack(o.Status) && double.IsNaN(t.DlProbeAt))
                            {
                                t.DlProbeAt = Now;
                                double p0 = Now;
                                try
                                {
                                    var dl = await trackClient.DownloadCertificateV2Async(Constants.ApiV2.FamilySsl, cr.OrderId);
                                    t.DlProbeResult = string.IsNullOrWhiteSpace(dl?.CertificatePem) ? "ok-empty" : "ok-with-certificate";
                                }
                                catch (Exception ex) { t.DlProbeResult = "error: " + Describe(ex); }
                                t.DlProbeMs = (Now - p0) * 1000.0;
                            }
                            try { await Task.Delay(TrackPollInterval, stopAll.Token); } catch (OperationCanceledException) { }
                        }
                    });
                }
            };

            var inflight = new List<Task>();
            var listerTask = Task.Run(async () =>
            {
                async Task PollOnce()
                {
                    var o = new ListObs { Start = Now };
                    try
                    {
                        await foreach (var e in listClient.ListOrdersV2Async(today, tomorrow, 100))
                        {
                            o.Rows++;
                            if (Mine(e) && o.OrderNumber == null)
                            {
                                o.OrderNumber = e.OrderNumber;
                                o.OrderStatus = e.OrderStatus;
                                o.CertStatus = e.CertificateStatus;
                            }
                        }
                    }
                    catch (Exception ex) { o.Error = Describe(ex); }
                    o.End = Now;
                    listObs.Enqueue(o);
                }
                while (!stopAll.IsCancellationRequested)
                {
                    inflight.RemoveAll(x => x.IsCompleted);
                    if (inflight.Count < MaxListPollsInFlight) inflight.Add(Task.Run(PollOnce));
                    try { await Task.Delay(ListPollInterval, stopAll.Token); } catch (OperationCanceledException) { }
                }
                await Task.WhenAll(inflight);
            });
            await Task.Delay(ListPollInterval); // listing poller is already running before t0

            var plugin = new CERTInextCAPlugin(proxy, cfg);
            var productInfo = new EnrollmentProductInfo
            {
                ProductID = _productCode,
                ProductParameters = new Dictionary<string, string>
                {
                    [Constants.EnrollmentParam.ProductCode] = _productCode,
                    [Constants.EnrollmentParam.ProfileId] = _productCode,
                }
            };

            t.T0Utc = DateTime.UtcNow;
            t.T0 = Now;
            EnrollmentResult result = null;
            try
            {
                result = await plugin.Enroll(
                    csr: csr,
                    subject: $"CN={t.Domain}",
                    san: new Dictionary<string, string[]> { ["dns"] = new[] { t.Domain } },
                    productInfo: productInfo,
                    requestFormat: RequestFormat.PKCS10,
                    enrollmentType: EnrollmentType.New);
            }
            catch (Exception ex)
            {
                t.Error = "Enroll: " + Describe(ex);
            }
            t.TEnrollEnd = Now;
            t.OrderId = result?.CARequestID ?? orderIdFromCreate;
            if (result != null)
            {
                t.EnrollStatus = ((EndEntityStatus)result.Status).ToString();
                t.EnrollHasCert = !string.IsNullOrWhiteSpace(result.Certificate);
                t.EnrollMessage = Scrub(result.StatusMessage ?? string.Empty);
            }

            // Keep observing: until issued is seen by tracker, or 90 s after the enroll returned.
            double deadline = t.TEnrollEnd + 90;
            while (Now < deadline)
            {
                await Task.Delay(500);
                bool issuedSeen = trackObs.Any(o => IsIssuedTrack(o.Status));
                if (issuedSeen && Now >= t.TEnrollEnd + 4) break;
                if (orderIdFromCreate == null && Now >= t.TEnrollEnd + 6) break; // nothing was placed
            }
            stopAll.Cancel();
            try { await Task.WhenAll(trackerTask, listerTask); } catch { /* observation only */ }

            Analyze(t, tp, trackObs.OrderBy(o => o.Recv).ToList(), listObs.OrderBy(o => o.Start).ToList());
        }

        private void Analyze(Trial t, TimingClientProxy tp, List<TrackObs> track, List<ListObs> lists)
        {
            var calls = tp.Calls.OrderBy(c => c.Start).ToList();
            var place = calls.FirstOrDefault(c => c.Name == "PlaceOrderV2Async");
            var csr = calls.FirstOrDefault(c => c.Name == "SubmitCsrV2Async");
            var dl = calls.FirstOrDefault(c => c.Name == "DownloadCertificateV2Async");
            if (place != null) { t.PlaceMs = place.DurationMs; t.TPlaceResp = place.End; if (place.Error != null) t.Error += "place: " + place.Error + "; "; }
            if (csr != null) { t.CsrMs = csr.DurationMs; t.TCsrResp = csr.End; if (csr.Error != null) t.Error += "csr: " + csr.Error + "; "; }
            if (dl != null) t.DownloadMs = dl.DurationMs;
            t.TrackCallMs = calls.Where(c => c.Name == "TrackOrderV2Async").Select(c => c.DurationMs).ToList();

            // Listing: first poll whose rows contained the order.
            t.ListPolls = lists.Count;
            t.ListErrors = lists.Count(l => l.Error != null);
            t.ListPollMedianS = Median(lists.Select(l => l.End - l.Start));
            var firstSeen = lists.Where(l => l.Matched).OrderBy(l => l.End).FirstOrDefault();
            if (firstSeen != null)
            {
                t.FirstSeenList = firstSeen.End;
                t.FirstSeenListLower = firstSeen.Start;
                t.FirstSeenListStatus = Scrub(firstSeen.Combined);
            }
            var issuedList = lists.Where(l => l.Matched && IsIssuedListing(l)).OrderBy(l => l.End).FirstOrDefault();
            if (issuedList != null) t.TIssuedList = issuedList.End;

            var lseq = new List<string>();
            foreach (var l in lists.Where(l => l.Matched).OrderBy(l => l.End))
            {
                string s = Scrub(l.Combined);
                if (lseq.Count == 0 || !lseq[^1].StartsWith(s + "@", StringComparison.Ordinal))
                    lseq.Add($"{s}@{F(l.End - t.T0)}");
            }
            t.ListSeq = string.Join("; ", lseq);

            // Tracker.
            t.TrackPolls = track.Count;
            t.TrackErrors = track.Count(o => o.Error != null);
            var okObs = track.Where(o => o.Error == null).ToList();
            if (okObs.Count > 0)
            {
                t.TrackFirstObsRecv = okObs[0].Recv;
                t.TrackFirstObsStatus = okObs[0].Status;
            }
            if (!double.IsNaN(t.TCsrResp))
            {
                var afterCsr = okObs.FirstOrDefault(o => o.Recv >= t.TCsrResp);
                if (afterCsr != null) t.StatusAfterCsr = afterCsr.Status + "@" + F(afterCsr.Recv - t.T0);
            }
            var issuedTrack = okObs.FirstOrDefault(o => IsIssuedTrack(o.Status));
            if (issuedTrack != null) { t.TIssuedTrack = issuedTrack.Recv; t.TIssuedTrackLower = issuedTrack.Sent; }

            var tseq = new List<string>();
            foreach (var o in okObs)
                if (tseq.Count == 0 || !tseq[^1].StartsWith(o.Status + "@", StringComparison.Ordinal))
                    tseq.Add($"{o.Status}@{F(o.Recv - t.T0)}");
            t.TrackSeq = string.Join("; ", tseq);
            foreach (var o in track.Where(o => o.Error != null).Take(2))
                t.Error += "track: " + o.Error + "; ";
        }

        private void LogTrial(Trial t)
        {
            W($"trial {t.Index:D2} order={(string.IsNullOrEmpty(t.OrderId) ? "-" : t.OrderId)} " +
              $"place={F(t.PlaceMs / 1000)}s csr={F(t.CsrMs / 1000)}s tracks=[{string.Join(",", t.TrackCallMs.Select(x => F(x / 1000)))}]s " +
              $"download={F(t.DownloadMs / 1000)}s enrollWall={F(t.TEnrollEnd - t.T0)}s enroll={t.EnrollStatus} cert={t.EnrollHasCert} " +
              $"createStatus={t.CreateRespStatus} firstSeenInListing={F(t.FirstSeenList - t.T0)}s({t.FirstSeenListStatus}) " +
              $"placeResp={F(t.TPlaceResp - t.T0)}s csrResp={F(t.TCsrResp - t.T0)}s " +
              $"dlProbe@{F(t.DlProbeAt - t.T0)}s={t.DlProbeResult} issuedTrack={F(t.TIssuedTrack - t.T0)}s issuedList={F(t.TIssuedList - t.T0)}s " +
              $"trackSeq=[{t.TrackSeq}] listSeq=[{t.ListSeq}] cleanup={t.CleanupNote} {t.Error}");
        }

        private void WriteCsv(string runId, List<Trial> trials)
        {
            try
            {
                string dir = Path.Combine(RepoRoot(), "experiment-results");
                Directory.CreateDirectory(dir);
                string path = Path.Combine(dir, $"v2-placeorder-latency-{runId}.csv");
                var sb = new StringBuilder();
                sb.AppendLine("trial,domain,order_id,t0_utc,create_resp_status,place_ms,csr_ms,track_calls_ms,download_ms," +
                              "enroll_wall_s,enroll_status,enroll_has_cert,t_place_resp_s,t_csr_resp_s,t_enroll_end_s," +
                              "first_seen_listing_s,first_seen_listing_lower_s,first_seen_listing_status," +
                              "seen_in_listing_before_place_resp,seen_in_listing_before_csr_resp,exposure_seen_to_enroll_end_s," +
                              "track_first_obs_s,track_first_obs_status,status_after_csr," +
                              "t_issued_track_s,t_issued_track_lower_s,t_issued_listing_s," +
                              "issued_before_place_resp,issued_before_csr_resp,issued_before_enroll_end," +
                              "dl_probe_at_s,dl_probe_ms,dl_probe_result,track_seq,listing_seq,list_polls,list_poll_median_s,track_polls,list_errors,track_errors,cleanup,error");
                foreach (var t in trials)
                {
                    string Rel(double x) => double.IsNaN(x) ? "" : F(x - t.T0);
                    string Q(string s) => "\"" + Scrub(s ?? "").Replace("\"", "'") + "\"";
                    bool seenBeforePlace = !double.IsNaN(t.FirstSeenList) && !double.IsNaN(t.TPlaceResp) && t.FirstSeenList < t.TPlaceResp;
                    bool seenBeforeCsr = !double.IsNaN(t.FirstSeenList) && !double.IsNaN(t.TCsrResp) && t.FirstSeenList < t.TCsrResp;
                    // Issued strictly before a response returned: use the observation's RECEIVE time vs that response's time.
                    bool issuedBeforePlace = !double.IsNaN(t.TIssuedList) && !double.IsNaN(t.TPlaceResp) && t.TIssuedList < t.TPlaceResp;
                    double issuedAny = double.IsNaN(t.TIssuedTrack) ? t.TIssuedList
                        : double.IsNaN(t.TIssuedList) ? t.TIssuedTrack : Math.Min(t.TIssuedTrack, t.TIssuedList);
                    bool issuedBeforeCsr = !double.IsNaN(issuedAny) && !double.IsNaN(t.TCsrResp) && issuedAny < t.TCsrResp;
                    bool issuedBeforeEnd = !double.IsNaN(issuedAny) && !double.IsNaN(t.TEnrollEnd) && issuedAny < t.TEnrollEnd;
                    double exposure = (!double.IsNaN(t.FirstSeenList) && !double.IsNaN(t.TEnrollEnd)) ? t.TEnrollEnd - t.FirstSeenList : double.NaN;
                    sb.AppendLine(string.Join(",", new[]
                    {
                        t.Index.ToString(CultureInfo.InvariantCulture), t.Domain, t.OrderId ?? "", t.T0Utc.ToString("o", CultureInfo.InvariantCulture),
                        t.CreateRespStatus, F(t.PlaceMs), F(t.CsrMs), Q(string.Join(";", t.TrackCallMs.Select(F))), F(t.DownloadMs),
                        F(t.TEnrollEnd - t.T0), t.EnrollStatus, t.EnrollHasCert ? "1" : "0", Rel(t.TPlaceResp), Rel(t.TCsrResp), Rel(t.TEnrollEnd),
                        Rel(t.FirstSeenList), Rel(t.FirstSeenListLower), Q(t.FirstSeenListStatus),
                        seenBeforePlace ? "1" : "0", seenBeforeCsr ? "1" : "0", F(exposure),
                        Rel(t.TrackFirstObsRecv), Q(t.TrackFirstObsStatus), Q(t.StatusAfterCsr),
                        Rel(t.TIssuedTrack), Rel(t.TIssuedTrackLower), Rel(t.TIssuedList),
                        issuedBeforePlace ? "1" : "0", issuedBeforeCsr ? "1" : "0", issuedBeforeEnd ? "1" : "0",
                        Rel(t.DlProbeAt), F(t.DlProbeMs), Q(t.DlProbeResult),
                        Q(t.TrackSeq), Q(t.ListSeq), t.ListPolls.ToString(CultureInfo.InvariantCulture), F(t.ListPollMedianS),
                        t.TrackPolls.ToString(CultureInfo.InvariantCulture), t.ListErrors.ToString(CultureInfo.InvariantCulture),
                        t.TrackErrors.ToString(CultureInfo.InvariantCulture), Q(t.CleanupNote), Q(t.Error)
                    }));
                }
                File.WriteAllText(path, sb.ToString());
                W($"CSV written: experiment-results/{Path.GetFileName(path)}");
            }
            catch (Exception ex)
            {
                W($"CSV write failed: {Describe(ex)}");
            }
        }

        private void WriteSummary(List<Trial> trials)
        {
            var ok = trials.Where(t => !string.IsNullOrEmpty(t.OrderId)).ToList();
            W($"=== summary (seconds; min / median / max; n) over {ok.Count} placed orders ===");
            void Row(string name, Func<Trial, double> get)
            {
                var xs = ok.Select(get).Where(x => !double.IsNaN(x)).ToArray();
                W(xs.Length == 0 ? $"{name,-22} n=0"
                    : $"{name,-22} {F(xs.Min())} / {F(Median(xs))} / {F(xs.Max())} (n={xs.Length})");
            }
            Row("place (HTTP)", t => t.PlaceMs / 1000);
            Row("csr submit (HTTP)", t => t.CsrMs / 1000);
            Row("download (HTTP)", t => t.DownloadMs / 1000);
            Row("enroll wall", t => t.TEnrollEnd - t.T0);
            Row("first seen in listing", t => t.FirstSeenList - t.T0);
            Row("issued (track)", t => t.TIssuedTrack - t.T0);
            Row("issued (listing)", t => t.TIssuedList - t.T0);
            Row("seen->enroll end", t => t.TEnrollEnd - t.FirstSeenList);
        }

        /// <summary>Revoke if issued, otherwise cancel via the raw endpoint (single attempt). Never throws.</summary>
        private async Task<string> CleanupAsync(CERTInextCAPlugin plugin, string orderId)
        {
            if (string.IsNullOrWhiteSpace(orderId)) return "no order";
            try
            {
                var current = await plugin.GetSingleRecord(orderId);
                if (current?.Status == (int)EndEntityStatus.GENERATED)
                {
                    int r = await plugin.Revoke(orderId, hexSerialNumber: string.Empty, revocationReason: 4);
                    return $"revoked ({r})";
                }
                await V2RawHttpHelpers.CancelSslOrderRawAsync(_apiUrl, _clientId, _clientSecret, orderId,
                    "V2 latency experiment cleanup — order not issued, cancelling.");
                return $"cancelled (status was {current?.Status})";
            }
            catch (Exception ex)
            {
                return "cleanup FAILED: " + Describe(ex);
            }
        }
    }
}
