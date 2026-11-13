// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using RestSharp;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Measurement experiment (issues 0062 + 0090, V2): does a SINGLE V2 call
    /// (<c>POST /ssl-certificates</c> with the CSR inline in the create body, no follow-up
    /// <c>PUT .../csr</c>) actually issue a certificate, and does the ~20 s "certificate is
    /// generated inside the call that delivers the CSR" hold move from <c>PUT /csr</c> onto the
    /// create call?
    ///
    /// Two arms, interleaved (A, B, A, B, ...), sequential, on the verified base domain
    /// (CERTINEXT_DCV_DOMAIN itself, DV product 842 pinned via <c>X-Product-Code</c> by default):
    /// <list type="bullet">
    ///   <item><b>A</b> - inline CSR single call: create body carries <c>"csr"</c>; nothing else is sent.</item>
    ///   <item><b>B</b> - two-call control exactly as the plugin does it: create (no csr), then
    ///     <c>PUT .../csr</c> with the PEM CSR.</item>
    /// </list>
    /// The plugin's <c>V2CreateSslOrderRequest</c> has no <c>csr</c> property, so every call here is
    /// raw HTTP (RestSharp, same headers the plugin sends); the body is the plugin's own DTO
    /// serialized with its own serializer options, with <c>csr</c> injected for arm A. No plugin
    /// production code is exercised or changed.
    ///
    /// Per order the test records: create latency + status/orderState/certificateState; PUT latency
    /// (arm B); Track Order polled every ~1.5 s from the create response (status/orderState/
    /// certificateState transitions, incl. whether "System Error" appears and clears); the orders
    /// report (the call Synchronize makes) polled concurrently every ~1.5 s with a narrow
    /// today..tomorrow window (first appearance and every status transition = the enroll/sync race
    /// window); whether <c>GET .../certificate</c> succeeds and when, and that the issued certificate
    /// matches the CSR's public key and CN. Every order is then revoked/cancelled and re-tracked.
    ///
    /// Opt-in: <c>CERTINEXT_V2_INLINE_CSR_EXPERIMENT=1</c> as a REAL environment variable.
    /// Optional env:
    /// <c>CERTINEXT_V2_INLINE_CSR_COUNT</c> orders per arm (default 5, max 8);
    /// <c>CERTINEXT_V2_INLINE_CSR_ARMS</c> (<c>AB</c> default, <c>BA</c> runs the control first in each pair, <c>A</c>, or <c>B</c>);
    /// <c>CERTINEXT_V2_INLINE_CSR_ENCODING</c> arm-A CSR encoding (<c>pem</c> default, <c>der</c> =
    /// headerless Base64 DER, <c>alt</c> = alternate per arm-A order); arm B is always PEM (the plugin's shape);
    /// <c>CERTINEXT_V2_INLINE_CSR_PRODUCT_HEADER</c> (<c>on</c> default = X-Product-Code: CERTINEXT_PRODUCT_CODE
    /// [842]; <c>off</c> = omit the header; anything else = that literal code);
    /// <c>CERTINEXT_V2_INLINE_CSR_SPACING_SECONDS</c> pause between orders (default 20);
    /// <c>CERTINEXT_V2_INLINE_CSR_TIMEOUT_SECONDS</c> per-order observation cap (default 180).
    /// No retries of order creation. Emails are scrubbed from every output line; credentials come
    /// from ~/.env_certinext_v2. Raw CSV goes to <c>experiment-results/</c>.
    /// </summary>
    public class V2InlineCsrIssuanceExperimentTests : IClassFixture<IntegrationTestFixture>
    {
        private const string OptInFlag = "CERTINEXT_V2_INLINE_CSR_EXPERIMENT";
        private const int MaxPerArm = 8;
        private const int MaxListPollsInFlight = 2;
        private const string CleanupReason = "V2 inline-CSR experiment cleanup (issues 0062/0090) - sandbox test order.";
        private static readonly TimeSpan ListPollInterval = TimeSpan.FromSeconds(1.5);
        private static readonly TimeSpan TrackPollInterval = TimeSpan.FromSeconds(1.5);

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

        public V2InlineCsrIssuanceExperimentTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
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
        private static string Scrub(string s, int max = 400)
        {
            if (string.IsNullOrEmpty(s)) return s ?? string.Empty;
            s = EmailRx.Replace(s, "<email>");
            s = s.Replace("\r", " ").Replace("\n", " ");
            return s.Length > max ? s.Substring(0, max) + "..." : s;
        }

        private static readonly Regex PersonBlockRx = new(
            "\"(orderedBy|requestor|technicalPointOfContact|requestedBy)\"\\s*:\\s*\\{[^}]*\\}", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        /// <summary>
        /// Scrub for raw API bodies: drops the person blocks (the response echoes the requestor and the
        /// account user's name/email) and then applies the normal email scrub and length cap.
        /// </summary>
        private static string ScrubBody(string s, int max = 400) =>
            Scrub(PersonBlockRx.Replace(s ?? string.Empty, m => $"\"{m.Groups[1].Value}\":{{<redacted>}}"), max);

        private static string Describe(Exception ex) => Scrub($"{ex.GetType().Name}: {ex.Message}");

        private void W(string s) => _output.WriteLine(Scrub(s, 1200));

        // ---------------------------------------------------------------------------
        // Observation records
        // ---------------------------------------------------------------------------

        private sealed class HttpResult
        {
            public double Start;
            public double End = double.NaN;
            public int Status;
            public string Body = string.Empty;
            public string Error = string.Empty;
            public double Ms => (End - Start) * 1000.0;
            public bool Ok => Status >= 200 && Status < 300;
        }

        private sealed class TrackObs
        {
            public double Sent;
            public double Recv;
            public int Http;
            public string Status = string.Empty;
            public string OrderState = string.Empty;
            public string CertState = string.Empty;
            public string Error = string.Empty;
            public string Body = string.Empty;
            public string Sig => $"{Status}|{OrderState}|{CertState}";
        }

        private sealed class ListObs
        {
            public double Start;
            public double End;
            public int Rows;
            public string Error = string.Empty;
            /// <summary>Orders on the experiment domain that did not exist before t0: orderNumber -> "orderStatus|certStatus".</summary>
            public Dictionary<string, string> New = new(StringComparer.Ordinal);
        }

        private sealed class Trial
        {
            public int Index;
            public string Arm;
            public string Encoding = "pem";
            public string Domain;
            public string OrderId = string.Empty;
            public DateTime T0Utc;
            public double T0;

            public int CreateHttp;
            public double CreateMs = double.NaN, TCreateResp = double.NaN;
            public string CreateStatus = string.Empty, CreateOrderState = string.Empty, CreateCertState = string.Empty;
            public string CreateBody = string.Empty;
            public int PutHttp;
            public double PutMs = double.NaN, TPutResp = double.NaN;
            public string PutBody = string.Empty;

            public double TFirstTrackObs = double.NaN;
            public double TIssuedTrack = double.NaN, TIssuedTrackLower = double.NaN;
            public string TrackSeq = string.Empty;
            public bool SystemErrorSeen;
            public double SysErrFirst = double.NaN, SysErrCleared = double.NaN;
            public int TrackPolls, TrackErrors;

            public double FirstSeenList = double.NaN, FirstSeenListLower = double.NaN;
            public string FirstSeenListStatus = string.Empty;
            public double TIssuedList = double.NaN;
            public string ListSeq = string.Empty;
            public int ListPolls, ListErrors;
            public double ListPollMedianS = double.NaN;

            public double DlFirstAt = double.NaN, DlSuccessAt = double.NaN, DlMs = double.NaN;
            public int DlAttempts;
            public volatile bool TrackSaidIssued;
            public string DlLastFailure = string.Empty;
            public string DlFirstResult = string.Empty;
            public string CertPubKeyMatch = string.Empty, CertCnMatch = string.Empty;

            public List<string> Strays = new();
            public string CleanupNote = string.Empty;
            public string FinalState = string.Empty;
            public string Error = string.Empty;

            public bool Issued => !double.IsNaN(TIssuedTrack) || !double.IsNaN(TIssuedList);
        }

        // ---------------------------------------------------------------------------
        // Small helpers
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

        private static string EnvOr(string name, string fallback)
        {
            string v = Environment.GetEnvironmentVariable(name);
            return string.IsNullOrWhiteSpace(v) ? fallback : v.Trim();
        }

        /// <summary>First string value of <paramref name="name"/> at the top level of the JSON body, else anywhere (depth-first); "" if none.</summary>
        private static string JsonString(string body, string name, bool topLevelOnly)
        {
            if (string.IsNullOrWhiteSpace(body)) return string.Empty;
            try
            {
                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.ValueKind == JsonValueKind.Object)
                {
                    foreach (var p in doc.RootElement.EnumerateObject())
                        if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase) && p.Value.ValueKind == JsonValueKind.String)
                            return p.Value.GetString() ?? string.Empty;
                }
                if (topLevelOnly) return string.Empty;
                return FindDeep(doc.RootElement, name) ?? string.Empty;
            }
            catch (JsonException) { return string.Empty; }
        }

        private static string FindDeep(JsonElement e, string name)
        {
            if (e.ValueKind == JsonValueKind.Object)
            {
                foreach (var p in e.EnumerateObject())
                {
                    if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase) && p.Value.ValueKind == JsonValueKind.String)
                        return p.Value.GetString();
                    string d = FindDeep(p.Value, name);
                    if (d != null) return d;
                }
            }
            else if (e.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in e.EnumerateArray())
                {
                    string d = FindDeep(item, name);
                    if (d != null) return d;
                }
            }
            return null;
        }

        private static bool IsIssuedStatus(string s) =>
            string.Equals(s, Constants.ApiV2.StatusIssued, StringComparison.OrdinalIgnoreCase);

        private static bool IsTerminalNonIssued(string s) =>
            string.Equals(s, Constants.ApiV2.StatusRevoked, StringComparison.OrdinalIgnoreCase)
            || string.Equals(s, Constants.ApiV2.StatusCancelled, StringComparison.OrdinalIgnoreCase)
            || string.Equals(s, Constants.ApiV2.StatusRejected, StringComparison.OrdinalIgnoreCase)
            || string.Equals(s, Constants.ApiV2.StatusExpired, StringComparison.OrdinalIgnoreCase);

        private static bool IsPendingStatus(string s) =>
            !string.IsNullOrEmpty(s) && s.StartsWith("pending-", StringComparison.OrdinalIgnoreCase);

        private static bool IsIssuedListing(string combined) =>
            combined != null &&
            (combined.IndexOf("Generated", StringComparison.OrdinalIgnoreCase) >= 0
             || combined.IndexOf("Downloaded", StringComparison.OrdinalIgnoreCase) >= 0);

        private static bool IsSystemError(string certState) =>
            !string.IsNullOrEmpty(certState) && certState.IndexOf("error", StringComparison.OrdinalIgnoreCase) >= 0;

        private static readonly JsonSerializerOptions PluginJsonOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        };

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

        // ---------------------------------------------------------------------------
        // CSR (BouncyCastle only)
        // ---------------------------------------------------------------------------

        private sealed class CsrBundle
        {
            public AsymmetricCipherKeyPair KeyPair;
            public string Pem;
            public string Base64Der;
        }

        private static CsrBundle GenerateCsr(string commonName)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            var keyPair = keyGen.GenerateKeyPair();
            var csr = new Pkcs10CertificationRequest("SHA256withRSA", new X509Name($"CN={commonName}"),
                keyPair.Public, null, keyPair.Private);
            byte[] der = csr.GetEncoded();
            return new CsrBundle
            {
                KeyPair = keyPair,
                Base64Der = Convert.ToBase64String(der),
                Pem = "-----BEGIN CERTIFICATE REQUEST-----\n"
                      + Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks)
                      + "\n-----END CERTIFICATE REQUEST-----"
            };
        }

        /// <summary>Parses the downloaded PEM with BouncyCastle and compares public key + CN to the CSR.</summary>
        private static void CheckCertificate(Trial t, string certPem, CsrBundle csr)
        {
            try
            {
                using var sr = new StringReader(certPem);
                var cert = new PemReader(sr).ReadObject() as Org.BouncyCastle.X509.X509Certificate;
                if (cert == null) { t.CertPubKeyMatch = "unparseable"; t.CertCnMatch = "unparseable"; return; }
                var certKey = cert.GetPublicKey() as RsaKeyParameters;
                var csrKey = csr.KeyPair.Public as RsaKeyParameters;
                t.CertPubKeyMatch = certKey != null && csrKey != null && certKey.Modulus.Equals(csrKey.Modulus)
                    && certKey.Exponent.Equals(csrKey.Exponent) ? "match" : "MISMATCH";
                string subject = cert.SubjectDN.ToString();
                t.CertCnMatch = subject.IndexOf("CN=" + t.Domain, StringComparison.OrdinalIgnoreCase) >= 0 ? "match" : "MISMATCH(" + Scrub(subject, 120) + ")";
            }
            catch (Exception ex)
            {
                t.CertPubKeyMatch = "error: " + Describe(ex);
                t.CertCnMatch = t.CertPubKeyMatch;
            }
        }

        // ---------------------------------------------------------------------------
        // Raw HTTP
        // ---------------------------------------------------------------------------

        /// <summary>
        /// One raw V2 call with the same headers the plugin client sends (Bearer, Accept, optional
        /// Idempotency-Key and X-Product-Code). Never throws: transport errors land in <see cref="HttpResult.Error"/>.
        /// </summary>
        private async Task<HttpResult> SendAsync(RestClient api, string token, Method method, string path,
            string jsonBody, string productHeader, bool idempotency, TimeSpan timeout)
        {
            var r = new HttpResult { Start = Now };
            try
            {
                var req = new RestRequest(path, method);
                req.AddHeader("Authorization", $"Bearer {token}");
                req.AddHeader("Accept", "application/json");
                if (idempotency) req.AddHeader("Idempotency-Key", Guid.NewGuid().ToString());
                if (!string.IsNullOrWhiteSpace(productHeader)) req.AddHeader("X-Product-Code", productHeader);
                if (jsonBody != null) req.AddJsonBody(jsonBody);
                using var cts = new CancellationTokenSource(timeout);
                var resp = await api.ExecuteAsync(req, cts.Token);
                r.Status = (int)resp.StatusCode;
                r.Body = resp.Content ?? string.Empty;
                if (resp.StatusCode == 0)
                    r.Error = Scrub($"{resp.ResponseStatus}: {resp.ErrorMessage}");
            }
            catch (Exception ex)
            {
                r.Error = Describe(ex);
            }
            r.End = Now;
            return r;
        }

        // ---------------------------------------------------------------------------
        // The experiment
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task V2InlineCsr_SingleCall_Vs_TwoCall_Issuance_Experiment()
        {
            Skip.If(!_v2Enabled, "V2 credentials not configured in ~/.env_certinext_v2 (CERTINEXT_USE_V2_API, API_URL, CLIENT_ID, CLIENT_SECRET).");
            Skip.If(Environment.GetEnvironmentVariable(OptInFlag) != "1",
                $"Opt-in: set {OptInFlag}=1 as a real environment variable (places live sandbox orders).");
            Skip.If(string.IsNullOrWhiteSpace(_baseDomain), "CERTINEXT_DCV_DOMAIN is required (verified base domain used as the order CN).");

            int perArm = int.TryParse(Environment.GetEnvironmentVariable("CERTINEXT_V2_INLINE_CSR_COUNT"), out int c) ? c : 5;
            perArm = Math.Max(1, Math.Min(MaxPerArm, perArm));
            string arms = EnvOr("CERTINEXT_V2_INLINE_CSR_ARMS", "AB").ToUpperInvariant();
            bool doA = arms.Contains('A'), doB = arms.Contains('B');
            Assert.True(doA || doB, "CERTINEXT_V2_INLINE_CSR_ARMS must contain A and/or B.");
            string encMode = EnvOr("CERTINEXT_V2_INLINE_CSR_ENCODING", "pem").ToLowerInvariant();
            Assert.Contains(encMode, new[] { "pem", "der", "alt" });
            string headerMode = EnvOr("CERTINEXT_V2_INLINE_CSR_PRODUCT_HEADER", "on");
            string productHeader = headerMode.Equals("on", StringComparison.OrdinalIgnoreCase) ? _productCode
                : (headerMode.Equals("off", StringComparison.OrdinalIgnoreCase) || headerMode.Equals("none", StringComparison.OrdinalIgnoreCase)) ? null
                : headerMode;
            double spacing = double.TryParse(Environment.GetEnvironmentVariable("CERTINEXT_V2_INLINE_CSR_SPACING_SECONDS"),
                NumberStyles.Float, CultureInfo.InvariantCulture, out double sp) ? sp : 20;
            double timeoutS = double.TryParse(Environment.GetEnvironmentVariable("CERTINEXT_V2_INLINE_CSR_TIMEOUT_SECONDS"),
                NumberStyles.Float, CultureInfo.InvariantCulture, out double to) ? to : 180;

            string runId = DateTime.UtcNow.ToString("MMddHHmm", CultureInfo.InvariantCulture);
            var cfg = BuildConfig();
            using var listClient = new CERTInextClient(cfg);
            using var cleanupClient = new CERTInextClient(cfg);
            var api = V2RawHttpHelpers.NewApiClient(_apiUrl.TrimEnd('/'), TimeSpan.FromSeconds(300));

            W($"V2 inline-CSR experiment run {runId}: domain={_baseDomain}, X-Product-Code={(productHeader ?? "<omitted>")}, " +
              $"arms={arms}, perArm={perArm}, armAEncoding={encMode}, spacingS={F(spacing)}, observeCapS={F(timeoutS)}");

            // Interleaved schedule A,B,A,B,...
            var schedule = new List<string>();
            for (int i = 0; i < perArm; i++)
            {
                // Arm order within each pair follows the ARMS string (e.g. "BA" puts the two-call control first).
                foreach (char ch in arms)
                    if (ch == 'A' || ch == 'B') schedule.Add(ch.ToString());
            }

            var trials = new List<Trial>();
            var consecutiveNoIssue = new Dictionary<string, int> { ["A"] = 0, ["B"] = 0 };
            var aCount = 0;
            double lastEnd = double.NegativeInfinity;
            try
            {
                foreach (string arm in schedule)
                {
                    if (consecutiveNoIssue[arm] >= 2)
                    {
                        W($"arm {arm}: skipped - the previous 2 orders in this arm did not issue; stopping the arm (report as a finding).");
                        continue;
                    }
                    var t = new Trial { Index = trials.Count + 1, Arm = arm, Domain = _baseDomain.ToLowerInvariant() };
                    if (arm == "A")
                    {
                        t.Encoding = encMode == "alt" ? (aCount % 2 == 0 ? "pem" : "der") : encMode;
                        aCount++;
                    }
                    trials.Add(t);

                    double wait = lastEnd + spacing - Now;
                    if (wait > 0) await Task.Delay(TimeSpan.FromSeconds(wait));

                    try
                    {
                        await RunTrialAsync(t, api, listClient, productHeader, timeoutS);
                    }
                    catch (Exception ex)
                    {
                        t.Error += "trial: " + Describe(ex) + "; ";
                    }
                    finally
                    {
                        await CleanupTrialAsync(cleanupClient, t);
                        lastEnd = Now;
                    }
                    consecutiveNoIssue[arm] = t.Issued ? 0 : consecutiveNoIssue[arm] + 1;
                    LogTrial(t);
                }
            }
            finally
            {
                WriteCsv(runId, trials, productHeader, encMode);
                WriteSummary(trials);
                W("ORDER IDS: " + string.Join(",", trials.SelectMany(t => new[] { t.OrderId }.Concat(t.Strays)).Where(s => !string.IsNullOrEmpty(s)).Distinct()));
            }

            var notTerminal = trials.Where(t => !string.IsNullOrEmpty(t.OrderId) && !IsTerminalNonIssued(t.FinalState))
                .Select(t => $"{t.OrderId}({t.FinalState})").ToList();
            Assert.True(notTerminal.Count == 0, "Orders not in a terminal state after cleanup: " + string.Join(", ", notTerminal));
        }

        private async Task RunTrialAsync(Trial t, RestClient api, CERTInextClient listClient, string productHeader, double timeoutS)
        {
            string basePath = Constants.ApiV2.SslCertificatesPath;
            bool inline = t.Arm == "A";

            // Everything not under test happens before t0.
            var csr = GenerateCsr(t.Domain);
            string token = await V2RawHttpHelpers.GetV2AccessTokenAsync(_apiUrl, _clientId, _clientSecret);
            string today = DateTime.UtcNow.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            string tomorrow = DateTime.UtcNow.AddDays(1).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

            var snapshot = new HashSet<string>(StringComparer.Ordinal);
            await foreach (var e in listClient.ListOrdersV2Async(today, tomorrow, 100))
                if (e?.OrderNumber != null && string.Equals(e.DomainName, t.Domain, StringComparison.OrdinalIgnoreCase))
                    snapshot.Add(e.OrderNumber);

            // Body = the plugin's own DTO + serializer options (identical to what Enroll sends for DV 842),
            // plus "csr" injected for arm A.
            string requestorPhone = CERTInextCAPlugin.ComposeV2Phone("1", "0000000000");
            var orderReq = new V2CreateSslOrderRequest
            {
                ProductVariant = "dv",
                Requestor = new V2Requestor { Name = _requestorName, Email = _requestorEmail, Phone = requestorPhone },
                Certificate = new V2CertificateParams { Domain = t.Domain, AutoSecureWww = false },
                Subscription = new V2SubscriptionParams { ValidityYears = 1, AutoRenew = false },
                Agreement = new V2AgreementParams { SignerName = _requestorName, SignerPlace = "Gateway Lab", Accepted = true },
                TechnicalPointOfContact = new V2TechnicalPointOfContact
                {
                    Name = _requestorName, Email = _requestorEmail, Phone = requestorPhone,
                    Designation = Constants.ApiV2.DefaultTechnicalContactDesignation
                },
                Remarks = "Issued via Keyfactor Command AnyCA REST Gateway.",
                GroupNumber = string.IsNullOrWhiteSpace(_groupNumber) ? null : _groupNumber
            };
            string createJson = JsonSerializer.Serialize(orderReq, PluginJsonOptions);
            if (inline)
            {
                var node = JsonNode.Parse(createJson) as JsonObject ?? throw new InvalidOperationException("create body is not a JSON object");
                node["csr"] = t.Encoding == "der" ? csr.Base64Der : csr.Pem;
                createJson = node.ToJsonString();
            }
            string putJson = JsonSerializer.Serialize(new V2SubmitCsrRequest { Csr = csr.Pem }, PluginJsonOptions);

            var trackObs = new ConcurrentQueue<TrackObs>();
            var listObs = new ConcurrentQueue<ListObs>();
            using var stopAll = new CancellationTokenSource();

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
                            if (e?.OrderNumber != null
                                && string.Equals(e.DomainName, t.Domain, StringComparison.OrdinalIgnoreCase)
                                && !snapshot.Contains(e.OrderNumber))
                                o.New[e.OrderNumber] = $"{e.OrderStatus}|{e.CertificateStatus}";
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

            Task trackerTask = Task.CompletedTask;
            string orderId = string.Empty;
            try
            {
                // ---- t0: create ----
                t.T0Utc = DateTime.UtcNow;
                t.T0 = Now;
                var create = await SendAsync(api, token, Method.Post, basePath, createJson, productHeader, idempotency: true, TimeSpan.FromSeconds(280));
                t.CreateHttp = create.Status;
                t.CreateMs = create.Ms;
                t.TCreateResp = create.End;
                t.CreateBody = ScrubBody(create.Body, 900);
                t.CreateStatus = JsonString(create.Body, "status", topLevelOnly: true);
                t.CreateOrderState = JsonString(create.Body, "orderState", topLevelOnly: false);
                t.CreateCertState = JsonString(create.Body, "certificateState", topLevelOnly: false);
                if (!string.IsNullOrEmpty(create.Error)) t.Error += "create: " + create.Error + "; ";
                if (!create.Ok) t.Error += $"create HTTP {create.Status}: {ScrubBody(create.Body, 300)}; ";
                orderId = create.Ok ? JsonString(create.Body, "orderId", topLevelOnly: true) : string.Empty;
                t.OrderId = orderId ?? string.Empty;

                if (!string.IsNullOrEmpty(orderId))
                {
                    // Tracker starts the instant the create response lands.
                    trackerTask = Task.WhenAll(
                        Task.Run(() => TrackLoopAsync(t, api, token, basePath, orderId, trackObs, stopAll.Token)),
                        Task.Run(() => DownloadLoopAsync(t, api, token, basePath, orderId, csr, stopAll.Token)));

                    if (!inline)
                    {
                        var put = await SendAsync(api, token, Method.Put, $"{basePath}/{orderId}/csr", putJson, null, idempotency: false, TimeSpan.FromSeconds(280));
                        t.PutHttp = put.Status;
                        t.PutMs = put.Ms;
                        t.TPutResp = put.End;
                        t.PutBody = ScrubBody(put.Body, 400);
                        if (!string.IsNullOrEmpty(put.Error)) t.Error += "put: " + put.Error + "; ";
                        if (!put.Ok) t.Error += $"put HTTP {put.Status}: {ScrubBody(put.Body, 300)}; ";
                    }

                    // Observe until issued + downloaded + listing agrees, a terminal failure, or the cap.
                    double deadline = t.T0 + timeoutS;
                    double terminalAt = double.NaN;
                    double settledAt = double.NaN;
                    while (Now < deadline)
                    {
                        await Task.Delay(500);
                        var snapT = trackObs.ToArray();
                        var latest = snapT.OrderBy(o => o.Recv).LastOrDefault(o => string.IsNullOrEmpty(o.Error));
                        if (latest != null && IsTerminalNonIssued(latest.Status))
                        {
                            if (double.IsNaN(terminalAt)) terminalAt = Now;
                            if (Now >= terminalAt + 3) break;
                        }
                        bool issuedSeen = snapT.Any(o => IsIssuedStatus(o.Status));
                        bool listingIssued = listObs.ToArray().Any(l => l.New.TryGetValue(orderId, out var s) && IsIssuedListing(s));
                        if (issuedSeen && !double.IsNaN(t.DlSuccessAt) && (listingIssued || Now > t.TIssuedTrack + 30))
                        {
                            // Tail: keep polling a few more seconds so the final Track Order / listing states are captured.
                            if (double.IsNaN(settledAt)) settledAt = Now;
                            if (Now >= settledAt + 5) break;
                        }
                        if (t.DlAttempts >= 60 && issuedSeen) break;
                    }
                }
                else
                {
                    // Create failed or returned no order id: keep listing for a moment so any stray order is seen.
                    await Task.Delay(TimeSpan.FromSeconds(10));
                }
            }
            finally
            {
                stopAll.Cancel();
                try { await Task.WhenAll(trackerTask, listerTask); } catch { /* observation only */ }
            }

            Analyze(t, trackObs.OrderBy(o => o.Recv).ToList(), listObs.OrderBy(o => o.Start).ToList());
        }

        private async Task TrackLoopAsync(Trial t, RestClient api, string token, string basePath, string orderId,
            ConcurrentQueue<TrackObs> trackObs, CancellationToken stop)
        {
            while (!stop.IsCancellationRequested)
            {
                var o = new TrackObs { Sent = Now };
                var r = await SendAsync(api, token, Method.Get, $"{basePath}/{orderId}", null, null, idempotency: false, TimeSpan.FromSeconds(30));
                o.Recv = Now;
                o.Http = r.Status;
                o.Error = r.Ok ? string.Empty : (string.IsNullOrEmpty(r.Error) ? $"HTTP {r.Status} {Scrub(r.Body, 150)}" : r.Error);
                if (r.Ok)
                {
                    o.Status = JsonString(r.Body, "status", topLevelOnly: true);
                    o.OrderState = JsonString(r.Body, "orderState", topLevelOnly: false);
                    o.CertState = JsonString(r.Body, "certificateState", topLevelOnly: false);
                    o.Body = ScrubBody(r.Body, 700);
                }
                trackObs.Enqueue(o);

                if (r.Ok && IsIssuedStatus(o.Status)) t.TrackSaidIssued = true;
                try { await Task.Delay(TrackPollInterval, stop); } catch (OperationCanceledException) { }
            }
        }

        /// <summary>
        /// Separate from the tracker so slow/failing downloads never delay Track Order polling.
        /// Starts probing GET .../certificate once Track Order first says "issued" and retries every
        /// ~2 s until one call returns a certificate (or the observation ends). The first failure body is kept.
        /// </summary>
        private async Task DownloadLoopAsync(Trial t, RestClient api, string token, string basePath, string orderId,
            CsrBundle csr, CancellationToken stop)
        {
            while (!stop.IsCancellationRequested && double.IsNaN(t.DlSuccessAt) && t.DlAttempts < 60)
            {
                if (t.TrackSaidIssued)
                {
                    t.DlAttempts++;
                    var dl = await SendAsync(api, token, Method.Get, $"{basePath}/{orderId}/certificate", null, null, idempotency: false, TimeSpan.FromSeconds(60));
                    string pem = dl.Ok ? JsonString(dl.Body, "certificatePem", topLevelOnly: true) : string.Empty;
                    string result = dl.Ok ? (string.IsNullOrWhiteSpace(pem) ? "ok-empty" : "ok-with-certificate")
                        : $"HTTP {dl.Status} {ScrubBody(string.IsNullOrEmpty(dl.Error) ? dl.Body : dl.Error, 220)}";
                    if (double.IsNaN(t.DlFirstAt))
                    {
                        t.DlFirstAt = dl.Start;
                        t.DlFirstResult = result;
                    }
                    t.DlLastFailure = dl.Ok && !string.IsNullOrWhiteSpace(pem) ? t.DlLastFailure : $"{result} @{F(dl.End - t.T0)}s ({F(dl.Ms / 1000)}s call)";
                    if (dl.Ok && !string.IsNullOrWhiteSpace(pem))
                    {
                        t.DlSuccessAt = dl.End;
                        t.DlMs = dl.Ms;
                        CheckCertificate(t, pem, csr);
                        return;
                    }
                }
                try { await Task.Delay(TimeSpan.FromSeconds(2), stop); } catch (OperationCanceledException) { }
            }
        }

        private void Analyze(Trial t, List<TrackObs> track, List<ListObs> lists)
        {
            string id = t.OrderId;

            // ---- tracker ----
            t.TrackPolls = track.Count;
            t.TrackErrors = track.Count(o => !string.IsNullOrEmpty(o.Error));
            var ok = track.Where(o => string.IsNullOrEmpty(o.Error)).ToList();
            if (ok.Count > 0) t.TFirstTrackObs = ok[0].Recv;
            var issuedTrack = ok.FirstOrDefault(o => IsIssuedStatus(o.Status));
            if (issuedTrack != null) { t.TIssuedTrack = issuedTrack.Recv; t.TIssuedTrackLower = issuedTrack.Sent; }

            // Sequence starts with the create response's own state so "System Error" at create time is visible.
            var seq = new List<string>();
            string createSig = $"{t.CreateStatus}|{t.CreateOrderState}|{t.CreateCertState}";
            if (!string.IsNullOrEmpty(t.OrderId)) seq.Add($"create:{createSig}@{F(t.TCreateResp - t.T0)}");
            string prev = createSig;
            foreach (var o in ok)
                if (o.Sig != prev)
                {
                    seq.Add($"{o.Sig}@{F(o.Recv - t.T0)}");
                    prev = o.Sig;
                }
            t.TrackSeq = string.Join("; ", seq);

            // System Error: first seen (create response counts) and when it clears.
            var states = new List<(double at, string cs)>();
            if (!string.IsNullOrEmpty(t.OrderId)) states.Add((t.TCreateResp, t.CreateCertState));
            states.AddRange(ok.Select(o => (o.Recv, o.CertState)));
            var firstErr = states.FirstOrDefault(s => IsSystemError(s.cs));
            if (firstErr.cs != null)
            {
                t.SystemErrorSeen = true;
                t.SysErrFirst = firstErr.at;
                var cleared = states.FirstOrDefault(s => s.at > firstErr.at && !IsSystemError(s.cs));
                if (cleared.cs != null) t.SysErrCleared = cleared.at;
            }
            foreach (var o in track.Where(o => !string.IsNullOrEmpty(o.Error)).Take(2))
                t.Error += "track: " + o.Error + "; ";

            // ---- listing ----
            t.ListPolls = lists.Count;
            t.ListErrors = lists.Count(l => !string.IsNullOrEmpty(l.Error));
            t.ListPollMedianS = Median(lists.Select(l => l.End - l.Start));
            var allNew = lists.SelectMany(l => l.New.Keys).Distinct().ToList();
            if (string.IsNullOrEmpty(id))
            {
                // No order id from create: any new order on the domain is a stray from this trial.
                t.Strays.AddRange(allNew);
                return;
            }
            if (allNew.Any(n => n != id)) t.Error += $"other new orders on domain during trial: {string.Join("/", allNew.Where(n => n != id))}; ";

            var matched = lists.Where(l => l.New.ContainsKey(id)).OrderBy(l => l.End).ToList();
            if (matched.Count > 0)
            {
                t.FirstSeenList = matched[0].End;
                t.FirstSeenListLower = matched[0].Start;
                t.FirstSeenListStatus = Scrub(matched[0].New[id]);
                var issuedL = matched.FirstOrDefault(l => IsIssuedListing(l.New[id]));
                if (issuedL != null) t.TIssuedList = issuedL.End;
            }
            var lseq = new List<string>();
            foreach (var l in matched)
            {
                string s = Scrub(l.New[id]);
                if (lseq.Count == 0 || !lseq[^1].StartsWith(s + "@", StringComparison.Ordinal))
                    lseq.Add($"{s}@{F(l.End - t.T0)}");
            }
            t.ListSeq = string.Join("; ", lseq);
        }

        // ---------------------------------------------------------------------------
        // Cleanup: revoke issued / cancel pending, then re-track and record the final state
        // ---------------------------------------------------------------------------

        private async Task CleanupTrialAsync(CERTInextClient client, Trial t)
        {
            var ids = new List<string>();
            if (!string.IsNullOrEmpty(t.OrderId)) ids.Add(t.OrderId);
            // Strays are only populated when create returned no order id, so there is exactly one order we created.
            if (string.IsNullOrEmpty(t.OrderId) && t.Strays.Count == 1) ids.AddRange(t.Strays);
            if (ids.Count == 0) { t.CleanupNote = "no order"; return; }

            var notes = new List<string>();
            foreach (string id in ids)
            {
                string note = await CleanupOneAsync(client, id, t);
                notes.Add($"{id}: {note}");
            }
            t.CleanupNote = string.Join(" | ", notes);
            if (string.IsNullOrEmpty(t.OrderId) && t.Strays.Count == 1) t.OrderId = t.Strays[0]; // reported as this trial's order
        }

        private async Task<string> CleanupOneAsync(CERTInextClient client, string id, Trial t)
        {
            string family = Constants.ApiV2.FamilySsl;
            string before = "?";
            string action = "none";
            try
            {
                before = (await client.TrackOrderV2Async(family, id)).Status ?? "(null)";
                if (IsTerminalNonIssued(before)) action = "skip (already " + before + ")";
                else if (IsIssuedStatus(before))
                {
                    try
                    {
                        await client.RevokeOrderV2Async(family, id, new V2RevokeRequest { Reason = "superseded", Note = CleanupReason });
                        action = "revoke(superseded)";
                    }
                    catch (Exception rex)
                    {
                        action = "revoke(superseded) rejected: " + Describe(rex);
                        await client.RevokeOrderV2Async(family, id, new V2RevokeRequest { Reason = "unspecified", Note = CleanupReason });
                        action += " -> revoke(unspecified)";
                    }
                }
                else if (IsPendingStatus(before))
                {
                    var outcome = await client.CancelOrderV2Async(family, id, CleanupReason);
                    action = "cancel -> " + outcome;
                }
                else action = "skip (unrecognised status)";
            }
            catch (Exception ex)
            {
                action += "; ACTION FAILED: " + Describe(ex);
            }

            string after = "?";
            for (int attempt = 0; attempt < 4; attempt++)
            {
                try
                {
                    after = (await client.TrackOrderV2Async(family, id)).Status ?? "(null)";
                    if (IsTerminalNonIssued(after)) break;
                }
                catch (Exception ex) { after = "TRACK ERROR: " + Describe(ex); }
                await Task.Delay(TimeSpan.FromSeconds(2));
            }
            if (id == t.OrderId || string.IsNullOrEmpty(t.OrderId)) t.FinalState = after;
            return $"before={before}; {action}; after={after}";
        }

        // ---------------------------------------------------------------------------
        // Output
        // ---------------------------------------------------------------------------

        private void LogTrial(Trial t)
        {
            W($"trial {t.Index:D2} arm={t.Arm} enc={(t.Arm == "A" ? t.Encoding : "pem(put)")} order={(string.IsNullOrEmpty(t.OrderId) ? "-" : t.OrderId)} " +
              $"createHttp={t.CreateHttp} createS={F(t.CreateMs / 1000)} createStatus={t.CreateStatus} createOrderState={t.CreateOrderState} createCertState={t.CreateCertState} " +
              $"putHttp={t.PutHttp} putS={F(t.PutMs / 1000)} " +
              $"issuedTrack={F(t.TIssuedTrack - t.T0)}s issuedListing={F(t.TIssuedList - t.T0)}s firstSeenListing={F(t.FirstSeenList - t.T0)}s({t.FirstSeenListStatus}) " +
              $"dlFirst@{F(t.DlFirstAt - t.T0)}s={t.DlFirstResult} dlAttempts={t.DlAttempts} dlLastFail=[{t.DlLastFailure}] dlOkAt={F(t.DlSuccessAt - t.T0)}s pubkey={t.CertPubKeyMatch} cn={t.CertCnMatch} " +
              $"sysErr={t.SystemErrorSeen}(first={F(t.SysErrFirst - t.T0)}s cleared={F(t.SysErrCleared - t.T0)}s) " +
              $"trackSeq=[{t.TrackSeq}] listSeq=[{t.ListSeq}] cleanup=[{t.CleanupNote}] final={t.FinalState} {t.Error}");
            if (t.Arm == "B" || !string.IsNullOrEmpty(t.PutBody))
                W($"trial {t.Index:D2} put body: {t.PutBody}");
            W($"trial {t.Index:D2} create body: {t.CreateBody}");
        }

        private void WriteCsv(string runId, List<Trial> trials, string productHeader, string encMode)
        {
            try
            {
                string dir = Path.Combine(RepoRoot(), "experiment-results");
                Directory.CreateDirectory(dir);
                string path = Path.Combine(dir, $"v2-inline-csr-{runId}.csv");
                var sb = new StringBuilder();
                sb.AppendLine("trial,arm,arm_a_encoding,product_header,domain,order_id,t0_utc," +
                              "create_http,create_ms,create_status,create_order_state,create_cert_state,create_body," +
                              "put_http,put_ms,put_body," +
                              "t_create_resp_s,t_put_resp_s,t_first_track_obs_s,t_issued_track_s,t_issued_track_lower_s,track_seq," +
                              "system_error_seen,system_error_first_s,system_error_cleared_s," +
                              "first_seen_listing_s,first_seen_listing_lower_s,first_seen_listing_status,t_issued_listing_s,listing_seq," +
                              "seen_in_listing_before_create_resp,listing_first_seen_to_create_resp_s,issued_in_listing_before_create_resp,create_resp_minus_issued_listing_s," +
                              "dl_first_at_s,dl_first_result,dl_last_failure,dl_success_at_s,dl_ms,dl_attempts,cert_pubkey,cert_cn," +
                              "track_polls,track_errors,list_polls,list_poll_median_s,list_errors,cleanup,final_state,error");
                foreach (var t in trials)
                {
                    string Rel(double x) => double.IsNaN(x) ? "" : F(x - t.T0);
                    string Q(string s) => "\"" + Scrub(s ?? "", 800).Replace("\"", "'") + "\"";
                    bool seenBefore = !double.IsNaN(t.FirstSeenList) && !double.IsNaN(t.TCreateResp) && t.FirstSeenList < t.TCreateResp;
                    bool issuedBefore = !double.IsNaN(t.TIssuedList) && !double.IsNaN(t.TCreateResp) && t.TIssuedList < t.TCreateResp;
                    sb.AppendLine(string.Join(",", new[]
                    {
                        t.Index.ToString(CultureInfo.InvariantCulture), t.Arm, t.Arm == "A" ? t.Encoding : "n/a", Q(productHeader ?? "<omitted>"), t.Domain, t.OrderId,
                        t.T0Utc.ToString("o", CultureInfo.InvariantCulture),
                        t.CreateHttp.ToString(CultureInfo.InvariantCulture), F(t.CreateMs), t.CreateStatus, Q(t.CreateOrderState), Q(t.CreateCertState), Q(t.CreateBody),
                        t.PutHttp.ToString(CultureInfo.InvariantCulture), F(t.PutMs), Q(t.PutBody),
                        Rel(t.TCreateResp), Rel(t.TPutResp), Rel(t.TFirstTrackObs), Rel(t.TIssuedTrack), Rel(t.TIssuedTrackLower), Q(t.TrackSeq),
                        t.SystemErrorSeen ? "1" : "0", Rel(t.SysErrFirst), Rel(t.SysErrCleared),
                        Rel(t.FirstSeenList), Rel(t.FirstSeenListLower), Q(t.FirstSeenListStatus), Rel(t.TIssuedList), Q(t.ListSeq),
                        seenBefore ? "1" : "0", (!double.IsNaN(t.FirstSeenList) && !double.IsNaN(t.TCreateResp)) ? F(t.TCreateResp - t.FirstSeenList) : "",
                        issuedBefore ? "1" : "0", (!double.IsNaN(t.TIssuedList) && !double.IsNaN(t.TCreateResp)) ? F(t.TCreateResp - t.TIssuedList) : "",
                        Rel(t.DlFirstAt), Q(t.DlFirstResult), Q(t.DlLastFailure), Rel(t.DlSuccessAt), F(t.DlMs), t.DlAttempts.ToString(CultureInfo.InvariantCulture), Q(t.CertPubKeyMatch), Q(t.CertCnMatch),
                        t.TrackPolls.ToString(CultureInfo.InvariantCulture), t.TrackErrors.ToString(CultureInfo.InvariantCulture),
                        t.ListPolls.ToString(CultureInfo.InvariantCulture), F(t.ListPollMedianS), t.ListErrors.ToString(CultureInfo.InvariantCulture),
                        Q(t.CleanupNote), Q(t.FinalState), Q(t.Error)
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
            foreach (string arm in new[] { "A", "B" })
            {
                var ts = trials.Where(t => t.Arm == arm && !string.IsNullOrEmpty(t.OrderId)).ToList();
                if (ts.Count == 0) continue;
                W($"=== arm {arm} summary (seconds after t0; min / median / max; n) over {ts.Count} orders, {ts.Count(t => t.Issued)} issued ===");
                void Row(string name, Func<Trial, double> get)
                {
                    var xs = ts.Select(get).Where(x => !double.IsNaN(x)).ToArray();
                    W(xs.Length == 0 ? $"{name,-34} n=0"
                        : $"{name,-34} {F(xs.Min())} / {F(Median(xs))} / {F(xs.Max())} (n={xs.Length})");
                }
                Row("create HTTP", t => t.CreateMs / 1000);
                if (arm == "B") Row("PUT /csr HTTP", t => t.PutMs / 1000);
                Row("first seen in listing", t => t.FirstSeenList - t.T0);
                Row("issued (track)", t => t.TIssuedTrack - t.T0);
                Row("issued (listing)", t => t.TIssuedList - t.T0);
                Row("create resp (t_create_resp)", t => t.TCreateResp - t.T0);
                Row("listing first seen -> create resp", t => t.TCreateResp - t.FirstSeenList);
                Row("download ok at", t => t.DlSuccessAt - t.T0);
                W($"   system error seen in {ts.Count(t => t.SystemErrorSeen)}/{ts.Count}; cleared in {ts.Count(t => !double.IsNaN(t.SysErrCleared))}; " +
                  $"download ok {ts.Count(t => !double.IsNaN(t.DlSuccessAt))}/{ts.Count}; pubkey match {ts.Count(t => t.CertPubKeyMatch == "match")}; cn match {ts.Count(t => t.CertCnMatch == "match")}");
            }
        }
    }
}
