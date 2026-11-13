// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

#if SUPPORTS_DCV
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Opt-in live probe: can the CERTInext V2 API express a certificate lifetime shorter than one
    /// year (CA/B Forum is shrinking maximum TLS lifetimes: 200 days now, 100 from Mar 2027, 47 from
    /// Mar 2029)? V2 orders only document <c>subscription.validityYears</c> (an integer billing
    /// entitlement window, "distinct from the certificate's own notBefore/notAfter").
    ///
    /// Each variant drives a real DV order through the V2 plugin (<c>Enroll</c>, then
    /// <c>GetSingleRecord</c> until issued) with the plugin's HTTP traffic routed through a loopback
    /// pass-through proxy. The proxy optionally mutates the JSON body of the order-create POST (to
    /// inject undocumented lifetime-style fields) and records the create request shape and response, so
    /// the evidence is the wire body and the issued certificate's notBefore/notAfter, never just
    /// "the CA accepted it". Every order created is revoked/cancelled in a finally block.
    ///
    /// Gated behind <c>CERTINEXT_PROBE_VALIDITY=1</c> (opt-in-only flag, never promoted from an env
    /// file) plus V2 credentials and Cloudflare DCV credentials. Places roughly 5-7 sandbox orders per
    /// full run. Reads <c>~/.env_certinext_v2</c> itself (do NOT source it into the shell).
    /// </summary>
    public class V2ValidityProbeTests : IClassFixture<IntegrationTestFixture>
    {
        private const string FlagName = "CERTINEXT_PROBE_VALIDITY";

        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;

        private readonly string _v2ApiUrl;
        private readonly string _v2ClientId;
        private readonly string _v2ClientSecret;
        private readonly string _v2ProductCode;
        private readonly string _v2Domain;
        private readonly string _cfApiToken;
        private readonly string _cfZoneId;
        private readonly bool _v2Enabled;
        private readonly bool _dcvEnabled;

        public V2ValidityProbeTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output  = output;

            var env = V2EnvHelper.LoadAndPromote();

            _v2ApiUrl       = V2EnvHelper.GetEnv(env, "CERTINEXT_API_URL");
            _v2ClientId     = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_ID");
            _v2ClientSecret = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_SECRET");
            _v2ProductCode  = V2EnvHelper.GetEnv(env, "CERTINEXT_PRODUCT_CODE", "842");
            _v2Domain       = V2EnvHelper.GetEnv(env, "CERTINEXT_DCV_DOMAIN", "test.example.com");
            _cfApiToken     = V2EnvHelper.GetEnv(env, "CERTINEXT_CF_API_TOKEN");
            _cfZoneId       = V2EnvHelper.GetEnv(env, "CERTINEXT_CF_ZONE_ID");

            _v2Enabled = !string.IsNullOrWhiteSpace(V2EnvHelper.GetEnv(env, "CERTINEXT_USE_V2_API"))
                         && !string.IsNullOrWhiteSpace(_v2ApiUrl)
                         && !string.IsNullOrWhiteSpace(_v2ClientId)
                         && !string.IsNullOrWhiteSpace(_v2ClientSecret);
            _dcvEnabled = _v2Enabled
                          && !string.IsNullOrWhiteSpace(_cfApiToken)
                          && !string.IsNullOrWhiteSpace(_cfZoneId);
        }

        // ---------------------------------------------------------------------------
        // Variants. Each is its own fact so a single variant can be re-run with --filter.
        // ---------------------------------------------------------------------------

        /// <summary>Plugin path, template ValidityDays=45 (the V2 plugin path reads only ValidityYears).</summary>
        [SkippableFact]
        public Task Probe_A_Plugin_TemplateValidityDays45() =>
            RunVariantAsync("A-plugin-days45",
                new Dictionary<string, string> { [Constants.EnrollmentParam.ValidityDays] = "45" },
                mutator: null);

        /// <summary>Control: plugin path, template ValidityYears=1.</summary>
        [SkippableFact]
        public Task Probe_B_Plugin_TemplateValidityYears1_Control() =>
            RunVariantAsync("B-plugin-years1",
                new Dictionary<string, string> { [Constants.EnrollmentParam.ValidityYears] = "1" },
                mutator: null);

        /// <summary>Undocumented <c>subscription.validityDays=45</c> injected next to validityYears=1.</summary>
        [SkippableFact]
        public Task Probe_C_Raw_SubscriptionValidityDays45() =>
            RunVariantAsync("C-sub-validityDays45", null, o =>
            {
                o["subscription"]!.AsObject()["validityDays"] = 45;
            });

        /// <summary>Kitchen sink of undocumented lifetime-ish fields at plausible levels (disjoint from C).</summary>
        [SkippableFact]
        public Task Probe_D_Raw_KitchenSinkLifetimeFields() =>
            RunVariantAsync("D-kitchen-sink", null, o =>
            {
                o["validityDays"] = 45;
                o["certificateValidityDays"] = 45;
                o["lifetimeDays"] = 45;
                o["certificate"]!.AsObject()["validityDays"] = 45;
                o["certificate"]!.AsObject()["lifetimeDays"] = 45;
                o["subscription"]!.AsObject()["lifetimeDays"] = 45;
                o["subscription"]!.AsObject()["certificateValidityDays"] = 45;
            });

        /// <summary><c>subscription.validityYears=0</c> (documented field, out-of-range value).</summary>
        [SkippableFact]
        public Task Probe_E_Raw_ValidityYears0() =>
            RunVariantAsync("E-years0", null, o =>
            {
                o["subscription"]!.AsObject()["validityYears"] = 0;
            });

        /// <summary>Negative control: a field that cannot possibly be meaningful, to learn whether unknown fields are rejected or ignored.</summary>
        [SkippableFact]
        public Task Probe_F_Raw_BogusUnknownField_Control() =>
            RunVariantAsync("F-bogus-field", null, o =>
            {
                o["bogusProbeField"] = 45;
            });

        /// <summary><c>subscription.validityYears=0.1233</c> (45/365): a fractional year in the documented integer field.</summary>
        [SkippableFact]
        public Task Probe_G_Raw_ValidityYearsFractional() =>
            RunVariantAsync("G-years-frac", null, o =>
            {
                o["subscription"]!.AsObject()["validityYears"] = 0.1233;
            });

        /// <summary><c>subscription.validityYears=2</c>: does the documented field change the issued certificate's own lifetime?</summary>
        [SkippableFact]
        public Task Probe_H_Raw_ValidityYears2() =>
            RunVariantAsync("H-years2", null, o =>
            {
                o["subscription"]!.AsObject()["validityYears"] = 2;
            });

        /// <summary>Read-only: dumps the V2 catalog entry shape (keys, validity-like fields, price tiers) for the configured product.</summary>
        [SkippableFact]
        public async Task Probe_I_CatalogEntryShape_ReadOnly()
        {
            Skip.If(Environment.GetEnvironmentVariable(FlagName) != "1",
                $"Opt-in: set {FlagName}=1 to run the certificate-lifetime probe.");
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            using var client = new CERTInextClient(BuildV2Config(_v2ApiUrl));
            var (code, _, content) = await client.ProbeV2GetAsync(Constants.ApiV2.CatalogProductsPath);
            _output.WriteLine($"Catalog HTTP {code}, {content?.Length ?? 0} chars");
            code.Should().Be(200);

            using var doc = JsonDocument.Parse(content ?? string.Empty);
            JsonElement? match = null;
            void Walk(JsonElement e)
            {
                if (match != null) return;
                if (e.ValueKind == JsonValueKind.Object)
                {
                    if (e.TryGetProperty("productCode", out var pc) && pc.ToString() == _v2ProductCode)
                    {
                        match = e;
                        return;
                    }
                    foreach (var p in e.EnumerateObject()) Walk(p.Value);
                }
                else if (e.ValueKind == JsonValueKind.Array)
                {
                    foreach (var i in e.EnumerateArray()) Walk(i);
                }
            }
            Walk(doc.RootElement);

            match.Should().NotBeNull($"catalog must list product {_v2ProductCode}");
            _output.WriteLine($"Catalog entry for {_v2ProductCode}: keys=[{string.Join(",", match!.Value.EnumerateObject().Select(p => p.Name))}]");
            foreach (var p in match.Value.EnumerateObject())
            {
                if (Regex.IsMatch(p.Name, "valid|day|term|year|life|price|period", RegexOptions.IgnoreCase))
                    _output.WriteLine($"  {p.Name} = {Scrub(p.Value.GetRawText())}");
            }
        }

        // ---------------------------------------------------------------------------
        // Engine
        // ---------------------------------------------------------------------------

        private async Task RunVariantAsync(
            string tag, Dictionary<string, string> extraTemplateParams, Action<JsonObject> mutator)
        {
            Skip.If(Environment.GetEnvironmentVariable(FlagName) != "1",
                $"Opt-in: set {FlagName}=1 to place real sandbox orders probing certificate lifetime handling.");
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");
            Skip.If(!_dcvEnabled,
                "CERTINEXT_CF_API_TOKEN + CERTINEXT_CF_ZONE_ID required — probe orders are driven to issuance via real DCV.");

            string suffix = Guid.NewGuid().ToString("N").Substring(0, 8);
            string cn = $"probe45-{suffix}.{_v2Domain}";
            string orderId = null;

            using var proxy = new MutatingProxy(_v2ApiUrl.TrimEnd('/'), mutator);
            var proxiedConfig = BuildV2Config(proxy.BaseUrl);
            using var directClient = new CERTInextClient(BuildV2Config(_v2ApiUrl));
            using var dnsFactory = new CloudflareDomainValidatorFactory(_cfApiToken, _cfZoneId);
            var plugin = new CERTInextCAPlugin(new CERTInextClient(proxiedConfig), dnsFactory, proxiedConfig);

            var productParams = new Dictionary<string, string>
            {
                [Constants.EnrollmentParam.ProductCode] = _v2ProductCode,
                [Constants.EnrollmentParam.ProfileId]   = _v2ProductCode,
            };
            if (extraTemplateParams != null)
                foreach (var kv in extraTemplateParams)
                    productParams[kv.Key] = kv.Value;

            string enrollOutcome;
            EnrollmentResult enrollResult = null;
            try
            {
                try
                {
                    enrollResult = await plugin.Enroll(
                        csr:            GenerateCsrPem(cn),
                        subject:        $"CN={cn}",
                        san:            new Dictionary<string, string[]> { ["dns"] = new[] { cn } },
                        productInfo:    new EnrollmentProductInfo { ProductID = _v2ProductCode, ProductParameters = productParams },
                        requestFormat:  RequestFormat.PKCS10,
                        enrollmentType: EnrollmentType.New);
                    orderId = string.IsNullOrWhiteSpace(enrollResult?.CARequestID) ? null : enrollResult.CARequestID;
                    enrollOutcome = $"returned status={enrollResult?.Status} msg={Scrub(enrollResult?.StatusMessage)}";
                }
                catch (Exception ex)
                {
                    enrollOutcome = $"threw {ex.GetType().Name}: {Scrub(ex.Message)}";
                }

                // Wire evidence for the create call (the proxy only records POST /ssl-certificates).
                var creates = proxy.CreateCaptures;
                _output.WriteLine($"=== {tag} ===");
                _output.WriteLine($"Plugin template params: {string.Join(", ", productParams.Where(k => k.Key.StartsWith("Validity")).Select(k => k.Key + "=" + k.Value))}");
                _output.WriteLine($"Create POSTs observed on the wire: {creates.Count}");
                foreach (var c in creates)
                {
                    _output.WriteLine($"  create request shape : {c.RequestShape}");
                    _output.WriteLine($"  create response      : HTTP {c.Status} {Scrub(c.ResponseBody)}");
                }
                _output.WriteLine($"Enroll outcome: {enrollOutcome}");

                // Order id from the create response is authoritative even if Enroll threw afterwards.
                orderId ??= creates.Select(c => c.OrderId).FirstOrDefault(i => !string.IsNullOrWhiteSpace(i));

                if (orderId == null)
                {
                    _output.WriteLine($"PROBE|{tag}|accepted=NO|orderId=-|createHttp={creates.FirstOrDefault()?.Status}");
                    return;
                }

                // Drive to issuance (DCV retry path runs inside GetSingleRecord for pending orders).
                AnyCAPluginCertificate record = null;
                for (int poll = 1; poll <= 12; poll++)
                {
                    record = await plugin.GetSingleRecord(orderId);
                    _output.WriteLine($"  poll #{poll}: status={record?.Status} certLen={record?.Certificate?.Length ?? 0}");
                    if (record?.Status == (int)EndEntityStatus.GENERATED && !string.IsNullOrWhiteSpace(record.Certificate))
                        break;
                    if (record?.Status == (int)EndEntityStatus.FAILED)
                        break;
                    await Task.Delay(TimeSpan.FromSeconds(15));
                }

                // Raw Track Order (direct, not proxied) so unmodelled fields such as `subscription` are visible.
                var (code, _, content) = await directClient.ProbeV2GetAsync(
                    $"{Constants.ApiV2.SslCertificatesPath}/{orderId}");
                string trackSummary = SummariseTrack(code, content);
                _output.WriteLine($"  Track Order: {trackSummary}");

                string certSummary = "no-cert";
                if (record?.Status == (int)EndEntityStatus.GENERATED && !string.IsNullOrWhiteSpace(record.Certificate))
                {
                    var cert = ParseLeaf(record.Certificate);
                    double days = (cert.NotAfter - cert.NotBefore).TotalDays;
                    certSummary = $"notBefore={cert.NotBefore:O} notAfter={cert.NotAfter:O} lifetimeDays={days:F2}";
                }
                _output.WriteLine($"  Issued cert: {certSummary}");
                _output.WriteLine($"PROBE|{tag}|accepted=YES|orderId={orderId}|{certSummary}|track={trackSummary}");
            }
            finally
            {
                if (orderId != null)
                {
                    var log = new List<string>();
                    bool ok = await V2OrderCleanup.RevokeOrCancelAsync(
                        directClient, orderId, "V2 validity probe cleanup", log.Add);
                    foreach (var l in log) _output.WriteLine("  " + Scrub(l));
                    var (_, finalStatus) = await directClient.ResolveAndTrackOrderV2WithFamilyAsync(orderId);
                    _output.WriteLine($"CLEANUP|{tag}|orderId={orderId}|terminal={ok}|finalStatus={finalStatus?.Status}");
                    ok.Should().BeTrue($"probe order {orderId} must be revoked/cancelled");
                }
                else
                {
                    _output.WriteLine($"CLEANUP|{tag}|no order created, nothing to clean up");
                }
            }
        }

        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

        private CERTInextConfig BuildV2Config(string apiUrl) =>
            new CERTInextConfig
            {
                ApiUrl            = apiUrl,
                UseV2Api          = true,
                V2InlineCsr       = V2EnvHelper.InlineCsrFromEnv,
                OAuthClientId     = _v2ClientId,
                OAuthClientSecret = _v2ClientSecret,

                RequestorName         = _fixture.IsConfigured ? _fixture.Config.RequestorName : "Keyfactor Test",
                RequestorEmail        = _fixture.IsConfigured ? _fixture.Config.RequestorEmail : "test@example.com",
                RequestorIsdCode      = "1",
                RequestorMobileNumber = "0000000000",
                SignerPlace           = "Gateway Lab",
                SignerIp              = "127.0.0.1",

                PageSize                   = 100,
                V2SyncLookbackHours        = 2,
                DcvEnabled                 = true,
                DcvPropagationDelaySeconds = 5,
                DcvTimeoutMinutes          = 3
            };

        private static string GenerateCsrPem(string commonName)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 2048));
            var keyPair = keyGen.GenerateKeyPair();
            var csr = new Pkcs10CertificationRequest(
                "SHA256withRSA", new X509Name($"CN={commonName}"), keyPair.Public, null, keyPair.Private);
            return "-----BEGIN CERTIFICATE REQUEST-----\n"
                + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                + "\n-----END CERTIFICATE REQUEST-----";
        }

        private static Org.BouncyCastle.X509.X509Certificate ParseLeaf(string pem)
        {
            var m = Regex.Match(pem, "-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", RegexOptions.Singleline);
            string b64 = (m.Success ? m.Groups[1].Value : pem)
                .Replace("\r", string.Empty).Replace("\n", string.Empty).Trim();
            return new X509CertificateParser().ReadCertificate(Convert.FromBase64String(b64));
        }

        /// <summary>Redacts e-mail addresses and truncates to 500 chars before anything is printed.</summary>
        private static string Scrub(string s)
        {
            if (string.IsNullOrEmpty(s)) return s;
            s = Regex.Replace(s, @"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", "<email>");
            return s.Length > 500 ? s.Substring(0, 500) + "...(truncated)" : s;
        }

        /// <summary>Only non-PII Track Order fields: status, issuedAt, expiresAt, subscription, and the top-level key names.</summary>
        private static string SummariseTrack(int httpStatus, string content)
        {
            if (string.IsNullOrWhiteSpace(content)) return $"HTTP {httpStatus} <empty>";
            try
            {
                using var doc = JsonDocument.Parse(content);
                var root = doc.RootElement;
                string Get(string n) => root.TryGetProperty(n, out var v) ? v.ToString() : "-";
                string sub = root.TryGetProperty("subscription", out var s) ? s.GetRawText() : "<absent>";
                string keys = string.Join(",", root.EnumerateObject().Select(p => p.Name));
                return $"HTTP {httpStatus} status={Get("status")} issuedAt={Get("issuedAt")} expiresAt={Get("expiresAt")} " +
                       $"subscription={Scrub(sub)} keys=[{keys}]";
            }
            catch (Exception ex)
            {
                return $"HTTP {httpStatus} <unparseable: {ex.GetType().Name}>";
            }
        }

        /// <summary>
        /// Allow-listed rendering of an order-create body. Requestor / TPOC / agreement / organization /
        /// certificate / delegation blocks and csr / remarks / recipient e-mails are reduced to their
        /// key names so no personal data reaches the test output. <c>subscription</c> and every other
        /// scalar are printed in full.
        /// </summary>
        private static string Shape(JsonObject body)
        {
            var keysOnly = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                { "requestor", "technicalPointOfContact", "agreement", "organization", "certificate", "delegation" };
            var hidden = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                { "csr", "remarks", "recipientEmails", "tags", "groupNumber" };
            var sb = new StringBuilder("{");
            foreach (var kv in body)
            {
                if (sb.Length > 1) sb.Append(", ");
                if (hidden.Contains(kv.Key))
                    sb.Append($"\"{kv.Key}\":<hidden>");
                else if (keysOnly.Contains(kv.Key) && kv.Value is JsonObject jo)
                    sb.Append($"\"{kv.Key}\":{{keys:[{string.Join(",", jo.Select(p => p.Key))}]}}");
                else
                    sb.Append($"\"{kv.Key}\":{kv.Value?.ToJsonString()}");
            }
            return sb.Append('}').ToString();
        }

        // ---------------------------------------------------------------------------
        // Loopback pass-through proxy (records / mutates only the order-create POST)
        // ---------------------------------------------------------------------------

        private sealed class CreateCapture
        {
            public string RequestShape;
            public int Status;
            public string ResponseBody;
            public string OrderId;
        }

        private sealed class MutatingProxy : IDisposable
        {
            private readonly string _upstreamBase;
            private readonly Action<JsonObject> _mutator;
            private readonly HttpListener _listener = new HttpListener();
            private readonly HttpClient _upstream;
            private readonly List<CreateCapture> _creates = new List<CreateCapture>();
            private readonly CancellationTokenSource _cts = new CancellationTokenSource();

            public string BaseUrl { get; }

            public List<CreateCapture> CreateCaptures
            {
                get { lock (_creates) return _creates.ToList(); }
            }

            public MutatingProxy(string upstreamBase, Action<JsonObject> mutator)
            {
                _upstreamBase = upstreamBase;
                _mutator = mutator;
                _upstream = new HttpClient(new HttpClientHandler
                {
                    AutomaticDecompression = DecompressionMethods.All
                }) { Timeout = TimeSpan.FromSeconds(120) };

                var probe = new TcpListener(IPAddress.Loopback, 0);
                probe.Start();
                int port = ((IPEndPoint)probe.LocalEndpoint).Port;
                probe.Stop();

                BaseUrl = $"http://127.0.0.1:{port}";
                _listener.Prefixes.Add(BaseUrl + "/");
                _listener.Start();
                _ = Task.Run(AcceptLoopAsync);
            }

            private async Task AcceptLoopAsync()
            {
                while (!_cts.IsCancellationRequested && _listener.IsListening)
                {
                    HttpListenerContext ctx;
                    try { ctx = await _listener.GetContextAsync(); }
                    catch { return; }
                    _ = Task.Run(() => HandleAsync(ctx));
                }
            }

            private async Task HandleAsync(HttpListenerContext ctx)
            {
                try
                {
                    byte[] reqBody;
                    using (var ms = new MemoryStream())
                    {
                        await ctx.Request.InputStream.CopyToAsync(ms);
                        reqBody = ms.ToArray();
                    }

                    string path = ctx.Request.Url!.AbsolutePath;
                    bool isCreate = string.Equals(ctx.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase)
                                    && string.Equals(path.TrimEnd('/'), Constants.ApiV2.SslCertificatesPath, StringComparison.Ordinal);

                    string capturedShape = null;
                    if (isCreate && reqBody.Length > 0)
                    {
                        var obj = JsonNode.Parse(reqBody)!.AsObject();
                        _mutator?.Invoke(obj);
                        capturedShape = Shape(obj);
                        reqBody = Encoding.UTF8.GetBytes(obj.ToJsonString());
                    }

                    using var up = new HttpRequestMessage(new HttpMethod(ctx.Request.HttpMethod), _upstreamBase + ctx.Request.RawUrl);
                    foreach (string name in ctx.Request.Headers.AllKeys)
                    {
                        if (name == null) continue;
                        string lower = name.ToLowerInvariant();
                        if (lower is "host" or "content-length" or "connection" or "transfer-encoding"
                                  or "accept-encoding" or "expect" or "content-type" or "keep-alive")
                            continue;
                        up.Headers.TryAddWithoutValidation(name, ctx.Request.Headers[name]);
                    }
                    if (reqBody.Length > 0 || ctx.Request.ContentType != null)
                    {
                        var content = new ByteArrayContent(reqBody);
                        if (ctx.Request.ContentType != null)
                            content.Headers.TryAddWithoutValidation("Content-Type", ctx.Request.ContentType);
                        up.Content = content;
                    }

                    using var resp = await _upstream.SendAsync(up);
                    byte[] respBody = await resp.Content.ReadAsByteArrayAsync();

                    if (isCreate)
                    {
                        string text = Encoding.UTF8.GetString(respBody);
                        string orderId = null;
                        try
                        {
                            using var d = JsonDocument.Parse(text);
                            if (d.RootElement.TryGetProperty("orderId", out var o)) orderId = o.GetString();
                        }
                        catch { /* error body or non-JSON */ }
                        lock (_creates)
                            _creates.Add(new CreateCapture
                            {
                                RequestShape = capturedShape,
                                Status = (int)resp.StatusCode,
                                ResponseBody = text,
                                OrderId = orderId
                            });
                    }

                    ctx.Response.StatusCode = (int)resp.StatusCode;
                    if (resp.Content.Headers.ContentType != null)
                        ctx.Response.ContentType = resp.Content.Headers.ContentType.ToString();
                    if (resp.Headers.Location != null)
                        ctx.Response.RedirectLocation = resp.Headers.Location.ToString();
                    ctx.Response.ContentLength64 = respBody.Length;
                    await ctx.Response.OutputStream.WriteAsync(respBody, 0, respBody.Length);
                    ctx.Response.Close();
                }
                catch
                {
                    try { ctx.Response.StatusCode = 502; ctx.Response.Close(); } catch { /* already closed */ }
                }
            }

            public void Dispose()
            {
                _cts.Cancel();
                try { _listener.Stop(); _listener.Close(); } catch { /* best effort */ }
                _upstream.Dispose();
                _cts.Dispose();
            }
        }
    }
}
#endif
