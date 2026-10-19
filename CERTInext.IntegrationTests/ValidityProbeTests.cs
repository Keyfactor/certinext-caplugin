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

// Probe: can the CERTInext V1 API express a certificate lifetime shorter than one year?
//
// Why: CA/B Forum is shrinking maximum TLS certificate lifetimes (200 days now, 100 days from
// Mar 2027, 47 days from Mar 2029). Today the plugin sends only subscriptionDetails.validity
// ("1"/"2"/"3" = subscription YEARS); a template ValidityDays is converted with ceil(days/365),
// so a 45-day request becomes a 1-year subscription. The V1 spec documents no days/lifetime
// field. This probe gathers live evidence.
//
// Three tests, all opt-in (CERTINEXT_PROBE_VALIDITY=1) because they place real orders:
//
//   Probe_RawValidityVariants           raw GenerateOrderSSL drafts (saveAndHold=1): validity
//                                       "1"/"0"/"45", undocumented lifetime-ish fields at several
//                                       levels, and a pure-nonsense field as the negative control
//                                       for "does the API reject unknown fields at all".
//   Probe_PluginPath_ValidityDays45 /   (SUPPORTS_DCV builds) enroll through the plugin with a
//   Probe_PluginPath_ValidityYears1_    template ValidityDays=45, then ValidityYears=1 (control),
//   Control                             drive DCV to issuance, and report the wire validity and
//                                       the issued certificate's notBefore/notAfter.
//   Probe_UndocumentedFields_Issued /   (SUPPORTS_DCV builds) issue ONE raw order carrying every
//   Probe_RawIssuedControl              undocumented lifetime-ish field (and a field-free control
//                                       through the same harness); if the shotgun certificate comes
//                                       back shorter than the control the API honored one.
//
// Residue: Probe_RawValidityVariants places five saveAndHold drafts that the V1 API cannot cancel
// (RejectOrder / SubmitCSR / TrackOrder all answer EMS-943 for a draft; they sit "On Hold / Setup
// Pending" with no certificate). Probe_CleanupAudit_TodaysVprobeOrders lists them;
// Probe_CleanupSweep_TodaysVprobeOrders retries the cancel. Every issued/pending order is revoked or
// rejected by the test that created it.
//
// Acceptance of an unknown field proves nothing by itself — only the issued certificate's
// notAfter shows whether a field was honored. Every order is cancelled / revoked at the end and
// the final TrackOrder state is printed as the cleanup verification.
//
//   set -a; . ~/.env_certinext; set +a
//   export CERTINEXT_PROBE_VALIDITY=1
//   dotnet test CERTInext.IntegrationTests/CERTInext.IntegrationTests.csproj -c Release \
//     -p:DcvSupport=true --filter "FullyQualifiedName~ValidityProbeTests" \
//     --logger "console;verbosity=detailed" > /tmp/probe45-v1.log 2>&1
//
// (xUnit buffers ITestOutputHelper output until the test ends — read the report at the tail.)
// Test output is passed through TestOutputScrub / key filtering so contact emails and other
// personal data from order payloads never reach it.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;
using Xunit.Abstractions;
#if SUPPORTS_DCV
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.PKI.Enums.EJBCA;
#endif

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    public class ValidityProbeTests : IClassFixture<IntegrationTestFixture>, IDisposable
    {
        private const string OptInFlag = "CERTINEXT_PROBE_VALIDITY";

        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _out;
        private readonly List<IDisposable> _toDispose = new List<IDisposable>();
        private readonly HttpClient _http = new HttpClient { Timeout = TimeSpan.FromSeconds(120) };
        private static readonly SecureRandom Rng = new SecureRandom();

        /// <summary>Every order this class creates; swept by <see cref="CleanupAsync"/>.</summary>
        private readonly List<CreatedOrder> _created = new List<CreatedOrder>();
        private List<string> LastRawShape = new List<string>();

        public ValidityProbeTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _out = output;
        }

        public void Dispose()
        {
            foreach (var d in _toDispose) d.Dispose();
            _toDispose.Clear();
            _http.Dispose();
        }

        private void RequireOptIn()
        {
            IntegrationSkip.IfNotConfigured(_fixture);
            Skip.IfNot(
                Environment.GetEnvironmentVariable(OptInFlag) == "1",
                $"Set {OptInFlag}=1 to run this probe — it places real orders on the configured account.");
        }

        // -------------------------------------------------------------------------------
        // Raw GenerateOrderSSL plumbing
        // -------------------------------------------------------------------------------

        private sealed class CreatedOrder
        {
            public string Label;
            public string OrderNumber;
            public string RequestNumber;
            public bool Issued; // true when it may need RevokeOrder instead of RejectOrder
        }

        private sealed class RawResult
        {
            public string Label;
            public int HttpStatus;
            public bool Accepted;
            public string ErrorCode;
            public string ErrorMessage;
            public string OrderNumber;
            public string RequestNumber;
            public JsonNode Body;
        }

        private static string NewCsrPem(string cn)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(Rng, 2048));
            AsymmetricCipherKeyPair kp = keyGen.GenerateKeyPair();
            var csr = new Pkcs10CertificationRequest(
                "SHA256withRSA", new X509Name($"CN={cn}"), kp.Public, null, kp.Private);
            return "-----BEGIN CERTIFICATE REQUEST-----\n"
                 + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                 + "\n-----END CERTIFICATE REQUEST-----";
        }

        /// <summary>meta block, authKey = SHA256(accessKey + ts + txn) computed with BouncyCastle.</summary>
        private JsonObject BuildMeta()
        {
            string ts = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:sszzz", CultureInfo.InvariantCulture);
            long val = (Rng.NextLong() & long.MaxValue) % 1_000_000_000_000_000_000L + 1L;
            string txn = val.ToString(CultureInfo.InvariantCulture);

            byte[] input = Encoding.UTF8.GetBytes(_fixture.Config.ApiKey + ts + txn);
            var digest = new Org.BouncyCastle.Crypto.Digests.Sha256Digest();
            digest.BlockUpdate(input, 0, input.Length);
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            return new JsonObject
            {
                ["ver"] = "1.0",
                ["ts"] = ts,
                ["txn"] = txn,
                ["accountNumber"] = _fixture.Config.AccountNumber,
                ["authKey"] = Convert.ToHexString(hash).ToLowerInvariant()
            };
        }

        private async Task<(int Http, JsonNode Body)> PostAsync(string path, JsonObject body)
        {
            string url = _fixture.Config.ApiUrl.TrimEnd('/') + "/" + path;
            using var content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
            using var resp = await _http.PostAsync(url, content);
            string text = await resp.Content.ReadAsStringAsync();
            JsonNode parsed = null;
            try { parsed = JsonNode.Parse(text); } catch (Exception) { /* non-JSON body */ }
            return ((int)resp.StatusCode, parsed);
        }

        /// <summary>
        /// A DV SSL order body shaped like the plugin's (same fields, same locations), with
        /// <paramref name="mutate"/> applied before it is sent so a variant can change or add fields.
        /// </summary>
        private JsonObject BuildOrderBody(string cn, string csr, bool saveAndHold, Action<JsonObject> mutate)
        {
            var cfg = _fixture.Config;
            string reqName = string.IsNullOrWhiteSpace(cfg.RequestorName) ? "Keyfactor Integration Test" : cfg.RequestorName;
            string first = reqName.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? reqName;
            string last = reqName.Trim().Contains(' ') ? reqName.Trim().Substring(reqName.Trim().IndexOf(' ')).Trim() : first;

            var details = new JsonObject
            {
                ["productCode"] = cfg.DefaultProductCode,
                ["accountingModel"] = "2",
                ["saveAndHold"] = saveAndHold ? "1" : "0",
                ["emailNotifications"] = "0",
                ["autoSecureWWW"] = "0",
                ["requestorInformation"] = new JsonObject
                {
                    ["requestorName"] = reqName,
                    ["requestorIsdCode"] = "1",
                    ["requestorMobileNumber"] = cfg.RequestorMobileNumber,
                    ["requestorEmail"] = cfg.RequestorEmail
                },
                ["subscriptionDetails"] = new JsonObject
                {
                    ["validity"] = "1",
                    ["autoRenew"] = "0",
                    ["renewCriteria"] = "30"
                },
                ["certificateInformation"] = new JsonObject { ["domainName"] = cn },
                ["technicalPointOfContact"] = new JsonObject
                {
                    ["pocFirstName"] = first,
                    ["pocLastName"] = last,
                    ["pocEmail"] = cfg.RequestorEmail,
                    ["pocIsdCode"] = "1",
                    ["pocMobileNumber"] = cfg.RequestorMobileNumber
                },
                ["agreementDetails"] = new JsonObject
                {
                    ["acceptAgreement"] = "1",
                    ["signerName"] = reqName,
                    ["signerPlace"] = "Gateway",
                    ["signerIP"] = "127.0.0.1"
                },
                ["additionalInformation"] = new JsonObject { ["remarks"] = "validity probe" }
            };
            if (!string.IsNullOrWhiteSpace(cfg.GroupNumber)) details["groupNumber"] = cfg.GroupNumber;
            if (!string.IsNullOrWhiteSpace(cfg.OrganizationNumber))
                details["organizationDetails"] = new JsonObject
                {
                    ["preVetting"] = "1",
                    ["organizationNumber"] = cfg.OrganizationNumber
                };
            if (!string.IsNullOrWhiteSpace(csr)) details["csr"] = csr;

            var root = new JsonObject { ["meta"] = BuildMeta(), ["orderDetails"] = details };
            mutate?.Invoke(root);
            return root;
        }

        private async Task<RawResult> PlaceRawOrderAsync(
            string label, bool saveAndHold, bool withCsr, Action<JsonObject> mutate, bool issuedIntent = false)
        {
            string cn = $"vprobe-{DateTime.UtcNow:HHmmssfff}-{Rng.Next(1000, 9999)}.scrup.org";
            string csr = withCsr ? NewCsrPem(cn) : null;

            (int http, JsonNode body) = (0, null);
            // The sandbox answers burst order placement with "Inactive Account User." — back off and
            // retry with a fresh meta/txn, same as the plugin's client does.
            for (int attempt = 1; attempt <= 4; attempt++)
            {
                var req = BuildOrderBody(cn, csr, saveAndHold, mutate);
                LastRawShape = Shape(req);
                (http, body) = await PostAsync("GenerateOrderSSL", req);
                string msg = body?["meta"]?["errorMessage"]?.ToString() ?? "";
                if (msg.IndexOf("Inactive Account User", StringComparison.OrdinalIgnoreCase) < 0) break;
                await Task.Delay(TimeSpan.FromSeconds(10 * attempt));
            }

            var meta = body?["meta"];
            string status = meta?["status"]?.ToString();
            var result = new RawResult
            {
                Label = label,
                HttpStatus = http,
                Accepted = status == "1",
                ErrorCode = meta?["errorCode"]?.ToString(),
                ErrorMessage = TestOutputScrub.Scrub(meta?["errorMessage"]?.ToString()),
                OrderNumber = body?["orderDetails"]?["orderNumber"]?.ToString(),
                RequestNumber = body?["orderDetails"]?["requestNumber"]?.ToString(),
                Body = body
            };
            if (result.Accepted)
                _created.Add(new CreatedOrder
                {
                    Label = label,
                    OrderNumber = result.OrderNumber,
                    RequestNumber = result.RequestNumber,
                    Issued = issuedIntent
                });

            await Task.Delay(2000); // sandbox rate-limits order bursts
            return result;
        }

        private async Task<JsonNode> RawTrackAsync(string orderNumber)
        {
            var body = new JsonObject
            {
                ["meta"] = BuildMeta(),
                ["orderDetails"] = new JsonObject { ["orderNumber"] = orderNumber }
            };
            return (await PostAsync("TrackOrder", body)).Body;
        }

        // -------------------------------------------------------------------------------
        // Output helpers (no personal data)
        // -------------------------------------------------------------------------------

        private static readonly Regex InterestingKey = new Regex(
            "valid|subscr|expir|term|period|renew|days|before|after|issue|lifetime|status|date|dcv|caa",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static readonly Regex SensitiveKey = new Regex(
            "mail|name|phone|mobile|contact|signer|csr|pem|chain|authkey|poc|requestor|certificate$|endentity",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static void Walk(JsonNode node, string path, List<(string Path, string Value)> leaves)
        {
            switch (node)
            {
                case JsonObject o:
                    foreach (var kv in o) Walk(kv.Value, path.Length == 0 ? kv.Key : path + "." + kv.Key, leaves);
                    break;
                case JsonArray a:
                    for (int i = 0; i < a.Count; i++) Walk(a[i], $"{path}[{i}]", leaves);
                    break;
                case null:
                    leaves.Add((path, "null"));
                    break;
                default:
                    leaves.Add((path, node.ToString()));
                    break;
            }
        }

        /// <summary>
        /// Prints the lifetime/term-relevant leaves of a TrackOrder response (values) and, once,
        /// the full key inventory (paths only) so undocumented fields can be spotted.
        /// </summary>
        private void DumpTrack(string label, JsonNode track, bool inventory)
        {
            var leaves = new List<(string Path, string Value)>();
            Walk(track?["orderDetails"], "orderDetails", leaves);
            _out.WriteLine($"    [{label}] TrackOrder lifetime/term-relevant fields:");
            foreach (var (path, value) in leaves)
            {
                string leafKey = path.Substring(path.LastIndexOf('.') + 1);
                if (InterestingKey.IsMatch(leafKey) && !SensitiveKey.IsMatch(leafKey))
                    _out.WriteLine($"        {path} = {TestOutputScrub.Scrub(value)}");
            }
            if (inventory)
            {
                _out.WriteLine($"    [{label}] TrackOrder key inventory (paths only):");
                _out.WriteLine("        " + string.Join(", ", leaves
                    .Select(l => Regex.Replace(l.Path, @"\[\d+\]", "[]"))
                    .Select(p => Regex.Replace(p, @"domainVerification\.[^.]+", "domainVerification.<domain>"))
                    .Distinct()));
            }
        }

        /// <summary>
        /// Flattens an order body to "path=value" lines (values cut to 40 chars; csr and meta omitted) so the
        /// plugin's real payload and the raw harness payload can be diffed field by field. The plugin payload
        /// comes from the client's own redacted Trace log, so personal data is already masked.
        /// </summary>
        private static List<string> Shape(JsonNode root)
        {
            var leaves = new List<(string Path, string Value)>();
            Walk(root?["orderDetails"], "orderDetails", leaves);
            return leaves
                .Where(l => !l.Path.EndsWith(".csr", StringComparison.Ordinal))
                .Select(l => $"{l.Path}={TestOutputScrub.Scrub(l.Value.Length > 40 ? l.Value.Substring(0, 40) + "..." : l.Value)}")
                .OrderBy(x => x, StringComparer.Ordinal)
                .ToList();
        }

        private static string Evidence(RawResult r) =>
            r.Accepted
                ? $"orderNumber={r.OrderNumber ?? "-"} requestNumber={r.RequestNumber ?? "-"}"
                : $"HTTP {r.HttpStatus} {r.ErrorCode} {r.ErrorMessage}";

        // -------------------------------------------------------------------------------
        // Cleanup
        // -------------------------------------------------------------------------------

        /// <summary>
        /// Cancels (RejectOrder) every created order that is not yet issued and revokes those that
        /// are, then prints each order's final TrackOrder state as the cleanup verification.
        /// </summary>
        private async Task CleanupAsync()
        {
            if (_created.Count == 0) return;
            _out.WriteLine("");
            _out.WriteLine("=== Cleanup ===");
            foreach (var o in _created)
            {
                string id = o.OrderNumber;
                if (string.IsNullOrWhiteSpace(id))
                {
                    // A saveAndHold draft has only a requestNumber. RejectOrder/RevokeOrder/TrackOrder all
                    // key on orderNumber and answer EMS-943 for a requestNumber (observed live), so the V1
                    // API offers no way to cancel a draft. It holds no certificate and consumes no credit.
                    _out.WriteLine($"[{o.Label}] draft requestNumber={o.RequestNumber}: no cancel endpoint accepts a requestNumber — left as a draft");
                    continue;
                }
                try
                {
                    // Re-read state: an order that issued while we waited needs Revoke, not Reject.
                    var before = await RawTrackAsync(id);
                    string st = before?["orderDetails"]?["certificateStatusId"]?.ToString();
                    bool issued = o.Issued || st == "20" || st == "9";

                    // Preferred call first, the other as a fallback: the issued/not-issued guess can be
                    // wrong (an order may issue, or fail to issue, between our check and the call).
                    string[] sequence = issued ? new[] { "RevokeOrder", "RejectOrder" } : new[] { "RejectOrder", "RevokeOrder" };
                    foreach (string call in sequence)
                    {
                        JsonObject payload = call == "RevokeOrder"
                            ? new JsonObject
                            {
                                ["meta"] = BuildMeta(),
                                ["revocationDetails"] = new JsonObject
                                {
                                    ["orderNumber"] = id,
                                    ["requestorEmail"] = _fixture.Config.RequestorEmail,
                                    ["revokeReasonId"] = "5",
                                    ["revokeRemarks"] = "validity probe cleanup"
                                }
                            }
                            : new JsonObject
                            {
                                ["meta"] = BuildMeta(),
                                ["orderDetails"] = new JsonObject
                                {
                                    ["orderNumber"] = id,
                                    ["rejectRemarks"] = "validity probe cleanup"
                                }
                            };
                        var (h, b) = await PostAsync(call, payload);
                        string ok = b?["meta"]?["status"]?.ToString();
                        _out.WriteLine($"[{o.Label}] {id}: {call} -> HTTP {h} status={ok} " +
                                       $"{b?["meta"]?["errorCode"]} {TestOutputScrub.Scrub(b?["meta"]?["errorMessage"]?.ToString())}");
                        if (ok == "1") break;
                        await Task.Delay(1500);
                    }
                }
                catch (Exception ex)
                {
                    _out.WriteLine($"[{o.Label}] {id}: cleanup call threw {TestOutputScrub.Describe(ex)}");
                }
                await Task.Delay(1500);
            }

            _out.WriteLine("--- Cleanup verification (final TrackOrder state) ---");
            var drafts = _created.Where(o => string.IsNullOrWhiteSpace(o.OrderNumber)).ToList();
            if (drafts.Count > 0)
            {
                // Drafts are only visible through GetOrderReport (matched by requestNumber, today's orders).
                var wanted = new HashSet<string>(drafts.Select(d => d.RequestNumber));
                var seen = new Dictionary<string, OrderReportEntry>();
                try
                {
                    await foreach (var e in _fixture.Client.ListOrdersAsync(
                        DateTime.UtcNow.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), 100))
                        if (e.RequestNumber != null && wanted.Contains(e.RequestNumber)) seen[e.RequestNumber] = e;
                }
                catch (Exception ex)
                {
                    _out.WriteLine($"    GetOrderReport lookup threw {TestOutputScrub.Describe(ex)}");
                }
                foreach (var d in drafts)
                {
                    seen.TryGetValue(d.RequestNumber, out var e);
                    _out.WriteLine($"[{d.Label}] draft requestNumber={d.RequestNumber}: " + (e == null
                        ? "not found in GetOrderReport (today)"
                        : $"GetOrderReport orderStatusId={e.OrderStatusId} orderStatus={TestOutputScrub.Scrub(e.OrderStatus)} " +
                          $"certificateStatusId={e.CertificateStatusId} certificateStatus={TestOutputScrub.Scrub(e.CertificateStatus)} orderNumber='{e.OrderNumber}'"));
                }
            }
            foreach (var o in _created)
            {
                string id = o.OrderNumber;
                if (string.IsNullOrWhiteSpace(id)) continue;
                try
                {
                    var t = await RawTrackAsync(id);
                    var d = t?["orderDetails"];
                    _out.WriteLine($"[{o.Label}] {id}: trackStatus={t?["meta"]?["status"]} {t?["meta"]?["errorCode"]} " +
                                   $"certificateStatusId={d?["certificateStatusId"]} certificateStatus={TestOutputScrub.Scrub(d?["certificateStatus"]?.ToString())} " +
                                   $"orderStatus={TestOutputScrub.Scrub(d?["orderStatus"]?.ToString())}");
                }
                catch (Exception ex)
                {
                    _out.WriteLine($"[{o.Label}] {id}: verify threw {TestOutputScrub.Describe(ex)}");
                }
            }
        }

        // -------------------------------------------------------------------------------
        // Test 1: raw request variants (drafts)
        // -------------------------------------------------------------------------------

        [SkippableFact]
        public async Task Probe_RawValidityVariants()
        {
            RequireOptIn();

            var variants = new List<(string Label, Action<JsonObject> Mutate)>
            {
                ("R0 control: validity=\"1\"", root => { }),
                ("R1 validity=\"0\"", root => Sub(root)["validity"] = "0"),
                ("R2 validity=\"45\"", root => Sub(root)["validity"] = "45"),
                ("R3 validity=\"1\" + subscriptionDetails.{validityDays,certificateValidityDays,noOfDays,lifetimeDays}=45", root =>
                {
                    var s = Sub(root);
                    s["validityDays"] = "45"; s["certificateValidityDays"] = "45";
                    s["noOfDays"] = "45"; s["lifetimeDays"] = "45";
                }),
                ("R4 validity=\"1\" + orderDetails.{validityDays,certificateValidityDays,noOfDays,lifetimeDays}=45", root =>
                {
                    var d = Details(root);
                    d["validityDays"] = "45"; d["certificateValidityDays"] = "45";
                    d["noOfDays"] = "45"; d["lifetimeDays"] = "45";
                }),
                ("R5 validity=\"1\" + certificateInformation.{validityDays,noOfDays}=45", root =>
                {
                    var c = CertInfo(root);
                    c["validityDays"] = "45"; c["noOfDays"] = "45";
                }),
                ("R6 negative control: validity=\"1\" + nonsense field orderDetails.zzProbeNonsense=\"x\"", root =>
                    Details(root)["zzProbeNonsense"] = "x"),
            };

            var results = new List<RawResult>();
            try
            {
                foreach (var (label, mutate) in variants)
                    results.Add(await PlaceRawOrderAsync(label, saveAndHold: true, withCsr: false, mutate));

                _out.WriteLine("=== Raw GenerateOrderSSL validity probe (saveAndHold=1 drafts) ===");
                _out.WriteLine($"productCode in use: {_fixture.Config.DefaultProductCode}");
                _out.WriteLine("");
                foreach (var r in results)
                {
                    _out.WriteLine($"[{(r.Accepted ? "ACCEPTED" : "REJECTED")}] {r.Label}");
                    _out.WriteLine($"    {Evidence(r)}");
                }

                // Read back what CERTInext stored for each accepted draft. A draft holds no certificate,
                // so a stored lifetime/term field (if any) is the only observable "was it honored" signal.
                _out.WriteLine("");
                _out.WriteLine("=== TrackOrder read-back of accepted drafts ===");
                bool inventoryDone = false;
                foreach (var r in results.Where(x => x.Accepted))
                {
                    string id = r.OrderNumber;
                    if (string.IsNullOrWhiteSpace(id))
                    {
                        _out.WriteLine($"  {r.Label} -> draft (requestNumber only): TrackOrder keys on orderNumber, so no read-back is possible");
                        continue;
                    }
                    var track = await RawTrackAsync(id);
                    _out.WriteLine($"  {r.Label} -> track meta.status={track?["meta"]?["status"]} {track?["meta"]?["errorCode"]}");
                    DumpTrack(r.Label.Substring(0, 2), track, inventory: !inventoryDone);
                    inventoryDone = true;
                    await Task.Delay(800);
                }
            }
            finally
            {
                await CleanupAsync();
            }

            // The probe reports; the only hard requirement is that the control order was placed,
            // otherwise nothing above is interpretable.
            Assert.True(results[0].Accepted,
                $"Control order (validity=\"1\", saveAndHold=1) was rejected, so the probe proved nothing: {Evidence(results[0])}");
        }

        private static JsonObject Details(JsonObject root) => root["orderDetails"]!.AsObject();
        private static JsonObject CertInfo(JsonObject root) => Details(root)["certificateInformation"]!.AsObject();
        private static JsonObject Sub(JsonObject root) => Details(root)["subscriptionDetails"]!.AsObject();

        // -------------------------------------------------------------------------------
        // Test: does GetProductDetails advertise any validity / lifetime / term attribute?
        // -------------------------------------------------------------------------------

        [SkippableFact]
        public async Task Probe_ProductDetails_LifetimeFields()
        {
            RequireOptIn();

            var body = new JsonObject
            {
                ["meta"] = BuildMeta(),
                ["productDetails"] = new JsonObject
                {
                    ["groupNumber"] = _fixture.Config.GroupNumber ?? "",
                    ["categoryID"] = "",
                    ["productCode"] = _fixture.Config.DefaultProductCode ?? ""
                }
            };
            var (http, resp) = await PostAsync("GetProductDetails", body);
            _out.WriteLine("=== GetProductDetails (product " + _fixture.Config.DefaultProductCode + ") ===");
            _out.WriteLine($"HTTP {http} meta.status={resp?["meta"]?["status"]} {resp?["meta"]?["errorCode"]} {TestOutputScrub.Scrub(resp?["meta"]?["errorMessage"]?.ToString())}");

            var leaves = new List<(string Path, string Value)>();
            Walk(resp?["productDetails"], "productDetails", leaves);
            _out.WriteLine("key inventory (paths only): " + string.Join(", ", leaves
                .Select(l => Regex.Replace(l.Path, @"\[\d+\]", "[]")).Distinct()));
            _out.WriteLine("lifetime/term-relevant values:");
            foreach (var (path, value) in leaves)
            {
                string leafKey = path.Substring(path.LastIndexOf('.') + 1);
                if (Regex.IsMatch(leafKey, "valid|lifetime|term|period|days|renew|subscr|duration|year", RegexOptions.IgnoreCase))
                    _out.WriteLine($"    {path} = {TestOutputScrub.Scrub(value)}");
            }
            Assert.True(resp?["meta"]?["status"]?.ToString() == "1", "GetProductDetails failed");
        }

        // -------------------------------------------------------------------------------
        // Cleanup audit: every order this probe family created has a "vprobe-" domain.
        // -------------------------------------------------------------------------------

        /// <summary>
        /// Lists today's orders (bounded GetOrderReport window, not a history sync) and tallies the
        /// "vprobe-*" ones by status, so a leaked live order is visible after a run.
        /// </summary>
        [SkippableFact]
        public async Task Probe_CleanupAudit_TodaysVprobeOrders()
        {
            RequireOptIn();

            var rows = new List<OrderReportEntry>();
            await foreach (var e in _fixture.Client.ListOrdersAsync(
                DateTime.UtcNow.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), 100))
                if (e.DomainName != null && e.DomainName.StartsWith("vprobe-", StringComparison.OrdinalIgnoreCase))
                    rows.Add(e);

            _out.WriteLine($"=== vprobe-* orders dated today: {rows.Count} ===");
            foreach (var g in rows
                .GroupBy(r => $"orderNumber={(string.IsNullOrWhiteSpace(r.OrderNumber) ? "(draft)" : "assigned")} | " +
                              $"orderStatus={TestOutputScrub.Scrub(r.OrderStatus)} | certificateStatus={TestOutputScrub.Scrub(r.CertificateStatus)}")
                .OrderBy(g => g.Key))
                _out.WriteLine($"    {g.Count(),3} x {g.Key}");

            // Live = has an order number and is neither cancelled/rejected nor revoked.
            var live = rows.Where(r => !string.IsNullOrWhiteSpace(r.OrderNumber)
                && !Regex.IsMatch((r.OrderStatus ?? "") + " " + (r.CertificateStatus ?? ""), "cancel|reject|revoked", RegexOptions.IgnoreCase))
                .ToList();
            _out.WriteLine($"live (non-draft, not cancelled/revoked): {live.Count}");
            foreach (var r in live)
                _out.WriteLine($"    LIVE orderNumber={r.OrderNumber} orderStatus={TestOutputScrub.Scrub(r.OrderStatus)} certificateStatus={TestOutputScrub.Scrub(r.CertificateStatus)}");
        }

        /// <summary>
        /// Sweeps leaked "vprobe-*" orders dated today: RejectOrder for each live (not cancelled / revoked)
        /// one, then re-lists to show the result. Only touches orders whose domain this probe family generated.
        /// </summary>
        [SkippableFact]
        public async Task Probe_CleanupSweep_TodaysVprobeOrders()
        {
            RequireOptIn();

            async Task<List<OrderReportEntry>> LiveAsync()
            {
                var live = new List<OrderReportEntry>();
                await foreach (var e in _fixture.Client.ListOrdersAsync(
                    DateTime.UtcNow.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), 100))
                    if (e.DomainName != null && e.DomainName.StartsWith("vprobe-", StringComparison.OrdinalIgnoreCase)
                        && !Regex.IsMatch((e.OrderStatus ?? "") + " " + (e.CertificateStatus ?? ""), "cancel|reject|revoked", RegexOptions.IgnoreCase))
                        live.Add(e);
                return live;
            }

            var before = await LiveAsync();
            _out.WriteLine($"live vprobe-* orders before sweep: {before.Count}");
            foreach (var e in before)
            {
                string id = !string.IsNullOrWhiteSpace(e.OrderNumber) ? e.OrderNumber : e.RequestNumber;
                var (h, b) = await PostAsync("RejectOrder", new JsonObject
                {
                    ["meta"] = BuildMeta(),
                    ["orderDetails"] = new JsonObject { ["orderNumber"] = id, ["rejectRemarks"] = "validity probe cleanup" }
                });
                _out.WriteLine($"    RejectOrder({id}) [{TestOutputScrub.Scrub(e.OrderStatus)} / {TestOutputScrub.Scrub(e.CertificateStatus)}] -> HTTP {h} " +
                               $"status={b?["meta"]?["status"]} {b?["meta"]?["errorCode"]} {TestOutputScrub.Scrub(b?["meta"]?["errorMessage"]?.ToString())}");

                // A saveAndHold draft answers EMS-943 to RejectOrder. Promote it to a real order by attaching
                // a CSR for its own domain (SubmitCSR), then cancel it.
                if (b?["meta"]?["errorCode"]?.ToString() == "EMS-943")
                {
                    await Task.Delay(1500);
                    var (h2, b2) = await PostAsync("SubmitCSR", new JsonObject
                    {
                        ["meta"] = BuildMeta(),
                        ["orderDetails"] = new JsonObject
                        {
                            ["requestorEmail"] = _fixture.Config.RequestorEmail,
                            ["orderNumber"] = id,
                            ["csr"] = NewCsrPem(e.DomainName)
                        }
                    });
                    _out.WriteLine($"      SubmitCSR({id}) -> HTTP {h2} status={b2?["meta"]?["status"]} {b2?["meta"]?["errorCode"]} " +
                                   $"{TestOutputScrub.Scrub(b2?["meta"]?["errorMessage"]?.ToString())}");
                    await Task.Delay(3000);
                    var (h3, b3) = await PostAsync("RejectOrder", new JsonObject
                    {
                        ["meta"] = BuildMeta(),
                        ["orderDetails"] = new JsonObject { ["orderNumber"] = id, ["rejectRemarks"] = "validity probe cleanup" }
                    });
                    _out.WriteLine($"      RejectOrder({id}) after SubmitCSR -> HTTP {h3} status={b3?["meta"]?["status"]} {b3?["meta"]?["errorCode"]} " +
                                   $"{TestOutputScrub.Scrub(b3?["meta"]?["errorMessage"]?.ToString())}");
                }
                await Task.Delay(1500);
            }

            await Task.Delay(3000);
            var after = await LiveAsync();
            _out.WriteLine($"live vprobe-* orders after sweep: {after.Count}");
            foreach (var e in after)
                _out.WriteLine($"    STILL LIVE {(string.IsNullOrWhiteSpace(e.OrderNumber) ? e.RequestNumber : e.OrderNumber)} " +
                               $"[{TestOutputScrub.Scrub(e.OrderStatus)} / {TestOutputScrub.Scrub(e.CertificateStatus)}]");
        }

#if SUPPORTS_DCV
        // -------------------------------------------------------------------------------
        // DCV plumbing (mirrors DcvLifecycleTests)
        // -------------------------------------------------------------------------------

        private IDomainValidatorFactory BuildDnsFactory()
        {
            if (_fixture.IsCloudflareConfigured)
            {
                var factory = new CloudflareDomainValidatorFactory(
                    _fixture.CloudflareApiToken, _fixture.CloudflareZoneId);
                _toDispose.Add(factory);
                return factory;
            }
            return new StubDomainValidatorFactory();
        }

        private CERTInextCAPlugin BuildPlugin()
        {
            var config = new CERTInextConfig
            {
                ApiUrl                     = _fixture.Config.ApiUrl,
                AuthMode                   = _fixture.Config.AuthMode,
                ApiKey                     = _fixture.Config.ApiKey,
                AccountNumber              = _fixture.Config.AccountNumber,
                GroupNumber                = _fixture.Config.GroupNumber,
                OrganizationNumber         = _fixture.Config.OrganizationNumber,
                RequestorName              = _fixture.Config.RequestorName,
                RequestorEmail             = _fixture.Config.RequestorEmail,
                RequestorIsdCode           = _fixture.Config.RequestorIsdCode,
                RequestorMobileNumber      = _fixture.Config.RequestorMobileNumber,
                SignerPlace                = _fixture.Config.SignerPlace,
                SignerIp                   = _fixture.Config.SignerIp,
                DefaultProductCode         = _fixture.Config.DefaultProductCode,
                PageSize                   = _fixture.Config.PageSize,
                DcvEnabled                 = true,
                DcvPropagationDelaySeconds = 5,
                DcvTimeoutMinutes          = 3
            };
            return new CERTInextCAPlugin(_fixture.Client, BuildDnsFactory(), config);
        }

        /// <summary>Captures every formatted log message (all levels) so the wire payload can be read back.</summary>
        private sealed class CapturingLogger : ILogger
        {
            public readonly List<string> Messages = new List<string>();
            public IDisposable BeginScope<TState>(TState state) => null;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
                Func<TState, Exception, string> formatter)
            {
                lock (Messages) Messages.Add(formatter(state, exception));
            }
        }

        /// <summary>
        /// Extracts the "subscriptionDetails" block from the client's PlaceOrderAsync Trace payload —
        /// the exact validity string that went on the wire. That block carries no personal data.
        /// </summary>
        private static string WireSubscriptionDetails(CapturingLogger log)
        {
            lock (log.Messages)
            {
                foreach (var m in log.Messages.Where(m => m.StartsWith("PlaceOrderAsync request payload:", StringComparison.Ordinal)))
                {
                    var match = Regex.Match(m, "\"subscriptionDetails\"\\s*:\\s*\\{[^}]*\\}");
                    if (match.Success) return match.Value;
                }
            }
            return "(PlaceOrderAsync payload not captured)";
        }

        /// <summary>
        /// Parses the leaf certificate with BouncyCastle. Accepts PEM (with or without the BEGIN/END
        /// markers, first certificate wins) or bare base64 DER.
        /// </summary>
        private static List<string> PluginPayloadShape(CapturingLogger log)
        {
            lock (log.Messages)
            {
                foreach (var m in log.Messages.Where(m => m.StartsWith("PlaceOrderAsync request payload:", StringComparison.Ordinal)))
                {
                    try { return Shape(JsonNode.Parse(m.Substring("PlaceOrderAsync request payload:".Length).Trim())); }
                    catch (Exception) { return new List<string> { "(payload not parseable)" }; }
                }
            }
            return new List<string> { "(PlaceOrderAsync payload not captured)" };
        }

        private static (DateTime NotBefore, DateTime NotAfter)? ParseCertWindow(string pem)
        {
            if (string.IsNullOrWhiteSpace(pem)) return null;
            try
            {
                string b64 = pem;
                int begin = b64.IndexOf("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal);
                if (begin >= 0)
                {
                    b64 = b64.Substring(begin + "-----BEGIN CERTIFICATE-----".Length);
                    int end = b64.IndexOf("-----END CERTIFICATE-----", StringComparison.Ordinal);
                    if (end >= 0) b64 = b64.Substring(0, end);
                }
                b64 = Regex.Replace(b64, @"\s+", "");
                var cert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(Convert.FromBase64String(b64));
                return cert == null ? ((DateTime, DateTime)?)null : (cert.NotBefore.ToUniversalTime(), cert.NotAfter.ToUniversalTime());
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>Drives a pending DV order to issuance via GetSingleRecord's sync-DCV retry (bounded).</summary>
        private async Task<AnyCAPluginCertificate> WaitForIssuanceAsync(CERTInextCAPlugin plugin, string id)
        {
            AnyCAPluginCertificate rec = null;
            for (int pass = 1; pass <= 8; pass++)
            {
                rec = await plugin.GetSingleRecord(id);
                if (rec != null && rec.Status == (int)EndEntityStatus.GENERATED
                    && !string.IsNullOrWhiteSpace(rec.Certificate))
                    return rec;
                _out.WriteLine($"    pass {pass}: status={rec?.Status} — waiting 30s");
                await Task.Delay(TimeSpan.FromSeconds(30));
            }
            return rec;
        }

        private void ReportCert(string label, AnyCAPluginCertificate rec)
        {
            var win = ParseCertWindow(rec?.Certificate);
            if (win == null)
            {
                string c = rec?.Certificate;
                _out.WriteLine($"    [{label}] could not parse certificate (status={rec?.Status}, length={c?.Length ?? 0}, " +
                               $"prefix='{(c == null ? "" : c.Substring(0, Math.Min(27, c.Length)))}')");
                return;
            }
            var (nb, na) = win.Value;
            double days = (na - nb).TotalDays;
            _out.WriteLine($"    [{label}] notBefore={nb:u} notAfter={na:u} lifetime={days:F2} days (~{Math.Round(days)})");
        }

        // -------------------------------------------------------------------------------
        // Test 2: plugin path, ValidityDays=45 vs ValidityYears=1
        // -------------------------------------------------------------------------------

        [SkippableFact]
        public Task Probe_PluginPath_ValidityDays45() =>
            RunPluginPathAsync("P1 template ValidityDays=45",
                new Dictionary<string, string> { ["ValidityDays"] = "45" }, inventory: true);

        [SkippableFact]
        public Task Probe_PluginPath_ValidityYears1_Control() =>
            RunPluginPathAsync("P2 control template ValidityYears=1",
                new Dictionary<string, string> { ["ValidityYears"] = "1" }, inventory: false);

        private async Task RunPluginPathAsync(string label, Dictionary<string, string> extra, bool inventory)
        {
            RequireOptIn();
            Skip.If(!_fixture.IsCloudflareConfigured,
                "CERTINEXT_CF_API_TOKEN + CERTINEXT_CF_ZONE_ID required — issuance needs real DNS-01 DCV.");

            var plugin = BuildPlugin();
            _out.WriteLine("=== Plugin path (DV, DCV on, driven to issuance) ===");
            try
            {
                string suffix = Guid.NewGuid().ToString("N").Substring(0, 8);
                string cn = $"vprobe-{suffix}.scrup.org";
                var pp = new Dictionary<string, string>(extra)
                {
                    ["ProfileId"] = _fixture.Config.DefaultProductCode
                };
                var info = new EnrollmentProductInfo
                {
                    ProductID = _fixture.Config.DefaultProductCode,
                    ProductParameters = pp
                };

                var logger = new CapturingLogger();
                EnrollmentResult res;
                using (CERTInextClientLoggerSwap(logger))
                {
                    res = await plugin.Enroll(
                        csr: NewCsrPem(cn),
                        subject: $"CN={cn}",
                        san: new Dictionary<string, string[]> { ["dns"] = new[] { cn } },
                        productInfo: info,
                        requestFormat: RequestFormat.PKCS10,
                        enrollmentType: EnrollmentType.New);
                }

                _out.WriteLine($"[{label}] params=[{string.Join(", ", extra.Select(kv => kv.Key + "=" + kv.Value))}]");
                _out.WriteLine($"    wire: {WireSubscriptionDetails(logger)}");
                _out.WriteLine("    plugin order payload shape: " + string.Join(" | ", PluginPayloadShape(logger)));
                _out.WriteLine($"    Enroll -> CARequestID={res?.CARequestID} Status={res?.Status}");
                if (!string.IsNullOrWhiteSpace(res?.CARequestID))
                    _created.Add(new CreatedOrder { Label = label, OrderNumber = res.CARequestID, Issued = true });
                Assert.False(string.IsNullOrWhiteSpace(res?.CARequestID), "Enroll returned no CARequestID");

                var rec = await WaitForIssuanceAsync(plugin, res.CARequestID);
                ReportCert(label, rec);
                var track = await RawTrackAsync(res.CARequestID);
                DumpTrack(label.Substring(0, 2), track, inventory);
            }
            finally
            {
                await CleanupAsync();
            }
        }

        private static IDisposable CERTInextClientLoggerSwap(ILogger logger) =>
            Keyfactor.Extensions.CAPlugin.CERTInext.Client.CERTInextClient.OverrideLoggerForTests(logger);

        // -------------------------------------------------------------------------------
        // Test 3: one issued order carrying every undocumented lifetime-ish field
        // -------------------------------------------------------------------------------

        [SkippableFact]
        public Task Probe_UndocumentedFields_Issued() =>
            RunRawIssuedAsync(
                "U1 shotgun (validity=\"1\" + validityDays/certificateValidityDays/noOfDays/lifetimeDays=45 at orderDetails, subscriptionDetails, certificateInformation)",
                root =>
                {
                    foreach (var level in new[] { Details(root), Sub(root), CertInfo(root) })
                    {
                        level["validityDays"] = "45";
                        level["certificateValidityDays"] = "45";
                        level["noOfDays"] = "45";
                        level["lifetimeDays"] = "45";
                    }
                });

        /// <summary>Harness control for the shotgun test: the same raw issued-order path with no extra fields.</summary>
        [SkippableFact]
        public Task Probe_RawIssuedControl() =>
            RunRawIssuedAsync("U0 raw control (validity=\"1\", no extra fields)", root => { });

        /// <summary>Does the issued certificate lifetime track the subscription years? Same harness, validity="3".</summary>
        [SkippableFact]
        public Task Probe_RawIssued_Validity3() =>
            RunRawIssuedAsync("U3 raw validity=\"3\"", root => Sub(root)["validity"] = "3");

        private async Task RunRawIssuedAsync(string label, Action<JsonObject> mutate)
        {
            RequireOptIn();
            Skip.If(!_fixture.IsCloudflareConfigured,
                "CERTINEXT_CF_API_TOKEN + CERTINEXT_CF_ZONE_ID required — issuance needs real DNS-01 DCV.");

            var plugin = BuildPlugin();
            _out.WriteLine("=== Raw (non-plugin) order driven to issuance through the plugin's sync-DCV path ===");
            try
            {
                var r = await PlaceRawOrderAsync(label, saveAndHold: false, withCsr: true, issuedIntent: true, mutate: mutate);
                _out.WriteLine($"[{(r.Accepted ? "ACCEPTED" : "REJECTED")}] {r.Label}");
                _out.WriteLine($"    {Evidence(r)}");
                _out.WriteLine("    raw order payload shape: " + string.Join(" | ", LastRawShape));
                Skip.IfNot(r.Accepted, "Order rejected — see output; nothing to issue.");

                string id = r.OrderNumber;
                Skip.If(string.IsNullOrWhiteSpace(id), "Order accepted but no orderNumber returned (draft?) — cannot drive DCV/issuance.");

                // Mirror what Enroll does for a plugin-placed order: poll TrackOrder until the DCV slot
                // (domainVerification) is exposed and run DCV IMMEDIATELY. Observed live: a raw order whose
                // DCV is attempted late (>=10s) sits in "Pending System RA" and GetDcv answers
                // "Invalid Request for this API", so timing matters, not the request body.
                var polls = 0;
                for (; polls < 60; polls++)
                {
                    var t = await RawTrackAsync(id);
                    if (t?["orderDetails"]?["domainVerification"] is JsonObject dv && dv.Any(kv => kv.Value is JsonObject)) break;
                    await Task.Delay(1000);
                }
                _out.WriteLine($"    DCV slot exposed after {polls} TrackOrder polls (1s apart)");

                var rec = await WaitForIssuanceAsync(plugin, id);
                ReportCert(label.Substring(0, 2), rec);
                DumpTrack(label.Substring(0, 2), await RawTrackAsync(id), inventory: false);
                if (rec == null || rec.Status != (int)EndEntityStatus.GENERATED || string.IsNullOrWhiteSpace(rec.Certificate))
                {
                    var tr = await RawTrackAsync(id);
                    foreach (var d in (tr?["orderDetails"]?["domainVerification"] as JsonObject)?
                        .Where(kv => kv.Value is JsonObject).Select(kv => kv.Key) ?? Enumerable.Empty<string>())
                    {
                        try
                        {
                            var dcv = await _fixture.Client.GetDcvAsync(id, d, "1");
                            _out.WriteLine($"    diag GetDcv({d}) ok, tokenPresent={!string.IsNullOrWhiteSpace(dcv?.DcvDetails?.Token)}");
                        }
                        catch (Exception ex)
                        {
                            _out.WriteLine($"    diag GetDcv({d}) threw {TestOutputScrub.Describe(ex)}");
                        }
                    }
                }
            }
            finally
            {
                await CleanupAsync();
            }
        }
#endif
    }
}
