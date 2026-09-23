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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Read-only discovery probes against the V2 <c>/reports/orders</c> and
    /// <c>/domains</c> endpoints.
    ///
    /// This is a fact-finding GATE ahead of switching V2-mode Synchronize from the V1
    /// GetOrderReport endpoint to V2 reports. It does not place, revoke, or modify any
    /// order or domain. All findings are printed via <see cref="ITestOutputHelper"/> and
    /// must be read from the test's tail output (xUnit buffers it until the test ends).
    ///
    /// Gated by <c>CERTINEXT_V2_REPORT_PROBE=1</c> (in addition to the usual
    /// <c>CERTINEXT_USE_V2_API=1</c> + V2 credentials) so it never runs by accident in CI.
    ///
    /// <b>To run:</b>
    /// <code>
    ///   cd &lt;repo&gt;
    ///   set -a; . ~/.env_certinext; set +a
    ///   export CERTINEXT_USE_V2_API=1 CERTINEXT_V2_REPORT_PROBE=1
    ///   dotnet test CERTInext.IntegrationTests/CERTInext.IntegrationTests.csproj -c Release \
    ///     --filter "FullyQualifiedName~V2ReportProbe" \
    ///     --logger "console;verbosity=detailed" > /tmp/v2_probe.log 2>&1
    /// </code>
    /// Note: the shell must source ONLY ~/.env_certinext (never ~/.env_certinext_v2 — see
    /// issue 0017); this class loads ~/.env_certinext_v2 itself, same pattern as V2ApiTests.
    /// </summary>
    public class V2ReportProbeTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;
        private readonly string _v2ApiUrl;
        private readonly string _v2ClientId;
        private readonly string _v2ClientSecret;
        private readonly string _v2Domain;
        private readonly string _issuedOrderId;
        private readonly bool _v2Enabled;
        private readonly bool _probeEnabled;

        public V2ReportProbeTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;

            // Load ~/.env_certinext_v2 if present, same priority rules as V2ApiTests:
            // V2-file-defined keys override whatever the fixture already promoted into
            // process env (the V1 CERTINEXT_API_URL differs from the V2 base URL).
            string v2Path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".env_certinext_v2");
            var (env, fileKeys) = LoadEnvFile(v2Path);

            foreach (string key in fileKeys)
                if (env.TryGetValue(key, out string fv))
                    Environment.SetEnvironmentVariable(key, fv);

            foreach (var kv in env)
                if (Environment.GetEnvironmentVariable(kv.Key) == null)
                    Environment.SetEnvironmentVariable(kv.Key, kv.Value);

            _v2ApiUrl = GetEnv(env, "CERTINEXT_API_URL");
            _v2ClientId = GetEnv(env, "CERTINEXT_CLIENT_ID");
            _v2ClientSecret = GetEnv(env, "CERTINEXT_CLIENT_SECRET");
            _v2Domain = GetEnv(env, "CERTINEXT_DCV_DOMAIN", "test.example.com");
            _issuedOrderId = GetEnv(env, "CERTINEXT_V2_ISSUED_ORDER_ID");

            _v2Enabled = !string.IsNullOrWhiteSpace(GetEnv(env, "CERTINEXT_USE_V2_API"))
                         && !string.IsNullOrWhiteSpace(_v2ApiUrl)
                         && !string.IsNullOrWhiteSpace(_v2ClientId)
                         && !string.IsNullOrWhiteSpace(_v2ClientSecret);

            _probeEnabled = _v2Enabled && !string.IsNullOrWhiteSpace(GetEnv(env, "CERTINEXT_V2_REPORT_PROBE"));
        }

        // ---------------------------------------------------------------------------
        // Probe 1 + 5: report shape, envelope pagination fields, product/serial/status vocab
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task Probe1_OrdersReport_ShapeAndFieldVocabulary()
        {
            Skip.IfNot(_probeEnabled, "CERTINEXT_V2_REPORT_PROBE not set (or V2 not enabled) — skipping report probe.");

            using var client = BuildV2Client();

            _output.WriteLine("=== Probe 1: GET /reports/orders?page=1&size=50 ===");
            var (status, contentType, content) = await client.ProbeV2GetAsync(
                "/api/certinext/v2/reports/orders?page=1&size=50");

            _output.WriteLine($"HTTP {status} (Content-Type: {contentType})");

            if (status != 200)
            {
                _output.WriteLine($"FINDING: /reports/orders is NOT live (200). Raw body: {Redact(content)}");
                return;
            }

            _output.WriteLine("FINDING: /reports/orders returned 200 — endpoint IS live (contradicts the " +
                               "plugin's current 501 assumption in CERTInextCAPlugin.cs ~862-868).");

            using var doc = JsonDocument.Parse(content);
            var root = doc.RootElement;

            var envelopeKeys = root.EnumerateObject().Select(p => p.Name).ToList();
            _output.WriteLine($"Envelope top-level keys: [{string.Join(", ", envelopeKeys)}]");

            foreach (string field in new[] { "page", "size", "totalElements", "totalPages" })
            {
                if (root.TryGetProperty(field, out var v))
                    _output.WriteLine($"  envelope.{field} = {v} (kind={v.ValueKind})");
                else
                    _output.WriteLine($"  envelope.{field} = <absent>");
            }

            if (!root.TryGetProperty("content", out var contentArr) || contentArr.ValueKind != JsonValueKind.Array)
            {
                _output.WriteLine("FINDING: no 'content' array in the envelope — cannot inspect rows.");
                return;
            }

            int rowCount = contentArr.GetArrayLength();
            _output.WriteLine($"content[] length on this page: {rowCount}");

            var rows = contentArr.EnumerateArray().Take(3).ToList();
            var distinctStatusValues = new SortedSet<string>();
            var sampleRowRaw = string.Empty;

            for (int i = 0; i < rows.Count; i++)
            {
                var row = rows[i];
                var rowKeys = row.EnumerateObject().Select(p => $"{p.Name}:{p.Value.ValueKind}").ToList();
                _output.WriteLine($"row[{i}] fields (name:type): [{string.Join(", ", rowKeys)}]");
                if (i == 0)
                    sampleRowRaw = Redact(row.GetRawText());

                foreach (var statusField in new[] { "orderStatus", "state", "certificateStatus" })
                    if (row.TryGetProperty(statusField, out var sv) && sv.ValueKind == JsonValueKind.String)
                        distinctStatusValues.Add($"{statusField}={sv.GetString()}");
            }

            _output.WriteLine($"Sample row 0 (redacted): {sampleRowRaw}");

            // Spec field table vs example body discrepancy (docs/reference/specs/CERTInext API
            // v2.postman_collection (1).json, item "Orders Report"): field table documents
            // orderStatus/domainName/certificateSerialNumber; the example body instead shows
            // state/identifier/account/group/product. Report which is actually live.
            bool hasTableFields = rows.Any(r => r.TryGetProperty("orderStatus", out _) ||
                                                 r.TryGetProperty("domainName", out _) ||
                                                 r.TryGetProperty("certificateSerialNumber", out _));
            bool hasExampleFields = rows.Any(r => r.TryGetProperty("state", out _) ||
                                                   r.TryGetProperty("identifier", out _));

            _output.WriteLine($"FINDING: spec field-table shape present = {hasTableFields}; " +
                               $"spec example-body shape present = {hasExampleFields}.");

            // Probe 5: does the row carry productCode / serial / cert body link?
            bool hasProductCode = rows.Any(r => r.TryGetProperty("productCode", out _) || r.TryGetProperty("product", out _));
            bool hasSerial = rows.Any(r => r.TryGetProperty("certificateSerialNumber", out _));
            bool hasCertLink = rows.Any(r => r.EnumerateObject().Any(p => p.Name.Contains("certificate", StringComparison.OrdinalIgnoreCase)
                                                                            && p.Name.Contains("link", StringComparison.OrdinalIgnoreCase)));
            _output.WriteLine($"FINDING: row carries product/productCode = {hasProductCode}; " +
                               $"certificateSerialNumber = {hasSerial}; a *Link field naming a cert body = {hasCertLink}.");

            // Probe 5 (continued): collect distinct status vocabulary across up to 3 pages.
            var allStatusValues = new SortedSet<string>(distinctStatusValues);
            for (int page = 2; page <= 3; page++)
            {
                var (pStatus, _, pContent) = await client.ProbeV2GetAsync(
                    $"/api/certinext/v2/reports/orders?page={page}&size=50");
                if (pStatus != 200 || string.IsNullOrWhiteSpace(pContent)) break;
                using var pDoc = JsonDocument.Parse(pContent);
                if (!pDoc.RootElement.TryGetProperty("content", out var pArr) || pArr.GetArrayLength() == 0) break;
                foreach (var row in pArr.EnumerateArray())
                    foreach (var statusField in new[] { "orderStatus", "state", "certificateStatus" })
                        if (row.TryGetProperty(statusField, out var sv) && sv.ValueKind == JsonValueKind.String)
                            allStatusValues.Add($"{statusField}={sv.GetString()}");
            }
            _output.WriteLine($"FINDING: distinct status values observed (pages 1-3): [{string.Join(", ", allStatusValues)}]");
        }

        // ---------------------------------------------------------------------------
        // Probe 2: pagination semantics
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task Probe2_OrdersReport_Pagination()
        {
            Skip.IfNot(_probeEnabled, "CERTINEXT_V2_REPORT_PROBE not set (or V2 not enabled) — skipping pagination probe.");

            using var client = BuildV2Client();
            _output.WriteLine("=== Probe 2: pagination semantics ===");

            foreach (var (label, query) in new[]
            {
                ("size=100", "/api/certinext/v2/reports/orders?page=1&size=100"),
                ("size=101 (over max)", "/api/certinext/v2/reports/orders?page=1&size=101"),
                ("page=0", "/api/certinext/v2/reports/orders?page=0&size=10"),
                ("page=1 (baseline)", "/api/certinext/v2/reports/orders?page=1&size=10"),
            })
            {
                var (status, _, content) = await client.ProbeV2GetAsync(query);
                string sizeEcho = "n/a", pageEcho = "n/a";
                if (status == 200 && !string.IsNullOrWhiteSpace(content))
                {
                    using var doc = JsonDocument.Parse(content);
                    if (doc.RootElement.TryGetProperty("size", out var sv)) sizeEcho = sv.ToString();
                    if (doc.RootElement.TryGetProperty("page", out var pv)) pageEcho = pv.ToString();
                }
                _output.WriteLine($"FINDING: {label} -> HTTP {status}, echoed size={sizeEcho}, echoed page={pageEcho}, " +
                                   $"bodySnippet={Redact(Truncate(content, 300))}");
            }
        }

        // ---------------------------------------------------------------------------
        // Probe 3: from/to filter param names + semantics (order date vs issue date)
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task Probe3_OrdersReport_FromToFilters()
        {
            Skip.IfNot(_probeEnabled, "CERTINEXT_V2_REPORT_PROBE not set (or V2 not enabled) — skipping from/to probe.");

            using var v2Client = BuildV2Client();
            _output.WriteLine("=== Probe 3: from/to filters ===");

            // Baseline: unfiltered totalElements.
            var (baseStatus, _, baseContent) = await v2Client.ProbeV2GetAsync(
                "/api/certinext/v2/reports/orders?page=1&size=1");
            long baseTotal = -1;
            if (baseStatus == 200 && !string.IsNullOrWhiteSpace(baseContent))
            {
                using var doc = JsonDocument.Parse(baseContent);
                if (doc.RootElement.TryGetProperty("totalElements", out var te)) baseTotal = te.GetInt64();
            }
            _output.WriteLine($"Baseline (no filter) totalElements = {baseTotal}");

            // Wide bracket per spec format (YYYY-MM-DD) that should include everything.
            var (wideStatus, _, wideContent) = await v2Client.ProbeV2GetAsync(
                "/api/certinext/v2/reports/orders?page=1&size=1&from=2000-01-01&to=2099-12-31");
            long wideTotal = -1;
            if (wideStatus == 200 && !string.IsNullOrWhiteSpace(wideContent))
            {
                using var doc = JsonDocument.Parse(wideContent);
                if (doc.RootElement.TryGetProperty("totalElements", out var te)) wideTotal = te.GetInt64();
            }
            _output.WriteLine($"FINDING: from=2000-01-01&to=2099-12-31 -> HTTP {wideStatus}, totalElements = {wideTotal} " +
                               $"(vs baseline {baseTotal}; equal => from/to accepted with YYYY-MM-DD and don't drop rows).");

            // Narrow bracket in the far past that should exclude everything, to confirm the
            // params actually filter (rather than being silently ignored).
            var (narrowStatus, _, narrowContent) = await v2Client.ProbeV2GetAsync(
                "/api/certinext/v2/reports/orders?page=1&size=1&from=2000-01-01&to=2000-01-02");
            long narrowTotal = -1;
            if (narrowStatus == 200 && !string.IsNullOrWhiteSpace(narrowContent))
            {
                using var doc = JsonDocument.Parse(narrowContent);
                if (doc.RootElement.TryGetProperty("totalElements", out var te)) narrowTotal = te.GetInt64();
            }
            _output.WriteLine($"FINDING: from=2000-01-01&to=2000-01-02 -> HTTP {narrowStatus}, totalElements = {narrowTotal} " +
                               "(if 0, from/to do filter; if unchanged from baseline, they are likely no-ops).");

            // Empirical order-date vs issue-date distinction: pick an issued order from the V1
            // report whose OrderDate we know, and bracket from/to tightly around that date.
            // If the row still appears in a bracket that excludes its (later) issuance date,
            // from/to are filtering on order date, not issue date.
            if (!_fixture.IsConfigured)
            {
                _output.WriteLine("V1 fixture not configured — cannot pick a known-orderDate order to " +
                                   "distinguish order-date vs issue-date filtering. Skipping that sub-probe.");
                return;
            }

            OrderReportSample sample = null;
            await foreach (var entry in _fixture.Client.ListOrdersAsync(pageSize: 20))
            {
                if (!string.IsNullOrWhiteSpace(entry.OrderNumber) &&
                    !string.IsNullOrWhiteSpace(entry.OrderDate) &&
                    DateTime.TryParse(entry.OrderDate, null,
                        System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal,
                        out DateTime parsedOrderDate))
                {
                    sample = new OrderReportSample(entry.OrderNumber, parsedOrderDate);
                    break;
                }
            }

            if (sample == null)
            {
                _output.WriteLine("No V1 order with a parsed OrderDate found in the first page — cannot run the " +
                                   "order-date-vs-issue-date sub-probe.");
                return;
            }

            string from = sample.OrderDate.ToString("yyyy-MM-dd");
            string to = sample.OrderDate.AddDays(1).ToString("yyyy-MM-dd");
            var (bracketStatus, _, bracketContent) = await v2Client.ProbeV2GetAsync(
                $"/api/certinext/v2/reports/orders?page=1&size=50&from={from}&to={to}");
            bool foundInOrderDateBracket = bracketStatus == 200 &&
                                            ContainsOrderNumber(bracketContent, sample.OrderNumber);
            _output.WriteLine($"FINDING: V1 order {Redact(sample.OrderNumber)} (V1 orderDate={sample.OrderDate:u}) " +
                               $"bracketed from={from}&to={to} in V2 report -> present = {foundInOrderDateBracket}. " +
                               "(V1 report has no separate issue-date field to bracket against, so a full " +
                               "order-date-vs-issue-date distinction could not be made empirically in this pass; " +
                               "see report notes.)");
        }

        // ---------------------------------------------------------------------------
        // Probe 4: orderNumber identity between V1 and V2
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task Probe4_OrderNumberIdentity_V1VsV2()
        {
            Skip.IfNot(_probeEnabled, "CERTINEXT_V2_REPORT_PROBE not set (or V2 not enabled) — skipping identity probe.");
            Skip.IfNot(_fixture.IsConfigured, "V1 fixture not configured — cannot compare V1 order numbers.");

            using var v2Client = BuildV2Client();
            _output.WriteLine("=== Probe 4: orderNumber identity (V1 <-> V2) ===");

            // Collect a handful of V1 order numbers.
            var v1OrderNumbers = new List<string>();
            await foreach (var entry in _fixture.Client.ListOrdersAsync(pageSize: 20))
            {
                if (!string.IsNullOrWhiteSpace(entry.OrderNumber))
                    v1OrderNumbers.Add(entry.OrderNumber);
                if (v1OrderNumbers.Count >= 5) break;
            }
            _output.WriteLine($"Collected {v1OrderNumbers.Count} V1 order numbers to compare.");

            // Pull the V2 report (first few pages, capped) to build a set of V2 orderNumbers.
            var v2OrderNumbers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int page = 1; page <= 5; page++)
            {
                var (status, _, content) = await v2Client.ProbeV2GetAsync(
                    $"/api/certinext/v2/reports/orders?page={page}&size=100");
                if (status != 200 || string.IsNullOrWhiteSpace(content)) break;
                using var doc = JsonDocument.Parse(content);
                if (!doc.RootElement.TryGetProperty("content", out var arr) || arr.GetArrayLength() == 0) break;
                foreach (var row in arr.EnumerateArray())
                    if (row.TryGetProperty("orderNumber", out var on) && on.ValueKind == JsonValueKind.String)
                        v2OrderNumbers.Add(on.GetString());
                if (arr.GetArrayLength() < 100) break; // last page
            }
            _output.WriteLine($"Collected {v2OrderNumbers.Count} distinct orderNumbers across up to 5 V2 report pages.");

            int matched = v1OrderNumbers.Count(n => v2OrderNumbers.Contains(n));
            _output.WriteLine($"FINDING: N compared = {v1OrderNumbers.Count}, N matched by exact orderNumber = {matched}.");

            // Cross-check: do V1 order numbers resolve against the V2 TrackOrder endpoint at all
            // (independent of the report), by probing all three V2 product families.
            int trackResolved = 0;
            foreach (var orderNumber in v1OrderNumbers)
            {
                bool resolved = false;
                foreach (var family in new[] { "ssl-certificates", "private-pki-certificates", "signature-certificates" })
                {
                    var (status, _, _) = await v2Client.ProbeV2GetAsync($"/api/certinext/v2/{family}/{orderNumber}");
                    if (status == 200) { resolved = true; break; }
                }
                if (resolved) trackResolved++;
            }
            _output.WriteLine($"FINDING: of {v1OrderNumbers.Count} V1 order numbers, {trackResolved} resolved via " +
                               "V2 GET /{family}/{orderId} (TrackOrder-equivalent) in any product family.");

            // If an order was placed via V2 (CERTINEXT_V2_ISSUED_ORDER_ID), check whether its ID
            // appears in the V2 report and whether it matches the V1 orderNumber format.
            if (!string.IsNullOrWhiteSpace(_issuedOrderId))
            {
                bool v2OrderInReport = v2OrderNumbers.Contains(_issuedOrderId);
                _output.WriteLine($"FINDING: CERTINEXT_V2_ISSUED_ORDER_ID ({Redact(_issuedOrderId)}) present in V2 report = " +
                                   $"{v2OrderInReport}.");
            }
            else
            {
                _output.WriteLine("CERTINEXT_V2_ISSUED_ORDER_ID not set — cannot check a V2-placed order's ID " +
                                   "against V1 orderNumber format.");
            }
        }

        // ---------------------------------------------------------------------------
        // Probe 6: List Domains
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task Probe6_ListDomains_Shape()
        {
            Skip.IfNot(_probeEnabled, "CERTINEXT_V2_REPORT_PROBE not set (or V2 not enabled) — skipping domains probe.");

            using var client = BuildV2Client();
            _output.WriteLine("=== Probe 6: GET /domains?search=<domain>&exactMatch=true ===");

            string query = $"/api/certinext/v2/domains?search={Uri.EscapeDataString(_v2Domain)}&exactMatch=true";
            var (status, contentType, content) = await client.ProbeV2GetAsync(query);
            _output.WriteLine($"HTTP {status} (Content-Type: {contentType})");

            if (status != 200 || string.IsNullOrWhiteSpace(content))
            {
                _output.WriteLine($"FINDING: /domains did not return 200 with a body. Raw: {Redact(content)}");
                return;
            }

            using var doc = JsonDocument.Parse(content);
            var root = doc.RootElement;
            var envelopeKeys = root.EnumerateObject().Select(p => p.Name).ToList();
            _output.WriteLine($"Envelope top-level keys: [{string.Join(", ", envelopeKeys)}]");

            if (!root.TryGetProperty("content", out var arr) || arr.ValueKind != JsonValueKind.Array || arr.GetArrayLength() == 0)
            {
                _output.WriteLine($"FINDING: no matching domain row for search={Redact(_v2Domain)}, exactMatch=true.");
                return;
            }

            var row = arr[0];
            var rowKeys = row.EnumerateObject().Select(p => $"{p.Name}:{p.Value.ValueKind}").ToList();
            _output.WriteLine($"row[0] fields (name:type): [{string.Join(", ", rowKeys)}]");
            _output.WriteLine($"Sample domain row (redacted): {Redact(row.GetRawText())}");

            foreach (string field in new[] { "domainId", "dcvStatus", "validTill", "domainName", "status" })
            {
                if (row.TryGetProperty(field, out var v))
                    _output.WriteLine($"  domain.{field} = {Redact(v.ToString())}");
                else
                    _output.WriteLine($"  domain.{field} = <absent>");
            }
        }

        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

        private sealed class OrderReportSample
        {
            public OrderReportSample(string orderNumber, DateTime orderDate)
            {
                OrderNumber = orderNumber;
                OrderDate = orderDate;
            }

            public string OrderNumber { get; }
            public DateTime OrderDate { get; }
        }

        private static bool ContainsOrderNumber(string reportJson, string orderNumber)
        {
            if (string.IsNullOrWhiteSpace(reportJson)) return false;
            try
            {
                using var doc = JsonDocument.Parse(reportJson);
                if (!doc.RootElement.TryGetProperty("content", out var arr) || arr.ValueKind != JsonValueKind.Array)
                    return false;
                return arr.EnumerateArray().Any(row =>
                    row.TryGetProperty("orderNumber", out var on) &&
                    on.ValueKind == JsonValueKind.String &&
                    string.Equals(on.GetString(), orderNumber, StringComparison.OrdinalIgnoreCase));
            }
            catch (JsonException)
            {
                return false;
            }
        }

        private CERTInextClient BuildV2Client()
        {
            return new CERTInextClient(new CERTInextConfig
            {
                // V1 fields (still needed for construction; not exercised by these probes).
                ApiUrl        = _fixture.IsConfigured ? _fixture.Config.ApiUrl : "https://v1-placeholder.certinext.io",
                AuthMode      = "AccessKey",
                ApiKey        = _fixture.IsConfigured ? _fixture.Config.ApiKey : "placeholder",
                AccountNumber = _fixture.IsConfigured ? _fixture.Config.AccountNumber : "0",
                // V2 fields
                UseV2Api      = true,
                ApiUrlV2      = _v2ApiUrl,
                ClientId      = _v2ClientId,
                ClientSecret  = _v2ClientSecret,
                RequestorName  = _fixture.IsConfigured ? _fixture.Config.RequestorName : "Test",
                RequestorEmail = _fixture.IsConfigured ? _fixture.Config.RequestorEmail : "test@example.com",
                SignerIp       = "127.0.0.1",
                SignerPlace    = "Gateway Lab",
                PageSize       = 100
            });
        }

        /// <summary>
        /// Redacts anything that looks like a token/secret/key value before it's written to
        /// test output. This is a best-effort scrub of raw JSON bodies for a discovery probe —
        /// never log access tokens, client secrets, or API keys.
        /// </summary>
        private static string Redact(string raw)
        {
            if (string.IsNullOrEmpty(raw)) return raw;
            string redacted = raw;
            foreach (string key in new[] { "accessToken", "access_token", "clientSecret", "client_secret", "apiKey", "api_key", "authKey", "token" })
            {
                redacted = System.Text.RegularExpressions.Regex.Replace(
                    redacted,
                    $"\"{System.Text.RegularExpressions.Regex.Escape(key)}\"\\s*:\\s*\"[^\"]*\"",
                    $"\"{key}\":\"***REDACTED***\"",
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            }
            return redacted;
        }

        private static string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= maxLength) return value;
            return value.Substring(0, maxLength) + "...(truncated)";
        }

        private static (Dictionary<string, string> env, HashSet<string> fileKeys) LoadEnvFile(string path)
        {
            var fileKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (System.Collections.DictionaryEntry de in Environment.GetEnvironmentVariables())
            {
                string k = de.Key?.ToString();
                string v = de.Value?.ToString();
                if (!string.IsNullOrEmpty(k)) result[k] = v ?? string.Empty;
            }

            if (File.Exists(path))
            {
                foreach (string rawLine in File.ReadAllLines(path))
                {
                    string line = rawLine.Trim();
                    if (string.IsNullOrEmpty(line) || line.StartsWith("#")) continue;

                    int idx = line.IndexOf('=');
                    if (idx <= 0) continue;

                    string key = line.Substring(0, idx).Trim();
                    string val = line.Substring(idx + 1).Trim().Trim('"').Trim('\'');
                    result[key] = val;
                    fileKeys.Add(key);
                }
            }

            return (result, fileKeys);
        }

        private static string GetEnv(Dictionary<string, string> env, string key, string defaultValue = "")
            => env.TryGetValue(key, out string v) && !string.IsNullOrWhiteSpace(v) ? v : defaultValue;
    }
}
