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
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Issue 0039 triage probes — READ-ONLY. Every call here is a GET; nothing is placed,
    /// cancelled, revoked or modified.
    ///
    /// <list type="number">
    /// <item><see cref="CustomFields_V2_PerCatalogProduct"/> — for every product in this
    /// account's V2 catalog, calls the spec's "Get Custom Fields for Product"
    /// (<c>GET /catalog/products/{code}/custom-fields</c>) and reports whether any field is
    /// <c>isMandatory="1"</c> (the EMS-918 "Additional information missing" risk).</item>
    /// <item><see cref="Ledger_V2_OrderStatusCrossReference"/> — reads the ledger statement
    /// and the orders report and reports, per order status, how many orders have a ledger
    /// row. Answers "does an order the plugin abandons (pending/cancelled) get billed?".
    /// Only counts and column names are printed — no amounts or invoice numbers.</item>
    /// </list>
    ///
    /// Gated by <c>CERTINEXT_0039_PROBE=1</c> in addition to <c>CERTINEXT_USE_V2_API</c> + V2
    /// credentials (loaded from <c>~/.env_certinext_v2</c> via <see cref="V2EnvHelper"/>).
    /// <code>
    ///   set -a; . ~/.env_certinext; set +a
    ///   export CERTINEXT_USE_V2_API=1 CERTINEXT_0039_PROBE=1
    ///   dotnet test CERTInext.IntegrationTests/CERTInext.IntegrationTests.csproj -c Release \
    ///     --filter "FullyQualifiedName~UnmodeledSpecFeaturesV2Probe" \
    ///     --logger "console;verbosity=detailed" > /tmp/probe0039.log 2>&1
    /// </code>
    /// </summary>
    public class UnmodeledSpecFeaturesV2ProbeTests : IClassFixture<IntegrationTestFixture>
    {
        private const string ProbeFlag = "CERTINEXT_0039_PROBE";
        private const int MaxPages = 5;
        private const int PageSize = 100;

        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;
        private readonly string _v2ApiUrl;
        private readonly string _v2ClientId;
        private readonly string _v2ClientSecret;
        private readonly bool _probeEnabled;

        public UnmodeledSpecFeaturesV2ProbeTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;

            var env = V2EnvHelper.LoadAndPromote();
            _v2ApiUrl = V2EnvHelper.GetEnv(env, "CERTINEXT_API_URL");
            _v2ClientId = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_ID");
            _v2ClientSecret = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_SECRET");

            bool v2Enabled = !string.IsNullOrWhiteSpace(V2EnvHelper.GetEnv(env, "CERTINEXT_USE_V2_API"))
                             && !string.IsNullOrWhiteSpace(_v2ApiUrl)
                             && !string.IsNullOrWhiteSpace(_v2ClientId)
                             && !string.IsNullOrWhiteSpace(_v2ClientSecret);
            _probeEnabled = v2Enabled && V2EnvHelper.GetEnv(env, ProbeFlag) == "1";
        }

        [SkippableFact]
        public async Task CustomFields_V2_PerCatalogProduct()
        {
            Skip.IfNot(_probeEnabled, $"{ProbeFlag}=1 not set (or V2 not enabled) — skipping 0039 custom-fields probe.");

            using var client = BuildV2Client();
            var catalog = await client.GetProductDetailsV2Async();
            _output.WriteLine($"Catalog products (groupNumber scoped={!string.IsNullOrWhiteSpace(_fixture.GroupNumber)}): {catalog.Count}");

            int withMandatory = 0;
            foreach (var product in catalog.Where(p => !string.IsNullOrWhiteSpace(p.ProductCode))
                                           .GroupBy(p => p.ProductCode).Select(g => g.First()))
            {
                string path = $"/api/certinext/v2/catalog/products/{Uri.EscapeDataString(product.ProductCode)}/custom-fields";
                var (status, _, content) = await client.ProbeV2GetAsync(path);
                string header = $"[{product.ProductCode}] typeId={product.ProductTypeId} name='{product.ProductName}'";

                if (status != 200 || string.IsNullOrWhiteSpace(content))
                {
                    _output.WriteLine($"{header} -> HTTP {status}; body: {Truncate(content, 300)}");
                    continue;
                }

                var fields = new List<(string Group, string Name, string FieldId, string Type, string Mandatory)>();
                string shape;
                try
                {
                    using var doc = JsonDocument.Parse(content);
                    shape = DescribeShape(doc.RootElement);
                    CollectFields(doc.RootElement, "(root)", fields);
                }
                catch (JsonException jex)
                {
                    _output.WriteLine($"{header} -> HTTP 200 but non-JSON body ({jex.Message}): {Truncate(content, 300)}");
                    continue;
                }

                var mandatory = fields.Where(f => f.Mandatory == "1").ToList();
                if (mandatory.Count > 0) withMandatory++;
                _output.WriteLine($"{header} -> HTTP 200 shape={shape} fields={fields.Count} mandatory={mandatory.Count}");
                foreach (var f in fields)
                    _output.WriteLine($"    group={f.Group} name='{f.Name}' fieldId={f.FieldId ?? "(none)"} type={f.Type ?? "(none)"} isMandatory={f.Mandatory ?? "(absent)"}");
                if (fields.Count == 0)
                    _output.WriteLine($"    raw: {Truncate(content, 400)}");
            }

            _output.WriteLine($"FINDING: {withMandatory} catalog product(s) report at least one isMandatory=\"1\" custom field.");
        }

        [SkippableFact]
        public async Task Ledger_V2_OrderStatusCrossReference()
        {
            Skip.IfNot(_probeEnabled, $"{ProbeFlag}=1 not set (or V2 not enabled) — skipping 0039 ledger probe.");

            using var client = BuildV2Client();

            var ledgerOrderIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var ledgerKeys = new SortedSet<string>();
            int ledgerRows = 0;
            for (int page = 1; page <= MaxPages; page++)
            {
                var (status, _, content) = await client.ProbeV2GetAsync($"/api/certinext/v2/reports/ledger?page={page}&size={PageSize}");
                if (status != 200)
                {
                    _output.WriteLine($"Ledger page {page}: HTTP {status}; body: {Truncate(content, 300)}");
                    break;
                }
                using var doc = JsonDocument.Parse(content);
                if (page == 1)
                {
                    var root = doc.RootElement;
                    string envelope = root.ValueKind == JsonValueKind.Object
                        ? string.Join(", ", root.EnumerateObject().Select(p =>
                            p.Value.ValueKind == JsonValueKind.Array ? $"{p.Name}:array[{p.Value.GetArrayLength()}]"
                            : p.Value.ValueKind == JsonValueKind.Number ? $"{p.Name}={p.Value}"
                            : $"{p.Name}:{p.Value.ValueKind}"))
                        : root.ValueKind.ToString();
                    _output.WriteLine($"Ledger page 1: HTTP 200 envelope=[{envelope}]");
                }
                if (!doc.RootElement.TryGetProperty("content", out var arr) || arr.ValueKind != JsonValueKind.Array || arr.GetArrayLength() == 0)
                    break;
                foreach (var row in arr.EnumerateArray())
                {
                    ledgerRows++;
                    foreach (var p in row.EnumerateObject()) ledgerKeys.Add(p.Name);
                    foreach (string k in new[] { "orderId", "orderNumber", "requestNumber" })
                        if (row.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(v.GetString()))
                            ledgerOrderIds.Add(v.GetString());
                }
                if (doc.RootElement.TryGetProperty("totalPages", out var tp) && tp.TryGetInt32(out int total) && page >= total)
                    break;
            }
            _output.WriteLine($"Ledger: rows read={ledgerRows}, distinct order/request ids={ledgerOrderIds.Count}, row keys=[{string.Join(", ", ledgerKeys)}]");

            var byStatus = new Dictionary<string, (int Total, int InLedger)>(StringComparer.OrdinalIgnoreCase);
            for (int page = 1; page <= MaxPages; page++)
            {
                var (status, _, content) = await client.ProbeV2GetAsync($"/api/certinext/v2/reports/orders?page={page}&size={PageSize}");
                if (status != 200)
                {
                    _output.WriteLine($"Orders report page {page}: HTTP {status}; body: {Truncate(content, 300)}");
                    break;
                }
                using var doc = JsonDocument.Parse(content);
                if (!doc.RootElement.TryGetProperty("content", out var arr) || arr.ValueKind != JsonValueKind.Array || arr.GetArrayLength() == 0)
                    break;
                foreach (var row in arr.EnumerateArray())
                {
                    string orderStatus = row.TryGetProperty("orderStatus", out var s) && s.ValueKind == JsonValueKind.String ? s.GetString() : "(none)";
                    string certStatus = row.TryGetProperty("certificateStatus", out var c) && c.ValueKind == JsonValueKind.String ? c.GetString() : "(none)";
                    string key = $"orderStatus='{orderStatus}' certificateStatus='{certStatus}'";
                    bool inLedger = new[] { "orderNumber", "requestNumber" }.Any(k =>
                        row.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String && ledgerOrderIds.Contains(v.GetString() ?? string.Empty));
                    byStatus.TryGetValue(key, out var agg);
                    byStatus[key] = (agg.Total + 1, agg.InLedger + (inLedger ? 1 : 0));
                }
                if (doc.RootElement.TryGetProperty("totalPages", out var tp) && tp.TryGetInt32(out int total) && page >= total)
                    break;
            }

            foreach (var kv in byStatus.OrderByDescending(k => k.Value.Total))
                _output.WriteLine($"  {kv.Key}: orders={kv.Value.Total}, withLedgerRow={kv.Value.InLedger}");
            _output.WriteLine("FINDING: see per-status withLedgerRow counts above (ledger ids matched against orderNumber/requestNumber).");
        }

        private static string DescribeShape(JsonElement root)
        {
            if (root.ValueKind != JsonValueKind.Object)
                return root.ValueKind.ToString();
            if (!root.TryGetProperty("customFields", out var cf))
                return $"object[{string.Join(",", root.EnumerateObject().Select(p => p.Name))}]";
            if (cf.ValueKind != JsonValueKind.Array)
                return $"customFields:{cf.ValueKind}";
            if (cf.GetArrayLength() == 0)
                return "customFields:[] (empty)";
            var first = cf[0];
            bool nested = first.ValueKind == JsonValueKind.Object
                          && (first.TryGetProperty("certificateInformation", out _) || first.TryGetProperty("additionalInformation", out _));
            return nested ? "customFields:[{certificateInformation,additionalInformation}] (spec description shape)"
                          : "customFields:[flat rows] (spec example shape)";
        }

        private static void CollectFields(JsonElement el, string group, List<(string, string, string, string, string)> sink)
        {
            if (el.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in el.EnumerateArray()) CollectFields(item, group, sink);
                return;
            }
            if (el.ValueKind != JsonValueKind.Object) return;

            bool looksLikeField = el.TryGetProperty("isMandatory", out _) || el.TryGetProperty("fieldId", out _);
            if (looksLikeField)
            {
                sink.Add((group,
                    Str(el, "name") ?? Str(el, "displayName") ?? Str(el, "fieldName"),
                    Str(el, "fieldId"),
                    Str(el, "type"),
                    Str(el, "isMandatory")));
                return;
            }
            foreach (var p in el.EnumerateObject())
                if (p.Value.ValueKind == JsonValueKind.Array || p.Value.ValueKind == JsonValueKind.Object)
                    CollectFields(p.Value, p.Name, sink);
        }

        private static string Str(JsonElement el, string name)
        {
            if (!el.TryGetProperty(name, out var v)) return null;
            return v.ValueKind == JsonValueKind.String ? v.GetString() : v.GetRawText();
        }

        private CERTInextClient BuildV2Client()
        {
            return new CERTInextClient(new CERTInextConfig
            {
                ApiUrl            = _v2ApiUrl,
                UseV2Api          = true,
                OAuthClientId     = _v2ClientId,
                OAuthClientSecret = _v2ClientSecret,
                GroupNumber       = _fixture.IsConfigured ? _fixture.GroupNumber : null,
                RequestorName     = _fixture.IsConfigured ? _fixture.Config.RequestorName : "Test",
                RequestorEmail    = _fixture.IsConfigured ? _fixture.Config.RequestorEmail : "test@example.com",
                PageSize          = PageSize
            });
        }

        private static string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= maxLength) return value;
            return value.Substring(0, maxLength) + "...(truncated)";
        }
    }
}
