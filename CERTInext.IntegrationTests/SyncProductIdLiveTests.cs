// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Issue 0097: the sync's <c>ProductID</c> must be a product name the gateway's templates use. These read-only
    /// probes show how each account catalog maps product codes to <c>productTypeID</c>, which the plugin resolves
    /// to a name. Opt-in: <c>CERTINEXT_SYNC_PRODUCTID_PROBE=1</c>.
    /// </summary>
    public class SyncProductIdLiveTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;
        private readonly Dictionary<string, string> _env;

        public SyncProductIdLiveTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;
            _env = V2EnvHelper.LoadAndPromote();
        }

        private void Print(string api, List<ProductDetail> products)
        {
            _output.WriteLine($"{api} catalog: {products?.Count ?? 0} products");
            foreach (var p in (products ?? new List<ProductDetail>()).OrderBy(p => p.ProductTypeId).ThenBy(p => p.ProductCode))
            {
                string name = CERTInextCAPlugin.ProductNameForTypeId(p.ProductTypeId) ?? "(no plugin product)";
                _output.WriteLine($"  code={p.ProductCode,-6} typeId={p.ProductTypeId,-4} active={p.Active,-5} " +
                                  $"-> {name,-36} catalogName='{p.ProductName}'");
            }
        }

        [SkippableFact]
        public async Task Probe_CatalogCodeToTypeId_V1AndV2_ReadOnly()
        {
            Skip.If(V2EnvHelper.GetEnv(_env, "CERTINEXT_SYNC_PRODUCTID_PROBE") != "1",
                "Requires CERTINEXT_SYNC_PRODUCTID_PROBE=1.");

            if (_fixture.IsConfigured)
                Print("V1", await _fixture.Client.GetProductDetailsAsync(CancellationToken.None));
            else
                _output.WriteLine("V1 not configured; skipped.");

            string apiUrl = V2EnvHelper.GetEnv(_env, "CERTINEXT_API_URL");
            string clientId = V2EnvHelper.GetEnv(_env, "CERTINEXT_CLIENT_ID");
            string clientSecret = V2EnvHelper.GetEnv(_env, "CERTINEXT_CLIENT_SECRET");
            if (string.IsNullOrWhiteSpace(apiUrl) || string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret))
            {
                _output.WriteLine("V2 not configured; skipped.");
                return;
            }
            using var v2 = new CERTInextClient(new CERTInextConfig
            {
                ApiUrl = apiUrl, UseV2Api = true, OAuthClientId = clientId, OAuthClientSecret = clientSecret
            });
            Print("V2", await v2.GetProductDetailsV2Async(CancellationToken.None));
        }

        /// <summary>
        /// Why a gateway row never gets re-saved by the sync: for each order in
        /// <c>CERTINEXT_PROBE_ORDERS</c> (comma-separated), prints its <c>/reports/orders</c> row (or that the report
        /// doesn't list it), the plugin's mapping of that row, and Track Order's status. Read-only.
        /// </summary>
        [SkippableFact]
        public async Task Probe_OrderReportAndTrackStatus_ReadOnly()
        {
            string ids = V2EnvHelper.GetEnv(_env, "CERTINEXT_PROBE_ORDERS");
            Skip.If(V2EnvHelper.GetEnv(_env, "CERTINEXT_SYNC_PRODUCTID_PROBE") != "1" || string.IsNullOrWhiteSpace(ids),
                "Requires CERTINEXT_SYNC_PRODUCTID_PROBE=1 and CERTINEXT_PROBE_ORDERS.");
            var wanted = new HashSet<string>(ids.Split(',', System.StringSplitOptions.RemoveEmptyEntries | System.StringSplitOptions.TrimEntries));

            using var v2 = new CERTInextClient(new CERTInextConfig
            {
                ApiUrl = V2EnvHelper.GetEnv(_env, "CERTINEXT_API_URL"), UseV2Api = true,
                OAuthClientId = V2EnvHelper.GetEnv(_env, "CERTINEXT_CLIENT_ID"),
                OAuthClientSecret = V2EnvHelper.GetEnv(_env, "CERTINEXT_CLIENT_SECRET")
            });

            var rows = new Dictionary<string, API.V2.OrderReportEntryV2>();
            int total = 0;
            await foreach (var row in v2.ListOrdersV2Async())
            {
                total++;
                if (wanted.Contains(row.OrderNumber)) rows[row.OrderNumber] = row;
            }
            _output.WriteLine($"Report rows read: {total}");

            foreach (string id in wanted.OrderBy(x => x))
            {
                string report = "not listed by /reports/orders";
                if (rows.TryGetValue(id, out var r))
                {
                    int? mapped = CERTInextCAPlugin.MapV2ReportStatusToDisposition(r.OrderStatus, r.CertificateStatus);
                    report = $"'{r.OrderStatus} | {r.CertificateStatus}' product={r.ProductCode} orderDate={r.OrderDate} " +
                             $"mapped={(mapped?.ToString() ?? "null (Track fallback)")}";
                }
                string track;
                try
                {
                    var (family, st) = await v2.ResolveAndTrackOrderV2WithFamilyAsync(id);
                    track = $"family={family}, status={st.Status}, orderState={st.OrderState}, certificateState={st.CertificateState}";
                }
                catch (System.Exception ex)
                {
                    track = $"{ex.GetType().Name}: {ex.Message}";
                }
                _output.WriteLine($"{id}: report {report} -> Track: {track}");
            }
        }
    }
}
