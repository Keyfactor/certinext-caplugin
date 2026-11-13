// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Live checks for the V2 spec follow-ups (issues 0094/0095). Each test has its own opt-in flag on
    /// top of <c>CERTINEXT_USE_V2_API</c>, so one can be run alone. They report what the sandbox does
    /// in the test output even where the sandbox lacks a feature (for example no SSL.com backend), so
    /// the result shows what a customer on the same account shape would hit.
    /// </summary>
    public class V2SpecFollowupsLiveTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;
        private readonly System.Collections.Generic.Dictionary<string, string> _env;
        private readonly string _v2ApiUrl;
        private readonly string _v2ClientId;
        private readonly string _v2ClientSecret;
        private readonly string _v2Domain;
        private readonly bool _v2Enabled;

        public V2SpecFollowupsLiveTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output  = output;
            _env = V2EnvHelper.LoadAndPromote();
            _v2ApiUrl       = V2EnvHelper.GetEnv(_env, "CERTINEXT_API_URL");
            _v2ClientId     = V2EnvHelper.GetEnv(_env, "CERTINEXT_CLIENT_ID");
            _v2ClientSecret = V2EnvHelper.GetEnv(_env, "CERTINEXT_CLIENT_SECRET");
            _v2Domain       = V2EnvHelper.GetEnv(_env, "CERTINEXT_DCV_DOMAIN", "test.example.com");
            _v2Enabled = !string.IsNullOrWhiteSpace(V2EnvHelper.GetEnv(_env, "CERTINEXT_USE_V2_API"))
                         && !string.IsNullOrWhiteSpace(_v2ApiUrl)
                         && !string.IsNullOrWhiteSpace(_v2ClientId)
                         && !string.IsNullOrWhiteSpace(_v2ClientSecret);
        }

        private bool Flag(string name) => V2EnvHelper.GetEnv(_env, name) == "1";

        private CERTInextClient BuildV2Client() =>
            new CERTInextClient(new CERTInextConfig
            {
                ApiUrl            = _v2ApiUrl,
                UseV2Api          = true,
                OAuthClientId     = _v2ClientId,
                OAuthClientSecret = _v2ClientSecret,
                RequestorName  = _fixture.IsConfigured ? _fixture.Config.RequestorName : "Test",
                RequestorEmail = _fixture.IsConfigured ? _fixture.Config.RequestorEmail : "test@example.com",
                SignerIp       = "127.0.0.1",
                SignerPlace    = "Gateway Lab",
                PageSize       = 100
            });

        /// <summary>Top-level key names of the first <c>content[]</c> row, for shape discovery (no values).</summary>
        private static string FirstRowKeys(string json)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("content", out var c) && c.ValueKind == JsonValueKind.Array
                    && c.GetArrayLength() > 0 && c[0].ValueKind == JsonValueKind.Object)
                    return string.Join(", ", c[0].EnumerateObject().Select(p => p.Name));
                return "(no rows)";
            }
            catch (JsonException)
            {
                return "(not JSON)";
            }
        }

        private static int RowCount(string json)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                return doc.RootElement.TryGetProperty("content", out var c) && c.ValueKind == JsonValueKind.Array
                    ? c.GetArrayLength() : -1;
            }
            catch (JsonException)
            {
                return -1;
            }
        }

        // ---------------------------------------------------------------------------
        // 0094 item 1: SSL.com domain-level DCV (read-only)
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Read-only. Runs the plugin's domain lookup on <c>CERTINEXT_DCV_DOMAIN</c> exactly as the DCV
        /// flow does, lists any domains the account has with <c>validatedBy=SSLCOM</c>, and, when one
        /// exists, reads its <c>GET /domains/{id}/dcv</c> to see SSL.com's record shape (method names and
        /// caStatus only; record values are not printed). Publishes and verifies nothing.
        /// Opt-in: <c>CERTINEXT_V2_SSLCOM_DCV_PROBE=1</c>.
        /// </summary>
        [SkippableFact]
        public async Task SslComDomainDcv_LookupAndShape_Probe()
        {
            Skip.If(!_v2Enabled || !Flag("CERTINEXT_V2_SSLCOM_DCV_PROBE"),
                "Requires CERTINEXT_USE_V2_API + V2 credentials and CERTINEXT_V2_SSLCOM_DCV_PROBE=1.");

            using var client = BuildV2Client();

            // 1. The lookup the DCV flow makes for every pending domain.
            var raw = await client.ProbeV2GetAsync(
                $"/api/certinext/v2/domains?search={Uri.EscapeDataString(_v2Domain)}&exactMatch=true");
            _output.WriteLine($"GET /domains?search={_v2Domain}&exactMatch=true -> HTTP {raw.StatusCode}, " +
                              $"rows={RowCount(raw.Content)}, rowKeys=[{FirstRowKeys(raw.Content)}]");
            raw.StatusCode.Should().Be(200, "the DCV flow's domain lookup must work for SSL.com detection");

            var row = await client.FindDomainV2Async(_v2Domain);
            _output.WriteLine(row == null
                ? "FindDomainV2Async: no row for the test domain (emSign path; nothing to detect)."
                : $"FindDomainV2Async: id={(string.IsNullOrEmpty(row.DomainId) ? "(MISSING)" : "present")}, " +
                  $"dcvStatus={row.DcvStatus}, validatedBy={row.ValidatedBy ?? "(absent = emSign)"}");
            if (row != null)
                row.DomainId.Should().NotBeNullOrEmpty("the SSL.com path needs the row id for /domains/{id}/dcv");

            // 2. Does the account have any SSL.com-validated domains at all?
            var sslCom = await client.ProbeV2GetAsync("/api/certinext/v2/domains?validatedBy=SSLCOM&limit=5");
            int sslComRows = RowCount(sslCom.Content);
            _output.WriteLine($"GET /domains?validatedBy=SSLCOM -> HTTP {sslCom.StatusCode}, rows={sslComRows}, " +
                              $"rowKeys=[{FirstRowKeys(sslCom.Content)}]");

            if (sslCom.StatusCode != 200 || sslComRows <= 0)
            {
                _output.WriteLine("RESULT: no SSL.com-validated domains on this account; the SSL.com DCV path " +
                                  "is not verifiable live here. Customers on emSign accounts keep the order-level flow.");
                return;
            }

            // 3. SSL.com's DCV record shape for the first such domain.
            using var doc = JsonDocument.Parse(sslCom.Content);
            var first = doc.RootElement.GetProperty("content")[0];
            string name = first.TryGetProperty("domainName", out var n) ? n.GetString() : null;
            var sslRow = await client.FindDomainV2Async(name);
            _output.WriteLine($"SSL.com domain {name}: validatedBy={sslRow?.ValidatedBy}, dcvStatus={sslRow?.DcvStatus}");
            try
            {
                var details = await client.GetDomainDcvV2Async(sslRow!.DomainId);
                var option = details.SelectDnsTxtOption();
                _output.WriteLine($"GET /domains/{{id}}/dcv: method={details.Method}, caStatus={details.CaStatus}, " +
                                  $"offered=[{details.DescribeOfferedMethods()}], dnsTxtOptionUsable={option != null}, " +
                                  $"recordName={option?.RecordName ?? "(none)"}");
            }
            catch (Exception ex)
            {
                _output.WriteLine($"GET /domains/{{id}}/dcv failed: {ex.Message}");
                _output.WriteLine("RESULT: a customer on this account would see DCV left pending with this warning.");
            }
        }
    }
}
