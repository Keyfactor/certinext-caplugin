// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0
//
// Live-DNS validation for issue 0006's CnameResolver. This deliberately does NOT go through
// CERTInext order placement (which is currently blocked by sandbox credit exhaustion, issue
// 0004) — it stages real CNAME records in the same Cloudflare zone used for DCV tests and
// exercises the production Dcv.CnameResolver directly against public DNS, to confirm the
// DnsClient.NET-backed resolution actually works end-to-end (as opposed to only the
// hop-walking algorithm, which the unit tests already cover via a fake single-hop delegate).

using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.CERTInext.Dcv;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    public class CnameResolverLiveDnsTests : IClassFixture<IntegrationTestFixture>, IAsyncLifetime
    {
        private const string CfApiBase = "https://api.cloudflare.com/client/v4";

        private readonly IntegrationTestFixture _fixture;
        private HttpClient _http;
        private string _hopAName;
        private string _hopBName;
        private string _hopCName;
        private string _hopARecordId;
        private string _hopBRecordId;

        public CnameResolverLiveDnsTests(IntegrationTestFixture fixture)
        {
            _fixture = fixture;
        }

        public Task InitializeAsync() => Task.CompletedTask;

        public async Task DisposeAsync()
        {
            if (_http == null)
                return;

            foreach (var recordId in new[] { _hopARecordId, _hopBRecordId })
            {
                if (string.IsNullOrEmpty(recordId))
                    continue;
                try
                {
                    await _http.DeleteAsync($"{CfApiBase}/zones/{_fixture.CloudflareZoneId}/dns_records/{recordId}");
                }
                catch
                {
                    // best-effort cleanup
                }
            }

            _http.Dispose();
        }

        private async Task<string> CreateCnameRecordAsync(string name, string target)
        {
            var payload = new { type = "CNAME", name, content = target, ttl = 60, proxied = false };
            var response = await _http.PostAsJsonAsync($"{CfApiBase}/zones/{_fixture.CloudflareZoneId}/dns_records", payload);
            string body = await response.Content.ReadAsStringAsync();
            Assert.True(response.IsSuccessStatusCode, $"Cloudflare CNAME creation failed for '{name}': {body}");

            using var doc = JsonDocument.Parse(body);
            Assert.True(doc.RootElement.GetProperty("success").GetBoolean(), $"Cloudflare reported failure: {body}");
            return doc.RootElement.GetProperty("result").GetProperty("id").GetString();
        }

        /// <summary>
        /// Two-hop live chain: hopA → hopB → hopC (hopC is never created, so it is terminal —
        /// exactly like a delegated validation zone whose target has no further CNAME). Confirms
        /// the production <see cref="CnameResolver"/> (real DnsClient.NET queries against the
        /// OS-configured resolver) walks a real, publicly-resolvable CNAME chain correctly.
        /// </summary>
        [SkippableFact]
        public async Task ResolveTerminalNameAsync_FollowsRealTwoHopCnameChain()
        {
            Skip.If(!_fixture.IsCloudflareConfigured,
                "CERTINEXT_CF_API_TOKEN / CERTINEXT_CF_ZONE_ID / CERTINEXT_DCV_DOMAIN are required.");

            string baseDomain = IntegrationTestData.DcvTestDomain;
            string suffix = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
            _hopAName = $"_cname-resolver-test-a-{suffix}.{baseDomain}";
            _hopBName = $"_cname-resolver-test-b-{suffix}.{baseDomain}";
            _hopCName = $"_cname-resolver-test-c-{suffix}.{baseDomain}";

            _http = new HttpClient();
            _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _fixture.CloudflareApiToken);

            _hopARecordId = await CreateCnameRecordAsync(_hopAName, _hopBName);
            _hopBRecordId = await CreateCnameRecordAsync(_hopBName, _hopCName);

            var resolver = new CnameResolver();

            // Freshly-created records can take a few seconds to propagate across Cloudflare's
            // edge / the resolver's negative-cache TTL, and a not-yet-propagated record reads as
            // "no CNAME" (a clean terminal result, not an exception) rather than an error — so
            // retry until the expected terminal name is reached, not just on thrown exceptions.
            string terminal = null;
            Exception lastError = null;
            for (int attempt = 0; attempt < 8; attempt++)
            {
                await Task.Delay(TimeSpan.FromSeconds(3));
                try
                {
                    terminal = await resolver.ResolveTerminalNameAsync(_hopAName, CancellationToken.None);
                    if (string.Equals(terminal.TrimEnd('.'), _hopCName.TrimEnd('.'), StringComparison.OrdinalIgnoreCase))
                        break;
                }
                catch (Exception ex)
                {
                    lastError = ex;
                }
            }

            Assert.True(terminal != null, $"Failed to resolve after retries: {lastError}");
            Assert.Equal(_hopCName.TrimEnd('.'), terminal.TrimEnd('.'), ignoreCase: true);
        }

        /// <summary>
        /// A name with no CNAME record at all (the DCV domain apex, which is expected to carry
        /// ordinary A/AAAA/TXT records for the existing DCV integration tests, not a CNAME) must
        /// resolve to itself unchanged — confirms the "terminal on first hop" path against real
        /// DNS, not just the fake-delegate unit tests.
        /// </summary>
        [SkippableFact]
        public async Task ResolveTerminalNameAsync_NoCname_ReturnsInputUnchanged()
        {
            Skip.If(!_fixture.IsCloudflareConfigured,
                "CERTINEXT_CF_API_TOKEN / CERTINEXT_CF_ZONE_ID / CERTINEXT_DCV_DOMAIN are required.");

            string baseDomain = IntegrationTestData.DcvTestDomain;
            var resolver = new CnameResolver();

            string terminal = await resolver.ResolveTerminalNameAsync(baseDomain, CancellationToken.None);

            Assert.Equal(baseDomain.TrimEnd('.'), terminal.TrimEnd('.'), ignoreCase: true);
        }
    }
}
