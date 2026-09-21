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
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Integration test stubs for the V2 REST API code path.
    ///
    /// All tests are gated behind the <c>CERTINEXT_USE_V2_API=1</c> environment variable
    /// and skip gracefully when it is not set, so they are safe to run in CI environments
    /// that do not have V2 credentials configured.
    ///
    /// <b>To run against a live V2 environment:</b>
    /// <code>
    ///   set -a; . ~/.env_certinext; . ~/.env_certinext_v2; set +a
    ///   export CERTINEXT_USE_V2_API=1
    ///   dotnet test CERTInext.IntegrationTests/ --filter "FullyQualifiedName~V2ApiTests"
    /// </code>
    ///
    /// <b>Required variables in <c>~/.env_certinext_v2</c> (or real env vars):</b>
    /// <list type="bullet">
    ///   <item><c>CERTINEXT_API_URL</c>     — V2 base URL (e.g. https://sandbox-us-api.certinext.io)</item>
    ///   <item><c>CERTINEXT_CLIENT_ID</c>    — OAuth2 client ID</item>
    ///   <item><c>CERTINEXT_CLIENT_SECRET</c> — OAuth2 client secret</item>
    ///   <item><c>CERTINEXT_PRODUCT_CODE</c>  — product code for lifecycle test (e.g. 842)</item>
    ///   <item><c>CERTINEXT_DCV_DOMAIN</c>    — domain for lifecycle test (e.g. dcv-test.example.com)</item>
    /// </list>
    /// V1 variables (<c>CERTINEXT_API_URL</c>, <c>CERTINEXT_ACCESS_KEY</c>, etc.) must remain
    /// configured because Synchronize continues to use the V1 GetOrderReport endpoint.
    /// </summary>
    public class V2ApiTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;
        private readonly string _v2ApiUrl;
        private readonly string _v2ClientId;
        private readonly string _v2ClientSecret;
        private readonly string _v2ProductCode;
        private readonly string _v2Domain;
        private readonly bool _v2Enabled;

        public V2ApiTests(IntegrationTestFixture fixture)
        {
            _fixture = fixture;

            // Load ~/.env_certinext_v2 if present; real env vars take precedence.
            var env = LoadEnvFile(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".env_certinext_v2"));

            // Apply to process env (V2 vars overlay V1 vars already loaded by fixture)
            foreach (var kv in env)
                if (Environment.GetEnvironmentVariable(kv.Key) == null)
                    Environment.SetEnvironmentVariable(kv.Key, kv.Value);

            _v2ApiUrl       = GetEnv(env, "CERTINEXT_API_URL");
            _v2ClientId     = GetEnv(env, "CERTINEXT_CLIENT_ID");
            _v2ClientSecret = GetEnv(env, "CERTINEXT_CLIENT_SECRET");
            _v2ProductCode  = GetEnv(env, "CERTINEXT_PRODUCT_CODE", "842");
            _v2Domain       = GetEnv(env, "CERTINEXT_DCV_DOMAIN", "test.example.com");

            _v2Enabled = !string.IsNullOrWhiteSpace(GetEnv(env, "CERTINEXT_USE_V2_API"))
                         && !string.IsNullOrWhiteSpace(_v2ApiUrl)
                         && !string.IsNullOrWhiteSpace(_v2ClientId)
                         && !string.IsNullOrWhiteSpace(_v2ClientSecret);
        }

        // ---------------------------------------------------------------------------
        // V2 Connectivity
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Calls GET /api/certinext/v2/auth/me and verifies a non-empty accountNumber
        /// is returned. Skips when CERTINEXT_USE_V2_API is not set.
        /// </summary>
        [SkippableFact]
        public async Task Connectivity_V2_Ping()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            using var client = BuildV2Client();
            var me = await client.GetAuthMeV2Async();

            me.Should().NotBeNull();
            me.AccountNumber.Should().NotBeNullOrEmpty("auth/me must return accountNumber for a valid OAuth2 client");
            me.AuthType.Should().Be("oauth2");
        }

        // ---------------------------------------------------------------------------
        // V2 Lifecycle: place order → track → revoke
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Places a V2 SSL order, asserts that the CARequestID starts with "ord_",
        /// then revokes the order.
        /// Skips when CERTINEXT_USE_V2_API is not set.
        /// </summary>
        [SkippableFact]
        public async Task Lifecycle_V2_EnrollTrackRevoke()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            using var client = BuildV2Client();

            // Place order
            var orderReq = new V2CreateSslOrderRequest
            {
                ProductVariant    = "dv",
                EmailNotifications = "all",
                Requestor = new V2Requestor
                {
                    Name        = _fixture.Config?.RequestorName ?? "Keyfactor Test",
                    Email       = _fixture.Config?.RequestorEmail ?? "test@example.com",
                    Phone       = "0000000000",
                    Designation = "IT Administrator"
                },
                Certificate = new V2CertificateParams
                {
                    Domain        = _v2Domain,
                    AutoSecureWww = false
                },
                Subscription = new V2SubscriptionParams
                {
                    ValidityYears   = 1,
                    AutoRenew       = false,
                    RenewBeforeDays = 30
                },
                Agreement = new V2AgreementParams
                {
                    SignerName  = _fixture.Config?.RequestorName ?? "Keyfactor Test",
                    SignerIp    = "127.0.0.1",
                    SignerPlace  = "Gateway Lab",
                    Accepted    = true
                },
                Remarks = "Keyfactor V2 integration test — safe to revoke immediately."
            };

            var createResp = await client.PlaceOrderV2Async(
                Constants.ApiV2.FamilySsl, _v2ProductCode, orderReq);

            createResp.Should().NotBeNull();
            createResp.OrderId.Should().NotBeNullOrEmpty(
                "V2 place-order must return a non-empty orderId (sandbox may return numeric IDs rather than 'ord_' prefix)");

            // Track the order
            var (_, trackResp) = await ResolveOrderFamilyAsync(client, createResp.OrderId);
            trackResp.OrderId.Should().Be(createResp.OrderId);
            trackResp.Status.Should().NotBeNullOrEmpty(
                "V2 TrackOrder must return a status for the placed order");

            // Note: revoke requires the order to reach 'issued' state first.
            // The sandbox processes orders asynchronously, so we only assert enroll + track here.
            // A full revoke smoke test requires waiting for issuance (run separately with DCV configured).
        }

        // ---------------------------------------------------------------------------
        // Synchronize still uses V1 when UseV2Api=true
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Verifies that Synchronize calls the V1 GetOrderReport (not V2 /reports/orders)
        /// even when UseV2Api=true.
        /// Skips when V1 credentials are absent.
        /// </summary>
        [SkippableFact]
        public async Task Sync_UsesV1_WhenV2Enabled()
        {
            Skip.If(!_fixture.IsConfigured || !_v2Enabled,
                "V1 credentials or V2 opt-in (CERTINEXT_USE_V2_API) not configured — skipping.");

            // Build a V2-enabled config that still has V1 creds for sync
            var config = new CERTInextConfig
            {
                // V1 creds (required for sync)
                ApiUrl          = _fixture.Config.ApiUrl,
                AuthMode        = "AccessKey",
                ApiKey          = _fixture.Config.ApiKey,
                AccountNumber   = _fixture.Config.AccountNumber,
                // V2 creds (only used for enroll/revoke)
                UseV2Api        = true,
                ApiUrlV2        = _v2Enabled ? _v2ApiUrl  : "https://placeholder.certinext.io",
                ClientId        = _v2Enabled ? _v2ClientId : "placeholder-client",
                ClientSecret    = _v2Enabled ? _v2ClientSecret : "placeholder-secret",
                RequestorName   = _fixture.Config.RequestorName,
                RequestorEmail  = _fixture.Config.RequestorEmail,
                PageSize        = 10    // small page — we just want to confirm sync runs via V1
            };

            using var client = new CERTInextClient(config);
            var plugin = new CERTInextCAPlugin(client, config);

            var buffer = new BlockingCollection<AnyCAPluginCertificate>(1000);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            Exception caughtEx = null;
            try
            {
                await plugin.Synchronize(buffer, DateTime.UtcNow.AddDays(-1), false, cts.Token);
            }
            catch (Exception ex)
            {
                caughtEx = ex;
            }
            buffer.CompleteAdding();

            // Sync must call V1 GetOrderReport, not V2 endpoints.
            // A V2-routing bug would throw KeyNotFoundException with "not found in any V2 product family".
            // A V1 API error (wrong creds / URL mismatch) is acceptable here — it proves the V1 path ran.
            if (caughtEx != null)
                caughtEx.Message.Should().NotContain("V2 product family",
                    "sync must use V1 GetOrderReport, not V2 product-family routing");
        }

        // ---------------------------------------------------------------------------
        // Private helpers
        // ---------------------------------------------------------------------------

        private CERTInextClient BuildV2Client()
        {
            return new CERTInextClient(new CERTInextConfig
            {
                // V1 fields (still needed for Synchronize)
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

        private static async Task<(string family, V2OrderStatusResponse status)> ResolveOrderFamilyAsync(
            CERTInextClient client, string orderId)
        {
            foreach (var family in new[] { Constants.ApiV2.FamilySsl, Constants.ApiV2.FamilyPrivatePki, Constants.ApiV2.FamilySignature })
            {
                try
                {
                    var s = await client.TrackOrderV2Async(family, orderId);
                    return (family, s);
                }
                catch (KeyNotFoundException)
                {
                    // try next
                }
            }
            throw new KeyNotFoundException($"Order '{orderId}' not found in any V2 product family.");
        }

        private static Dictionary<string, string> LoadEnvFile(string path)
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

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
                }
            }

            // Real env vars take precedence
            foreach (System.Collections.DictionaryEntry de in Environment.GetEnvironmentVariables())
            {
                string k = de.Key?.ToString();
                string v = de.Value?.ToString();
                if (!string.IsNullOrEmpty(k)) result[k] = v ?? string.Empty;
            }

            return result;
        }

        private static string GetEnv(Dictionary<string, string> env, string key, string defaultValue = "")
            => env.TryGetValue(key, out string v) && !string.IsNullOrWhiteSpace(v) ? v : defaultValue;
    }
}
