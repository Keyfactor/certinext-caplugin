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
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Plugin-level integration tests for the V2 (OAuth2) API path — Tiers 1–3 (no DCV
    /// build required). Unlike <see cref="V2ApiTests"/>, which exercises
    /// <see cref="CERTInextClient"/> methods directly, these tests drive the full
    /// <c>IAnyCAPlugin</c> surface (<c>Enroll</c>, <c>Revoke</c>, <c>GetSingleRecord</c>,
    /// <c>Synchronize</c>) the way Keyfactor Command actually calls the plugin.
    ///
    /// All tests are gated behind <c>CERTINEXT_USE_V2_API=1</c> plus valid V2 OAuth2
    /// credentials and skip gracefully otherwise.  See <see cref="V2ApiTests"/> for the
    /// full list of required environment variables.
    /// </summary>
    public class V2LifecycleTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;

        private readonly string _v2ApiUrl;
        private readonly string _v2ClientId;
        private readonly string _v2ClientSecret;
        private readonly string _v2ProductCode;
        private readonly string _v2Domain;
        private readonly bool _v2Enabled;

        public V2LifecycleTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output  = output;

            var env = V2EnvHelper.LoadAndPromote();

            _v2ApiUrl       = V2EnvHelper.GetEnv(env, "CERTINEXT_API_URL");
            _v2ClientId     = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_ID");
            _v2ClientSecret = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_SECRET");
            _v2ProductCode  = V2EnvHelper.GetEnv(env, "CERTINEXT_PRODUCT_CODE", "842");
            _v2Domain       = V2EnvHelper.GetEnv(env, "CERTINEXT_DCV_DOMAIN", "test.example.com");

            _v2Enabled = !string.IsNullOrWhiteSpace(V2EnvHelper.GetEnv(env, "CERTINEXT_USE_V2_API"))
                         && !string.IsNullOrWhiteSpace(_v2ApiUrl)
                         && !string.IsNullOrWhiteSpace(_v2ClientId)
                         && !string.IsNullOrWhiteSpace(_v2ClientSecret);
        }

        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Builds a <see cref="CERTInextConfig"/> wired for the V2 API.  V1 fields are
        /// populated from the fixture's config because <c>Synchronize</c> always uses
        /// the V1 <c>GetOrderReport</c> endpoint regardless of <c>UseV2Api</c>.
        /// </summary>
        private CERTInextConfig BuildV2Config(bool dcvEnabled = false, int? pageSize = null)
        {
            return new CERTInextConfig
            {
                // V1 fields — required so Synchronize (always V1) keeps working.
                ApiUrl             = _fixture.IsConfigured ? _fixture.Config.ApiUrl : "https://v1-placeholder.certinext.io",
                AuthMode           = "AccessKey",
                ApiKey             = _fixture.IsConfigured ? _fixture.Config.ApiKey : "placeholder",
                AccountNumber      = _fixture.IsConfigured ? _fixture.Config.AccountNumber : "0",
                GroupNumber        = _fixture.IsConfigured ? _fixture.Config.GroupNumber : string.Empty,
                OrganizationNumber = _fixture.IsConfigured ? _fixture.Config.OrganizationNumber : string.Empty,
                DefaultProductCode = _fixture.IsConfigured ? _fixture.Config.DefaultProductCode : _v2ProductCode,

                // V2 fields
                UseV2Api     = true,
                ApiUrlV2     = _v2ApiUrl,
                ClientId     = _v2ClientId,
                ClientSecret = _v2ClientSecret,

                RequestorName         = _fixture.IsConfigured ? _fixture.Config.RequestorName : "Keyfactor Test",
                RequestorEmail        = _fixture.IsConfigured ? _fixture.Config.RequestorEmail : "test@example.com",
                RequestorIsdCode      = "1",
                RequestorMobileNumber = "0000000000",
                SignerPlace           = "Gateway Lab",
                SignerIp              = "127.0.0.1",

                PageSize = pageSize ?? 100,

                DcvEnabled                 = dcvEnabled,
                DcvPropagationDelaySeconds = 5,
                DcvTimeoutMinutes          = 3
            };
        }

        /// <summary>
        /// Constructs a plugin instance wired to a real <see cref="CERTInextClient"/>
        /// built from <paramref name="config"/> (or a fresh <see cref="BuildV2Config"/>
        /// if none is supplied). Uses the two-arg test constructor so no
        /// <c>Initialize</c> call is required.
        /// </summary>
        private CERTInextCAPlugin BuildV2Plugin(CERTInextConfig config = null)
        {
            config ??= BuildV2Config();
            var client = new CERTInextClient(config);
            return new CERTInextCAPlugin(client, config);
        }

        /// <summary>
        /// Generates a fresh RSA-2048 PKCS#10 CSR for the given common name using
        /// BouncyCastle only.
        /// </summary>
        private static string GenerateCsrPem(string commonName)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            var keyPair = keyGen.GenerateKeyPair();

            var subject = new X509Name($"CN={commonName}");
            var csr = new Pkcs10CertificationRequest("SHA256withRSA", subject, keyPair.Public, null, keyPair.Private);

            return "-----BEGIN CERTIFICATE REQUEST-----\n"
                + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                + "\n-----END CERTIFICATE REQUEST-----";
        }

        /// <summary>
        /// Runs a full synchronization via the plugin and returns all collected records.
        /// </summary>
        private static async Task<List<AnyCAPluginCertificate>> RunSyncAsync(
            CERTInextCAPlugin plugin, DateTime? lastSync = null, bool fullSync = true)
        {
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(boundedCapacity: 10_000);
            var collected = new List<AnyCAPluginCertificate>();

            var syncTask = Task.Run(async () =>
            {
                await plugin.Synchronize(
                    buffer,
                    lastSync: lastSync,
                    fullSync: fullSync,
                    cancelToken: CancellationToken.None);

                if (!buffer.IsAddingCompleted)
                    buffer.CompleteAdding();
            });

            foreach (var record in buffer.GetConsumingEnumerable())
                collected.Add(record);

            await syncTask;
            return collected;
        }

        /// <summary>
        /// Polls <see cref="CERTInextCAPlugin.GetSingleRecord"/> until the order reaches
        /// GENERATED or FAILED, or the poll budget is exhausted.
        /// </summary>
        private static async Task<AnyCAPluginCertificate> WaitForIssuanceAsync(
            CERTInextCAPlugin plugin, string caRequestId, int maxPolls = 6, int delaySeconds = 15)
        {
            AnyCAPluginCertificate record = null;
            for (int poll = 1; poll <= maxPolls; poll++)
            {
                record = await plugin.GetSingleRecord(caRequestId);
                if (record?.Status == (int)EndEntityStatus.GENERATED
                    || record?.Status == (int)EndEntityStatus.FAILED)
                    break;
                if (poll < maxPolls)
                    await Task.Delay(TimeSpan.FromSeconds(delaySeconds));
            }
            return record;
        }

        private EnrollmentProductInfo BuildV2ProductInfo() =>
            new EnrollmentProductInfo
            {
                ProductID         = _v2ProductCode,
                ProductParameters = new Dictionary<string, string>
                {
                    [Constants.EnrollmentParam.ProductCode] = _v2ProductCode,
                    [Constants.EnrollmentParam.ProfileId]   = _v2ProductCode,
                }
            };

        /// <summary>
        /// Resolves the order ID to exercise for tests that need a pre-existing V2 order.
        /// Reads only <c>CERTINEXT_V2_ORDER_ID</c> — deliberately does not fall back to an
        /// order ID produced by another test in this class, so results do not depend on
        /// test run order (see issues/0017, gap G7).
        /// </summary>
        private static string ResolveOrderId()
            => Environment.GetEnvironmentVariable("CERTINEXT_V2_ORDER_ID");

        // ---------------------------------------------------------------------------
        // Gap 1 — Enroll() via the plugin, V2 path
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task Enroll_V2_ReturnsCARequestID()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            var plugin = BuildV2Plugin();

            var result = await plugin.Enroll(
                csr:            GenerateCsrPem(_v2Domain),
                subject:        $"CN={_v2Domain}",
                san:            new Dictionary<string, string[]> { ["dns"] = new[] { _v2Domain } },
                productInfo:    BuildV2ProductInfo(),
                requestFormat:  RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Should().NotBeNull();
            result.CARequestID.Should().NotBeNullOrWhiteSpace(
                "V2 Enroll must return a non-empty CARequestID — it is the stable foreign key for all future operations");
            result.Status.Should().NotBe((int)EndEntityStatus.FAILED,
                $"V2 Enroll must not FAILED at submission time; message: {result.StatusMessage}");

            _output.WriteLine($"CARequestID: {result.CARequestID}");
            _output.WriteLine($"Status:      {result.Status}");
            _output.WriteLine($"Message:     {result.StatusMessage}");
        }

        // ---------------------------------------------------------------------------
        // Gap 2 — Revoke() via the plugin, V2 path
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task Revoke_V2_IssuedOrder_ReturnsRevoked()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            string orderId = ResolveOrderId();
            Skip.If(string.IsNullOrWhiteSpace(orderId),
                "No V2 order ID available — set CERTINEXT_V2_ORDER_ID to a real V2 order to run this test.");

            var plugin = BuildV2Plugin();

            var current = await plugin.GetSingleRecord(orderId);
            Skip.If(current?.Status != (int)EndEntityStatus.GENERATED,
                $"Order '{orderId}' is in status {current?.Status} (not GENERATED) — revocation requires an issued certificate; skipping.");

            int revokeResult;
            try
            {
                revokeResult = await plugin.Revoke(orderId, hexSerialNumber: string.Empty, revocationReason: 1 /* keyCompromise */);
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("not in issued state"))
            {
                // Documented sandbox-timing quirk: the CA reports 'issued' via GetSingleRecord
                // while still internally finalizing the order, and rejects revoke with 422 in
                // that window (see issues/0019). Any other exception must fail the test.
                Skip.If(true,
                    $"Order '{orderId}' tracked as GENERATED but CA rejected revocation (sandbox timing): {ex.Message}");
                return; // unreachable
            }

            revokeResult.Should().Be((int)EndEntityStatus.REVOKED,
                "V2 Revoke must return the REVOKED status code on success");
        }

        // ---------------------------------------------------------------------------
        // Gap 3 — GetSingleRecord() via the plugin, V2 path
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task GetSingleRecord_V2_Plugin_ReturnsDetails()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            string orderId = ResolveOrderId();
            Skip.If(string.IsNullOrWhiteSpace(orderId),
                "No V2 order ID available — set CERTINEXT_V2_ORDER_ID to a real V2 order to run this test.");

            var plugin = BuildV2Plugin();
            var record = await plugin.GetSingleRecord(orderId);

            record.Should().NotBeNull("plugin.GetSingleRecord must return a record for a known V2 order");
            record.CARequestID.Should().Be(orderId);
            _output.WriteLine($"CARequestID: {record.CARequestID}");
            _output.WriteLine($"Status:      {record.Status}");
            _output.WriteLine($"ProductID:   {record.ProductID}");
        }

        // ---------------------------------------------------------------------------
        // Gap 4 — Enroll -> Synchronize -> Revoke, full V2 lifecycle via the plugin
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task Enroll_Synchronize_Revoke_V2_FullLifecycle()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            var config = BuildV2Config();
            var plugin = BuildV2Plugin(config);

            // --- Enroll ---
            var enrollResult = await plugin.Enroll(
                csr:            GenerateCsrPem(_v2Domain),
                subject:        $"CN={_v2Domain}",
                san:            new Dictionary<string, string[]> { ["dns"] = new[] { _v2Domain } },
                productInfo:    BuildV2ProductInfo(),
                requestFormat:  RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            enrollResult.Should().NotBeNull();
            enrollResult.CARequestID.Should().NotBeNullOrWhiteSpace();
            enrollResult.Status.Should().NotBe((int)EndEntityStatus.FAILED,
                $"V2 Enroll must not FAILED at submission time; message: {enrollResult.StatusMessage}");

            _output.WriteLine($"Enrolled V2 order {enrollResult.CARequestID}, status={enrollResult.Status}");

            // --- Synchronize (always V1, even though UseV2Api=true) ---
            // Delta sync (fullSync=false, lastSync=recent) rather than a full historical
            // pull — this sandbox account has accumulated 1000+ orders from prior test
            // runs, and a full sync of the entire history is unnecessarily slow here; the
            // order we just enrolled is recent, so a delta sync is sufficient to prove it
            // surfaces via Synchronize.
            var synced = await RunSyncAsync(BuildV2Plugin(config), lastSync: DateTime.UtcNow.AddDays(-1), fullSync: false);
            synced.Should().Contain(
                r => r.CARequestID == enrollResult.CARequestID,
                $"the newly enrolled V2 order '{enrollResult.CARequestID}' must appear in a delta sync " +
                "(Synchronize always uses V1 GetOrderReport regardless of UseV2Api)");

            var syncedRecord = synced.First(r => r.CARequestID == enrollResult.CARequestID);
            _output.WriteLine($"Synced record status: {syncedRecord.Status}");

            // --- Revoke — only if the sandbox has already auto-issued ---
            if (syncedRecord.Status != (int)EndEntityStatus.GENERATED)
            {
                Skip.If(true,
                    $"Order '{enrollResult.CARequestID}' is in status {syncedRecord.Status} (not GENERATED) — " +
                    "sandbox may not auto-issue a V2 order without DCV; skipping revoke step.");
            }

            int revokeResult;
            try
            {
                revokeResult = await plugin.Revoke(enrollResult.CARequestID, hexSerialNumber: string.Empty, revocationReason: 1);
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("not in issued state"))
            {
                // Documented sandbox-timing quirk: the sandbox has been observed to report an
                // order as 'issued' via TrackOrder/GetSingleRecord while still internally
                // finalizing it, and reject a revoke attempted in that window (see issues/0019).
                // Any other exception (e.g. the camelCase-reason HTTP 400 that 0019 describes)
                // must fail the test rather than be swallowed here.
                Skip.If(true,
                    $"Order '{enrollResult.CARequestID}' tracked as GENERATED but CA rejected revocation " +
                    $"(sandbox timing): {ex.Message}");
                return; // unreachable
            }

            revokeResult.Should().Be((int)EndEntityStatus.REVOKED,
                "Revoke must return the REVOKED status code on success");
        }

        // ---------------------------------------------------------------------------
        // Gap 9 — GetSingleRecord() cert-body regression, V2 path
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task GetSingleRecord_V2_IssuedOrder_HasParseableCertBody()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            string orderId = ResolveOrderId();
            Skip.If(string.IsNullOrWhiteSpace(orderId),
                "No V2 order ID available — set CERTINEXT_V2_ORDER_ID to a real V2 order to run this test.");

            var plugin = BuildV2Plugin();
            var record = await WaitForIssuanceAsync(plugin, orderId, maxPolls: 1);

            Skip.If(record?.Status != (int)EndEntityStatus.GENERATED,
                $"Order '{orderId}' is not GENERATED (status={record?.Status}) — skipping cert-body check.");

            record!.Certificate.Should().NotBeNullOrWhiteSpace(
                "GetSingleRecord must populate the PEM body for a GENERATED V2 order");
            record.Certificate.Should().StartWith("-----BEGIN CERTIFICATE-----");

            var b64 = record.Certificate
                .Replace("-----BEGIN CERTIFICATE-----", string.Empty)
                .Replace("-----END CERTIFICATE-----", string.Empty)
                .Replace("\r", string.Empty).Replace("\n", string.Empty).Trim();

            Action parse = () => new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(Convert.FromBase64String(b64));
            parse.Should().NotThrow("the issued V2 certificate PEM must be parseable");
        }

        // ---------------------------------------------------------------------------
        // Gap 10 — GetSingleRecord() across all synced orders, V2-configured plugin
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Runs a full sync (always V1) with a V2-configured (<c>UseV2Api=true</c>) plugin,
        /// then calls <c>GetSingleRecord</c> for a sample of the resulting CARequestIDs.
        /// Since V1-created order IDs are not resolvable via the V2 family probe,
        /// <see cref="System.Collections.Generic.KeyNotFoundException"/> is an accepted,
        /// documented outcome here (see issues/0016) — this test guards against any
        /// *other* unhandled exception type escaping GetSingleRecord.
        /// </summary>
        [SkippableFact]
        public async Task GetSingleRecord_V2_AllSyncedOrders_DoNotThrow()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");
            Skip.If(!_fixture.IsConfigured, "V1 credentials not configured — Synchronize requires them.");

            // Delta sync — this sandbox account has 1000+ historical orders; a recent
            // window is enough to sample GetSingleRecord behavior without paging the
            // entire multi-month history on every test run.
            var plugin = BuildV2Plugin();
            var synced = await RunSyncAsync(plugin, lastSync: DateTime.UtcNow.AddDays(-7), fullSync: false);
            synced.Should().NotBeNull();
            synced.Should().NotBeEmpty(
                "the delta sync window must return at least one record from this sandbox account to sample " +
                "GetSingleRecord against — an empty sync makes the rest of this test vacuous (see gap G6)");

            var sample = synced.Take(10).ToList();
            _output.WriteLine($"Sampling {sample.Count} of {synced.Count} synced records for GetSingleRecord (V2-configured plugin).");

            int ok = 0, keyNotFound = 0;
            foreach (var rec in sample)
            {
                try
                {
                    await plugin.GetSingleRecord(rec.CARequestID);
                    ok++;
                }
                catch (KeyNotFoundException)
                {
                    // Expected: V1-created order IDs are not resolvable via the V2 family
                    // probe when the plugin is UseV2Api=true. See issues/0016.
                    keyNotFound++;
                }
            }

            _output.WriteLine($"GetSingleRecord results: {ok} succeeded, {keyNotFound} KeyNotFoundException (expected for V1 orders under V2 config).");
            (ok + keyNotFound).Should().Be(sample.Count,
                "every sampled GetSingleRecord call must either succeed or throw the documented KeyNotFoundException " +
                "(issues/0016) — any other exception type must escape this loop and fail the test (see gap G6)");
        }

        // ---------------------------------------------------------------------------
        // Gap 11 — Synchronize() still uses V1 when UseV2Api=true, and returns records
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task Sync_V2_StillUsesV1_ReturnsRecords()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");
            Skip.If(!_fixture.IsConfigured, "V1 credentials not configured — Synchronize requires them.");

            // Delta sync — this sandbox account has 1000+ historical orders; a recent
            // window proves Synchronize returns records without paging the entire
            // multi-month history on every test run.
            var plugin = BuildV2Plugin();
            var synced = await RunSyncAsync(plugin, lastSync: DateTime.UtcNow.AddDays(-7), fullSync: false);

            synced.Should().NotBeNull();
            synced.Should().NotBeEmpty(
                "Synchronize must return the account's recent V1 order inventory even when UseV2Api=true " +
                "(Synchronize always uses V1 GetOrderReport)");

            _output.WriteLine($"Synchronize returned {synced.Count} record(s) with UseV2Api=true.");
        }
    }

    /// <summary>
    /// Shared helper for loading <c>~/.env_certinext_v2</c> and promoting its values into
    /// process environment, overriding V1 values the fixture may have already set. Used
    /// by both <see cref="V2LifecycleTests"/> and <c>V2DcvLifecycleTests</c> so the two
    /// files don't duplicate env-loading logic.
    /// </summary>
    internal static class V2EnvHelper
    {
        /// <summary>
        /// Loads <c>~/.env_certinext_v2</c>, force-promotes its keys into process
        /// environment (overriding any V1 values already set by <see cref="IntegrationTestFixture"/>),
        /// and returns the merged environment dictionary.
        /// </summary>
        public static Dictionary<string, string> LoadAndPromote()
        {
            string v2Path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".env_certinext_v2");

            var (env, fileKeys) = LoadEnvFile(v2Path);

            // Force-promote V2-file-defined keys into process env so they override
            // any V1 values the fixture already set.
            foreach (string key in fileKeys)
                if (env.TryGetValue(key, out string fv))
                    Environment.SetEnvironmentVariable(key, fv);

            // Promote remaining keys that aren't already in process env
            foreach (var kv in env)
                if (Environment.GetEnvironmentVariable(kv.Key) == null)
                    Environment.SetEnvironmentVariable(kv.Key, kv.Value);

            return env;
        }

        /// <summary>
        /// Loads a KEY=VALUE env file and merges with process env vars. File values take
        /// priority over process env because the fixture may have already promoted V1
        /// values (e.g. CERTINEXT_API_URL with /emSignHub-API suffix) into process env,
        /// and the V2 base URL differs. Returns the merged dict and the set of keys
        /// defined in the file.
        /// </summary>
        public static (Dictionary<string, string> env, HashSet<string> fileKeys) LoadEnvFile(string path)
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

        public static string GetEnv(Dictionary<string, string> env, string key, string defaultValue = "")
            => env.TryGetValue(key, out string v) && !string.IsNullOrWhiteSpace(v) ? v : defaultValue;
    }
}
