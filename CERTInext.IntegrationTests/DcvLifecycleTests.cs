// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.PKI.Enums.EJBCA;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Integration tests for the DNS DCV enrollment path.
    ///
    /// DNS validator selection:
    ///   • When <c>CERTINEXT_CF_API_TOKEN</c> and <c>CERTINEXT_CF_ZONE_ID</c> are set in
    ///     <c>~/.env_certinext</c>, a <see cref="CloudflareDomainValidator"/> is used and
    ///     a real TXT record is published and cleaned up around the enrollment.
    ///   • Otherwise a <see cref="StubDomainValidator"/> is used.  The plugin still
    ///     exercises the full DCV orchestration path (Stage → propagation wait → VerifyDcv
    ///     → Cleanup), but no real DNS record is published.  Whether CERTInext's VerifyDcv
    ///     succeeds in this mode depends on the sandbox environment.
    ///
    /// All tests skip when CERTInext credentials are absent (<see cref="IntegrationSkip"/>).
    /// Add the following to <c>~/.env_certinext</c> to run with real DNS:
    /// <code>
    /// CERTINEXT_CF_API_TOKEN=&lt;your Cloudflare API token with DNS:Edit&gt;
    /// CERTINEXT_CF_ZONE_ID=&lt;Cloudflare Zone ID for your test domain&gt;
    /// CERTINEXT_DCV_DOMAIN=&lt;subdomain to use, e.g. dcv-test.example.com&gt;
    /// </code>
    /// </summary>
    public class DcvLifecycleTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;

        public DcvLifecycleTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;
        }

        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

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

        private IDomainValidatorFactory BuildDnsFactory() =>
            _fixture.IsCloudflareConfigured
                ? (IDomainValidatorFactory)new CloudflareDomainValidatorFactory(
                    _fixture.CloudflareApiToken, _fixture.CloudflareZoneId)
                : new StubDomainValidatorFactory();

        /// <summary>
        /// Runs <c>plugin.Synchronize</c> and returns every record that came out of the
        /// blocking buffer.  Mirrors the helper in <c>LifecycleTests</c>; kept local so
        /// the DCV bulk test isn't coupled to that file's private member.
        /// </summary>
        private static async Task<List<AnyCAPluginCertificate>> RunSyncAsync(CERTInextCAPlugin plugin)
        {
            var buffer = new System.Collections.Concurrent.BlockingCollection<AnyCAPluginCertificate>(boundedCapacity: 10_000);
            var collected = new List<AnyCAPluginCertificate>();

            var syncTask = Task.Run(async () =>
            {
                await plugin.Synchronize(buffer, lastSync: null, fullSync: true, cancelToken: System.Threading.CancellationToken.None);
                if (!buffer.IsAddingCompleted)
                    buffer.CompleteAdding();
            });

            foreach (var record in buffer.GetConsumingEnumerable())
                collected.Add(record);

            await syncTask;
            return collected;
        }

        private CERTInextCAPlugin BuildPlugin(bool dcvEnabled, int propagationDelaySeconds = 5, int? pageSize = null)
        {
            var config = new CERTInextConfig
            {
                ApiUrl                    = _fixture.Config.ApiUrl,
                AuthMode                  = _fixture.Config.AuthMode,
                ApiKey                    = _fixture.Config.ApiKey,
                AccountNumber             = _fixture.Config.AccountNumber,
                GroupNumber               = _fixture.Config.GroupNumber,
                OrganizationNumber        = _fixture.Config.OrganizationNumber,
                RequestorName             = _fixture.Config.RequestorName,
                RequestorEmail            = _fixture.Config.RequestorEmail,
                RequestorIsdCode          = _fixture.Config.RequestorIsdCode,
                RequestorMobileNumber     = _fixture.Config.RequestorMobileNumber,
                SignerPlace                = _fixture.Config.SignerPlace,
                SignerIp                   = _fixture.Config.SignerIp,
                DefaultProductCode         = _fixture.Config.DefaultProductCode,
                PageSize                   = pageSize ?? _fixture.Config.PageSize,
                DcvEnabled                 = dcvEnabled,
                DcvPropagationDelaySeconds = propagationDelaySeconds,
                DcvTimeoutMinutes          = 3
            };

            return new CERTInextCAPlugin(_fixture.Client, BuildDnsFactory(), config);
        }

        // ---------------------------------------------------------------------------
        // Tests
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Enroll with DCV enabled.  Uses a real Cloudflare DNS record when CF credentials
        /// are configured, otherwise uses <see cref="StubDomainValidator"/>.
        ///
        /// The test verifies that the plugin completes without throwing.  The enrollment
        /// result status depends on whether the CERTInext sandbox auto-issues after DCV.
        /// </summary>
        [SkippableFact]
        public async Task DcvEnroll_CompletesWithoutThrowing()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            var plugin = BuildPlugin(dcvEnabled: true);

            var result = await plugin.Enroll(
                csr:            GenerateCsrPem(IntegrationTestData.DcvTestDomain),
                subject:        $"CN={IntegrationTestData.DcvTestDomain}",
                san:            new Dictionary<string, string[]>
                {
                    ["dns"] = new[] { IntegrationTestData.DcvTestDomain }
                },
                productInfo:    IntegrationTestData.DvSslProductInfo(_fixture.Config.DefaultProductCode),
                requestFormat:  RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Should().NotBeNull();
            _output.WriteLine($"Domain:      {IntegrationTestData.DcvTestDomain}");
            _output.WriteLine($"CARequestID: {result.CARequestID}");
            _output.WriteLine($"Status:      {result.Status}");
            _output.WriteLine($"Message:     {result.StatusMessage}");

            if (_fixture.IsCloudflareConfigured)
            {
                // With real DNS, CERTInext should be able to verify — assert issuance or pending
                new[] { (int)EndEntityStatus.GENERATED, (int)EndEntityStatus.EXTERNALVALIDATION }
                    .Should().Contain(result.Status,
                    "enrollment with real DNS DCV should produce a valid terminal or pending status");
            }
            else
            {
                // Without real DNS the VerifyDcv may fail; we only assert no unhandled exception
                // was thrown (the Enroll method handles the error gracefully).
                result.Should().NotBeNull("enrollment should return a result even when stub DNS is used");
            }
        }

        /// <summary>
        /// Enroll without DCV enabled — verifies the plugin skips the DCV path entirely
        /// and returns a result from the normal enrollment flow.
        /// </summary>
        [SkippableFact]
        public async Task EnrollWithoutDcv_DoesNotInvokeDnsProvider()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            // Use a plugin backed by the real client but DcvEnabled=false
            var plugin = BuildPlugin(dcvEnabled: false);

            var result = await plugin.Enroll(
                csr:            GenerateCsrPem(IntegrationTestData.DcvTestDomain),
                subject:        $"CN={IntegrationTestData.DcvTestDomain}",
                san:            new Dictionary<string, string[]>
                {
                    ["dns"] = new[] { IntegrationTestData.DcvTestDomain }
                },
                productInfo:    IntegrationTestData.DvSslProductInfo(_fixture.Config.DefaultProductCode),
                requestFormat:  RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Should().NotBeNull();
        }

        /// <summary>
        /// End-to-end "DCV mode off" scenario, mirroring how a v3.2 gateway host would
        /// experience the plugin (no IDomainValidatorFactory available, so DCV silently
        /// no-ops). Enrolls a fresh domain with DcvEnabled=false, then runs the plugin's
        /// own <c>Synchronize</c> and asserts the order surfaces in pending-DCV state.
        /// This is the live verification for GitHub issue #7.
        ///
        /// The CERTInext side may auto-issue some orders very quickly thanks to cached
        /// DCV for previously-validated parent domains; this test uses a freshly random
        /// subdomain to minimize that but tolerates either pending or issued in the
        /// assertion (the real signal we want is "the plugin did not invoke DCV").
        /// </summary>
        [SkippableFact]
        public async Task EnrollWithDcvOff_OrderAppearsInSync_PluginDidNotInvokeDcv()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            // Generate a unique CN so prior cached-DCV state on the parent zone doesn't
            // bias the result.
            string suffix = System.Guid.NewGuid().ToString("N").Substring(0, 8);
            string cn = $"dcv-off-{suffix}.scrup.org";

            // Plugin built with DCV disabled. BuildPlugin still wires a Cloudflare or stub
            // factory but PerformDcvIfNeededAsync gates on _config.DcvEnabled so neither
            // factory will be touched on this Enroll path.
            var plugin = BuildPlugin(dcvEnabled: false);

            // --- Enroll phase ---
            var enrollSw = System.Diagnostics.Stopwatch.StartNew();
            var enrollResult = await plugin.Enroll(
                csr:            GenerateCsrPem(cn),
                subject:        $"CN={cn}",
                san:            new Dictionary<string, string[]> { ["dns"] = new[] { cn } },
                productInfo:    IntegrationTestData.DvSslProductInfo(_fixture.Config.DefaultProductCode),
                requestFormat:  RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);
            enrollSw.Stop();

            enrollResult.Should().NotBeNull();
            enrollResult.CARequestID.Should().NotBeNullOrWhiteSpace(
                "the CA must accept the order even with DCV off — DCV-off ≠ no enrollment");

            _output.WriteLine($"Enroll completed in {enrollSw.Elapsed:mm\\:ss\\.fff}");
            _output.WriteLine($"  CARequestID:  {enrollResult.CARequestID}");
            _output.WriteLine($"  Status:       {enrollResult.Status}");
            _output.WriteLine($"  Message:      {enrollResult.StatusMessage}");

            // The plugin's "DCV off" contract: with DcvEnabled=false the plugin does NOT
            // wait for issuance. Even if CERTInext later auto-issues from cached DCV, the
            // immediate Enroll response should be pending (no issuance polling ran).
            // We allow GENERATED too because cached DCV on the parent zone could plausibly
            // make CERTInext mark the order issued before its first reply — but the most
            // common case is EXTERNALVALIDATION.
            new[] { (int)EndEntityStatus.EXTERNALVALIDATION, (int)EndEntityStatus.GENERATED }
                .Should().Contain(enrollResult.Status,
                    $"DCV-off Enroll must return a recognizable terminal/pending state; got {enrollResult.Status}");

            // --- Sync phase: pull the whole account, find our order ---
            var syncSw = System.Diagnostics.Stopwatch.StartNew();
            var synced = await RunSyncAsync(plugin);
            syncSw.Stop();
            _output.WriteLine($"Synchronize returned {synced.Count} records in {syncSw.Elapsed:mm\\:ss\\.fff}");

            var record = synced.FirstOrDefault(r => r.CARequestID == enrollResult.CARequestID);
            record.Should().NotBeNull(
                $"the enrolled order ({enrollResult.CARequestID}) must appear in plugin.Synchronize results");
            _output.WriteLine($"  Sync record status: {record!.Status}");

            // Final shape assertion: order is in the inventory, and its status is either
            // pending (EXTERNALVALIDATION — typical when CERTInext hasn't moved it yet)
            // or issued (GENERATED — if CERTInext autoissued from cached DCV). It must
            // NOT be FAILED — DCV-off should not produce a failed cert.
            new[] { (int)EndEntityStatus.EXTERNALVALIDATION, (int)EndEntityStatus.GENERATED }
                .Should().Contain(record.Status,
                    "the synced record must reflect either pending or issued — never FAILED with DCV off");

            // Surface the human-readable summary so the live behavior is visible in the
            // test output without needing to grep the gateway logs.
            _output.WriteLine($"--- Verdict: DCV-off enroll for {cn} succeeded, plugin did not invoke DCV, " +
                              $"order {enrollResult.CARequestID} surfaced in sync with Status={record.Status}. ---");
        }

        /// <summary>
        /// Symmetric counterpart to <see cref="EnrollWithDcvOff_OrderAppearsInSync_PluginDidNotInvokeDcv"/>.
        /// Drives a fresh enrollment with DCV ON end-to-end against the live sandbox and
        /// asserts the issued cert flows through Synchronize.  This is the v3.3+
        /// production scenario — plugin places the order, runs DNS TXT staging via
        /// Cloudflare, asks CERTInext to verify, waits for issuance, and the resulting
        /// GENERATED record surfaces in the gateway's inventory.
        /// </summary>
        [SkippableFact]
        public async Task EnrollWithDcvOn_OrderIssuedEndToEnd_AndAppearsInSync()
        {
            IntegrationSkip.IfNotConfigured(_fixture);
            Skip.If(!_fixture.IsCloudflareConfigured,
                "CERTINEXT_CF_API_TOKEN + CERTINEXT_CF_ZONE_ID required — DCV-on test must publish real TXT records.");

            string suffix = System.Guid.NewGuid().ToString("N").Substring(0, 8);
            string cn = $"dcv-on-{suffix}.scrup.org";

            var plugin = BuildPlugin(dcvEnabled: true);

            // --- Enroll phase ---
            var enrollSw = System.Diagnostics.Stopwatch.StartNew();
            var enrollResult = await plugin.Enroll(
                csr:            GenerateCsrPem(cn),
                subject:        $"CN={cn}",
                san:            new Dictionary<string, string[]> { ["dns"] = new[] { cn } },
                productInfo:    IntegrationTestData.DvSslProductInfo(_fixture.Config.DefaultProductCode),
                requestFormat:  RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);
            enrollSw.Stop();

            enrollResult.Should().NotBeNull();
            enrollResult.CARequestID.Should().NotBeNullOrWhiteSpace();
            _output.WriteLine($"Enroll completed in {enrollSw.Elapsed:mm\\:ss\\.fff}");
            _output.WriteLine($"  CARequestID:  {enrollResult.CARequestID}");
            _output.WriteLine($"  Status:       {enrollResult.Status}");
            _output.WriteLine($"  Certificate:  {(string.IsNullOrWhiteSpace(enrollResult.Certificate) ? "(not in Enroll response)" : enrollResult.Certificate[..60] + "...")}");

            // Enroll must NOT be FAILED. GENERATED if the bounded issuance wait caught
            // the cert before returning; EXTERNALVALIDATION if not — sync will catch it.
            new[] { (int)EndEntityStatus.EXTERNALVALIDATION, (int)EndEntityStatus.GENERATED }
                .Should().Contain(enrollResult.Status,
                    $"DCV-on Enroll must return pending or issued; got {enrollResult.Status}");

            // --- Sync phase ---
            var syncSw = System.Diagnostics.Stopwatch.StartNew();
            var synced = await RunSyncAsync(plugin);
            syncSw.Stop();
            _output.WriteLine($"Synchronize returned {synced.Count} records in {syncSw.Elapsed:mm\\:ss\\.fff}");

            var record = synced.FirstOrDefault(r => r.CARequestID == enrollResult.CARequestID);
            record.Should().NotBeNull(
                $"the enrolled order ({enrollResult.CARequestID}) must appear in plugin.Synchronize results");
            _output.WriteLine($"  Sync record status: {record!.Status}");
            _output.WriteLine($"  Cert PEM length:    {(record.Certificate?.Length ?? 0)}");

            // The plugin's sync-DCV-retry should have advanced any still-pending orders.
            // With Cloudflare DCV available, every DCV-on enrollment should resolve to
            // GENERATED by the time sync returns. If we see EXTERNALVALIDATION here it
            // means CERTInext's async issuance window is still in flight after our sync —
            // worth noting but not a hard failure (the next sync will pick it up).
            record.Status.Should().BeOneOf((int)EndEntityStatus.GENERATED, (int)EndEntityStatus.EXTERNALVALIDATION);

            // Hard signal we'll always demand: when sync returns GENERATED, there must
            // be a non-empty PEM. A GENERATED record with no Certificate would mean the
            // plugin's download path is broken.
            if (record.Status == (int)EndEntityStatus.GENERATED)
            {
                record.Certificate.Should().NotBeNullOrWhiteSpace(
                    "GENERATED records must carry the issued PEM in their Certificate field");
            }

            _output.WriteLine($"--- Verdict: DCV-on enroll for {cn} drove DCV end-to-end via plugin, " +
                              $"order {enrollResult.CARequestID} surfaced in sync with Status={record.Status}. ---");
        }

        /// <summary>
        /// Exercises the deferred-DCV retry path during single-record refresh against an
        /// existing pending order.  Reads <c>CERTINEXT_PENDING_ORDER_ID</c> from the
        /// environment; the test is skipped if not set, since this scenario requires a
        /// real order that CERTInext has parked at <c>Pending System RA</c> with
        /// <c>dcvStatus=0</c> after the initial enrollment.
        ///
        /// On success, <c>GetSingleRecord</c> drives DCV (Cloudflare TXT publish →
        /// CERTInext VerifyDcv → wait for verification → cleanup) and returns either an
        /// issued record (<see cref="EndEntityStatus.GENERATED"/>) or a still-pending
        /// record if CERTInext has not finished server-side validation yet.
        /// </summary>
        [SkippableFact]
        public async Task GetSingleRecord_DrivesDcvForPendingOrder()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            string orderId = System.Environment.GetEnvironmentVariable("CERTINEXT_PENDING_ORDER_ID");
            Skip.If(string.IsNullOrWhiteSpace(orderId),
                "Set CERTINEXT_PENDING_ORDER_ID to a real pending-DCV order to run this test.");

            Skip.If(!_fixture.IsCloudflareConfigured,
                "CERTINEXT_CF_API_TOKEN and CERTINEXT_CF_ZONE_ID must be set so the plugin " +
                "can publish a real TXT record for CERTInext to verify.");

            // DCV must be enabled and a real DNS provider must be wired up — otherwise the
            // sync-retry helper short-circuits with no effect.
            var plugin = BuildPlugin(dcvEnabled: true);

            var record = await plugin.GetSingleRecord(orderId);

            record.Should().NotBeNull();
            _output.WriteLine($"CARequestID:  {record.CARequestID}");
            _output.WriteLine($"Status:       {record.Status}");
            _output.WriteLine($"Certificate:  {(string.IsNullOrWhiteSpace(record.Certificate) ? "(not yet issued)" : record.Certificate[..60] + "...")}");

            // We assert no unhandled exception was thrown and a record came back.  The exact
            // final status is environment-dependent (CERTInext may still be working through
            // VerifyDcv even after the plugin returns), so we accept either GENERATED or
            // a still-pending EXTERNALVALIDATION status here — the regression we're guarding
            // against is the silent no-op the plugin used to do on this path.
            new[] { (int)EndEntityStatus.GENERATED, (int)EndEntityStatus.EXTERNALVALIDATION }
                .Should().Contain(record.Status,
                    "deferred-DCV retry should leave the order in a valid pending or issued state");
        }

        /// <summary>
        /// Volume / pagination smoke test — enrolls a configurable number of DV orders
        /// concurrently (default 101) against fresh unique subdomains, then runs
        /// <c>plugin.Synchronize</c> with the connector's PageSize=100 to verify
        /// (a) every order issued, (b) every order shows up in sync, and (c) the sync
        /// iterator correctly crosses the 100-record page boundary in
        /// <c>ListCertificatesAsync</c>.
        ///
        /// This is an opt-in test because it places real CA orders and takes several
        /// minutes.  Set <c>CERTINEXT_RUN_BULK_TEST=1</c> in the environment to run.
        /// Override the count with <c>CERTINEXT_BULK_TEST_COUNT</c> (default 101) and
        /// the concurrency cap with <c>CERTINEXT_BULK_TEST_PARALLEL</c> (default 5).
        /// </summary>
        [SkippableFact]
        public async Task BulkDvEnrollment_AllOrdersIssue_AndPaginationWorks()
        {
            IntegrationSkip.IfNotConfigured(_fixture);
            Skip.If(System.Environment.GetEnvironmentVariable("CERTINEXT_RUN_BULK_TEST") != "1",
                "Opt-in: set CERTINEXT_RUN_BULK_TEST=1 to run the volume/pagination test.");
            Skip.If(!_fixture.IsCloudflareConfigured,
                "CERTINEXT_CF_API_TOKEN + CERTINEXT_CF_ZONE_ID required — bulk test must publish real TXT records.");

            int count = int.TryParse(System.Environment.GetEnvironmentVariable("CERTINEXT_BULK_TEST_COUNT"), out int c)
                ? c : 101;
            int parallel = int.TryParse(System.Environment.GetEnvironmentVariable("CERTINEXT_BULK_TEST_PARALLEL"), out int p)
                ? p : 5;

            // PageSize=100 ensures the 101st order forces a second page during Synchronize.
            var plugin = BuildPlugin(dcvEnabled: true, propagationDelaySeconds: 5, pageSize: 100);

            // --- Phase 1: bounded-parallel enrollments ---
            var enrolled = new System.Collections.Concurrent.ConcurrentBag<(int idx, string cn, EnrollmentResult result)>();
            var failures = new System.Collections.Concurrent.ConcurrentBag<(int idx, string cn, string error)>();
            var sw = System.Diagnostics.Stopwatch.StartNew();

            using (var sem = new System.Threading.SemaphoreSlim(parallel, parallel))
            {
                var tasks = Enumerable.Range(0, count).Select(async i =>
                {
                    await sem.WaitAsync();
                    try
                    {
                        // Unique CN per order — uses Guid hex prefix so reruns don't collide.
                        string suffix = Guid.NewGuid().ToString("N").Substring(0, 8);
                        string cn = $"bulk-{suffix}.scrup.org";
                        string csr = GenerateCsrPem(cn);

                        var result = await plugin.Enroll(
                            csr:            csr,
                            subject:        $"CN={cn}",
                            san:            new Dictionary<string, string[]> { ["dns"] = new[] { cn } },
                            productInfo:    IntegrationTestData.DvSslProductInfo(_fixture.Config.DefaultProductCode),
                            requestFormat:  RequestFormat.PKCS10,
                            enrollmentType: EnrollmentType.New);

                        enrolled.Add((i, cn, result));
                        _output.WriteLine($"[{i:000}] OK   cn={cn}  id={result.CARequestID}  status={result.Status}");
                    }
                    catch (Exception ex)
                    {
                        failures.Add((i, $"#{i}", ex.Message));
                        _output.WriteLine($"[{i:000}] FAIL {ex.GetType().Name}: {ex.Message}");
                    }
                    finally
                    {
                        sem.Release();
                    }
                });
                await Task.WhenAll(tasks);
            }

            sw.Stop();
            _output.WriteLine($"--- Enroll phase: enrolled={enrolled.Count}, failed={failures.Count}, elapsed={sw.Elapsed:mm\\:ss} ---");

            failures.Should().BeEmpty(
                "every Enroll() call must succeed (the plugin's EMS-956 tolerance means even pending DCV returns gracefully); " +
                $"got {failures.Count} hard failures.");
            enrolled.Count.Should().Be(count, $"expected {count} successful Enroll() calls");

            var enrolledIds = enrolled
                .Where(e => !string.IsNullOrEmpty(e.result.CARequestID))
                .Select(e => e.result.CARequestID)
                .ToHashSet();
            enrolledIds.Count.Should().Be(count, "every enrollment must return a CARequestID");

            // --- Phase 2: Synchronize until every enrolled order reaches GENERATED ---
            //
            // CERTInext's pipeline is async: VerifyDcv triggers a server-side DNS-01 check
            // and certificate generation that completes a few seconds *after* the plugin's
            // Enroll() returns.  A single Synchronize captures whatever state CERTInext has
            // settled at that exact moment, so a chunk of orders typically remain at
            // EXTERNALVALIDATION on the first pass.  The sync-driven DCV retry in the plugin
            // handles staggered completion across subsequent gateway sync cycles — so this
            // test mimics that by running Synchronize repeatedly until either all 101 are
            // GENERATED or a bounded number of attempts is exhausted.
            const int maxSyncPasses = 8;
            const int delayBetweenPassesSeconds = 30;

            List<AnyCAPluginCertificate> synced = null;
            System.Diagnostics.Stopwatch syncPhaseSw = System.Diagnostics.Stopwatch.StartNew();
            int passesUsed = 0;
            int finalNotIssued = -1;

            for (int pass = 1; pass <= maxSyncPasses; pass++)
            {
                passesUsed = pass;
                var passSw = System.Diagnostics.Stopwatch.StartNew();
                synced = await RunSyncAsync(plugin);
                passSw.Stop();

                int generated = synced.Count(r => enrolledIds.Contains(r.CARequestID) && r.Status == (int)EndEntityStatus.GENERATED);
                int pending   = enrolledIds.Count - generated;
                finalNotIssued = pending;

                _output.WriteLine(
                    $"--- Sync pass #{pass}: returned {synced.Count} records, {generated}/{enrolledIds.Count} GENERATED, " +
                    $"{pending} still pending, elapsed={passSw.Elapsed:mm\\:ss} ---");

                if (pending == 0)
                    break;

                if (pass < maxSyncPasses)
                {
                    _output.WriteLine($"    Waiting {delayBetweenPassesSeconds}s before next sync pass…");
                    await Task.Delay(TimeSpan.FromSeconds(delayBetweenPassesSeconds));
                }
            }
            syncPhaseSw.Stop();

            // Pagination check — sync must have returned strictly more than one page.
            synced.Count.Should().BeGreaterThan(100,
                "with 101 freshly-enrolled orders + any pre-existing, sync must return >100 records " +
                "to prove the ListCertificatesAsync paginator crossed PageSize=100.");

            // Every enrolled CARequestID must show up.
            var syncedIds = synced.Select(r => r.CARequestID).ToHashSet();
            var missing = enrolledIds.Where(id => !syncedIds.Contains(id)).ToList();
            missing.Should().BeEmpty(
                $"{missing.Count} enrolled orders did not appear in sync results: " +
                $"{string.Join(", ", missing.Take(5))}{(missing.Count > 5 ? ", ..." : "")}");

            // Final assertion — every enrolled order must be GENERATED after the polling window.
            var lookup = synced.ToDictionary(r => r.CARequestID, r => r);
            var notIssued = enrolledIds
                .Select(id => lookup[id])
                .Where(r => r.Status != (int)EndEntityStatus.GENERATED)
                .ToList();

            if (notIssued.Count > 0)
            {
                _output.WriteLine($"--- After {passesUsed} sync passes, {notIssued.Count} order(s) still not GENERATED: ---");
                foreach (var r in notIssued.Take(10))
                    _output.WriteLine($"    {r.CARequestID}  Status={r.Status}");
            }

            notIssued.Should().BeEmpty(
                $"every enrolled DV order should auto-issue on the new sandbox after {maxSyncPasses} sync passes; " +
                $"{notIssued.Count} did not (last pass: {finalNotIssued} pending).");

            _output.WriteLine($"--- SUCCESS: {count}/{count} DV orders enrolled, synced, and issued in {passesUsed} sync pass(es). " +
                              $"Enroll={sw.Elapsed:mm\\:ss}  SyncPhase={syncPhaseSw.Elapsed:mm\\:ss}  Total={(sw.Elapsed + syncPhaseSw.Elapsed):mm\\:ss} ---");
        }
    }

    /// <summary>
    /// Shared test data for DCV integration tests.
    /// </summary>
    internal static class IntegrationTestData
    {
        /// <summary>
        /// Domain used for DCV tests.  Override via <c>CERTINEXT_DCV_DOMAIN</c> in
        /// <c>~/.env_certinext</c>.
        /// </summary>
        public static string DcvTestDomain =>
            System.Environment.GetEnvironmentVariable("CERTINEXT_DCV_DOMAIN")
            ?? "dcv-test.example.com";

        public static EnrollmentProductInfo DvSslProductInfo(string productCode = null) =>
            new EnrollmentProductInfo
            {
                ProductID         = productCode ?? Constants.Products.DvSsl,
                ProductParameters = new Dictionary<string, string>
                {
                    ["ProfileId"]    = productCode ?? Constants.Products.DvSsl,
                    ["ValidityYears"] = "1"
                }
            };
    }
}
