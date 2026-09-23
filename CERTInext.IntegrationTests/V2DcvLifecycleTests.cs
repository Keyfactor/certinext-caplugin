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

#if SUPPORTS_DCV
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
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
    /// Plugin-level DCV integration tests for the V2 (OAuth2) API path (gaps 5-8, 14-15).
    /// Mirrors <see cref="DcvLifecycleTests"/>'s structure for V1: uses a real
    /// <see cref="CloudflareDomainValidatorFactory"/> when Cloudflare credentials are
    /// configured, otherwise a <see cref="StubDomainValidatorFactory"/>.
    ///
    /// Requires the <c>SUPPORTS_DCV</c> build (<c>-p:DcvSupport=true</c>) because it uses
    /// the v3.3-only <see cref="IDomainValidatorFactory"/> constructor. Excluded from the
    /// no-DCV build via the test project's <c>&lt;Compile Remove&gt;</c> item group.
    /// </summary>
    public class V2DcvLifecycleTests : IClassFixture<IntegrationTestFixture>, IDisposable
    {
        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;
        private readonly List<IDisposable> _toDispose = new List<IDisposable>();

        private readonly string _v2ApiUrl;
        private readonly string _v2ClientId;
        private readonly string _v2ClientSecret;
        private readonly string _v2ProductCode;
        private readonly string _v2Domain;
        private readonly bool _v2Enabled;
        private readonly string _cfApiToken;
        private readonly string _cfZoneId;
        private readonly bool _dcvEnabled;

        public V2DcvLifecycleTests(IntegrationTestFixture fixture, ITestOutputHelper output)
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

        public void Dispose()
        {
            foreach (var d in _toDispose)
                d.Dispose();
            _toDispose.Clear();
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

        private static async Task<List<AnyCAPluginCertificate>> RunSyncAsync(
            CERTInextCAPlugin plugin, DateTime? lastSync = null, bool fullSync = true)
        {
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(boundedCapacity: 10_000);
            var collected = new List<AnyCAPluginCertificate>();

            var syncTask = Task.Run(async () =>
            {
                await plugin.Synchronize(buffer, lastSync: lastSync, fullSync: fullSync, cancelToken: CancellationToken.None);
                if (!buffer.IsAddingCompleted)
                    buffer.CompleteAdding();
            });

            foreach (var record in buffer.GetConsumingEnumerable())
                collected.Add(record);

            await syncTask;
            return collected;
        }

        private IDomainValidatorFactory BuildV2DnsFactory()
        {
            if (_dcvEnabled)
            {
                var factory = new CloudflareDomainValidatorFactory(_cfApiToken, _cfZoneId);
                _toDispose.Add(factory);
                return factory;
            }
            return new StubDomainValidatorFactory();
        }

        private CERTInextConfig BuildV2Config(bool dcvEnabled = true, int propagationDelaySeconds = 5, int? pageSize = null)
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
                DcvPropagationDelaySeconds = propagationDelaySeconds,
                DcvTimeoutMinutes          = 3
            };
        }

        /// <summary>
        /// Builds a plugin wired for the V2 API with a real DNS factory injected via the
        /// v3.3-only three-arg test constructor, so <c>EnrollV2Async</c> /
        /// <c>GetSingleRecordV2Async</c> can drive DCV inline.
        /// </summary>
        private CERTInextCAPlugin BuildV2DcvPlugin(bool dcvEnabled = true, int propagationDelaySeconds = 5, int? pageSize = null)
        {
            var config = BuildV2Config(dcvEnabled, propagationDelaySeconds, pageSize);
            var client = new CERTInextClient(config);
            return new CERTInextCAPlugin(client, BuildV2DnsFactory(), config);
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
        /// Parses an issued certificate PEM and asserts its public key matches the requested
        /// algorithm/size. Copy of the equivalent helper in <see cref="DcvLifecycleTests"/>.
        /// </summary>
        private static void AssertIssuedCertMatchesAlgorithm(string certPem, KeyAlgorithmSpec spec, string tag)
        {
            var b64 = certPem
                .Replace("-----BEGIN CERTIFICATE-----", string.Empty)
                .Replace("-----END CERTIFICATE-----", string.Empty)
                .Replace("\r", string.Empty).Replace("\n", string.Empty).Trim();

            var cert = new Org.BouncyCastle.X509.X509CertificateParser().ReadCertificate(Convert.FromBase64String(b64));
            cert.Should().NotBeNull($"{tag}: issued cert PEM must parse");

            var pub = cert.GetPublicKey();
            switch (spec.Kind)
            {
                case KeyKind.Rsa:
                    pub.Should().BeOfType<RsaKeyParameters>();
                    ((RsaKeyParameters)pub).Modulus.BitLength.Should().Be(spec.Strength,
                        $"{tag}: issued RSA cert must have a {spec.Strength}-bit modulus");
                    break;
                case KeyKind.Ecdsa:
                    pub.Should().BeOfType<ECPublicKeyParameters>();
                    ((ECPublicKeyParameters)pub).Parameters.Curve.FieldSize.Should().Be(spec.Strength,
                        $"{tag}: issued EC cert must use a {spec.Strength}-bit curve");
                    break;
                case KeyKind.Ed25519:
                    pub.Should().BeOfType<Ed25519PublicKeyParameters>();
                    break;
                case KeyKind.Ed448:
                    pub.Should().BeOfType<Ed448PublicKeyParameters>();
                    break;
            }
        }

        // ---------------------------------------------------------------------------
        // Gap 5 — Enroll with DCV on, V2 path, does not throw
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task DcvEnroll_V2_CompletesWithoutThrowing()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            var config = BuildV2Config(dcvEnabled: true);
            using var probeClient = new CERTInextClient(config);
            var (domainVerified, rawStatus) = await V2DomainStatusHelper.GetDcvStatusAsync(probeClient, _v2Domain);
            _output.WriteLine($"Pre-enroll domain status for '{_v2Domain}': dcvStatus={rawStatus ?? "<no row>"}");

            var recordingFactory = new RecordingDomainValidatorFactory(BuildV2DnsFactory());
            var plugin = new CERTInextCAPlugin(new CERTInextClient(config), recordingFactory, config);

            var result = await plugin.Enroll(
                csr:            GenerateCsrPem(_v2Domain),
                subject:        $"CN={_v2Domain}",
                san:            new Dictionary<string, string[]> { ["dns"] = new[] { _v2Domain } },
                productInfo:    BuildV2ProductInfo(),
                requestFormat:  RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Should().NotBeNull("Enroll must return a result even when DCV verification does not complete inline");
            _output.WriteLine($"CARequestID: {result.CARequestID}");
            _output.WriteLine($"Status:      {result.Status}");
            _output.WriteLine($"Message:     {result.StatusMessage}");

            var staged = recordingFactory.StagedCalls;
            var cleaned = recordingFactory.CleanedUpFqdns;
            _output.WriteLine($"DNS provider calls: staged={staged.Count}, cleaned={cleaned.Count}");

            if (domainVerified)
            {
                // Reuse path (issues/0020): the domain is already verified account-wide, so no
                // fresh TXT record should ever be staged for it.
                staged.Should().BeEmpty(
                    $"domain '{_v2Domain}' was already VERIFIED before enrollment (reuse path) — no TXT record " +
                    "should be staged. If this fails, see issues/0020 (the plugin currently treats the CA's " +
                    "EMS-1080 'already verified' response as a failure and defers, rather than as satisfied).");
                new[] { (int)EndEntityStatus.EXTERNALVALIDATION, (int)EndEntityStatus.GENERATED }
                    .Should().Contain(result.Status,
                        $"a reused, already-verified domain must let the order proceed to pending or issued; " +
                        $"got {result.Status}. Message: {result.StatusMessage}");
            }
            else
            {
                // Publish path: a fresh challenge must actually get staged and cleaned up.
                staged.Should().NotBeEmpty(
                    $"domain '{_v2Domain}' was not yet VERIFIED (dcvStatus={rawStatus ?? "<no row>"}) — Enroll " +
                    "must stage a TXT record to exercise the publish path.");
                cleaned.Should().NotBeEmpty(
                    "a staged DCV TXT record must be cleaned up after the publish-path attempt.");
            }
        }

        // ---------------------------------------------------------------------------
        // Gap 6 — Enroll with DCV off, V2 path, does not invoke the DNS provider
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task EnrollWithoutDcv_V2_DoesNotInvokeDnsProvider()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            var config = BuildV2Config(dcvEnabled: false);
            var recordingFactory = new RecordingDomainValidatorFactory(BuildV2DnsFactory());
            var plugin = new CERTInextCAPlugin(new CERTInextClient(config), recordingFactory, config);

            var result = await plugin.Enroll(
                csr:            GenerateCsrPem(_v2Domain),
                subject:        $"CN={_v2Domain}",
                san:            new Dictionary<string, string[]> { ["dns"] = new[] { _v2Domain } },
                productInfo:    BuildV2ProductInfo(),
                requestFormat:  RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Should().NotBeNull();
            result.CARequestID.Should().NotBeNullOrWhiteSpace(
                "the CA must accept the order even with DCV off — DCV-off must not block enrollment");

            recordingFactory.StagedCalls.Should().BeEmpty(
                "with DcvEnabled=false the plugin must never stage a DCV TXT record — this test's name promised " +
                "that, but nothing previously checked it");
            recordingFactory.CleanedUpFqdns.Should().BeEmpty(
                "with DcvEnabled=false the plugin must never attempt DCV cleanup either");
        }

        // ---------------------------------------------------------------------------
        // Gap 7 — GetSingleRecord drives DCV for an existing pending V2 order
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task GetSingleRecord_V2_DrivesDcvForPendingOrder()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            string orderId = Environment.GetEnvironmentVariable("CERTINEXT_V2_PENDING_ORDER_ID");
            Skip.If(string.IsNullOrWhiteSpace(orderId),
                "Set CERTINEXT_V2_PENDING_ORDER_ID to a real pending-dcv V2 order to run this test.");
            Skip.If(!_dcvEnabled,
                "CERTINEXT_CF_API_TOKEN and CERTINEXT_CF_ZONE_ID must be set so the plugin can publish a real TXT record.");

            var plugin = BuildV2DcvPlugin(dcvEnabled: true);
            var record = await plugin.GetSingleRecord(orderId);

            record.Should().NotBeNull();
            _output.WriteLine($"CARequestID: {record.CARequestID}");
            _output.WriteLine($"Status:      {record.Status}");

            new[] { (int)EndEntityStatus.GENERATED, (int)EndEntityStatus.EXTERNALVALIDATION }
                .Should().Contain(record.Status,
                    "deferred-DCV retry should leave the V2 order in a valid pending or issued state");
        }

        // ---------------------------------------------------------------------------
        // Gap 8 — End-to-end DCV-on enrollment, issued cert appears in sync
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task EnrollWithDcvOn_V2_OrderIssuedEndToEnd_AndAppearsInSync()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");
            Skip.If(!_dcvEnabled,
                "CERTINEXT_CF_API_TOKEN + CERTINEXT_CF_ZONE_ID required — DCV-on test must publish real TXT records.");

            var config = BuildV2Config(dcvEnabled: true);
            using var probeClient = new CERTInextClient(config);
            var (domainVerified, rawStatus) = await V2DomainStatusHelper.GetDcvStatusAsync(probeClient, _v2Domain);
            _output.WriteLine($"Pre-enroll domain status for '{_v2Domain}': dcvStatus={rawStatus ?? "<no row>"}");

            var recordingFactory = new RecordingDomainValidatorFactory(BuildV2DnsFactory());
            var plugin = new CERTInextCAPlugin(new CERTInextClient(config), recordingFactory, config);

            var enrollResult = await plugin.Enroll(
                csr:            GenerateCsrPem(_v2Domain),
                subject:        $"CN={_v2Domain}",
                san:            new Dictionary<string, string[]> { ["dns"] = new[] { _v2Domain } },
                productInfo:    BuildV2ProductInfo(),
                requestFormat:  RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            enrollResult.Should().NotBeNull();
            enrollResult.CARequestID.Should().NotBeNullOrWhiteSpace();
            _output.WriteLine($"Enroll CARequestID={enrollResult.CARequestID}, Status={enrollResult.Status}");

            new[] { (int)EndEntityStatus.EXTERNALVALIDATION, (int)EndEntityStatus.GENERATED }
                .Should().Contain(enrollResult.Status,
                    $"DCV-on V2 Enroll must return pending or issued; got {enrollResult.Status}");

            var staged = recordingFactory.StagedCalls;
            var cleaned = recordingFactory.CleanedUpFqdns;
            _output.WriteLine($"DNS provider calls: staged={staged.Count}, cleaned={cleaned.Count}");

            if (domainVerified)
            {
                // Reuse path (issues/0020): no fresh TXT record should be staged for an
                // already-verified domain.
                staged.Should().BeEmpty(
                    $"domain '{_v2Domain}' was already VERIFIED before enrollment (reuse path) — no TXT record " +
                    "should be staged. See issues/0020.");
            }
            else
            {
                staged.Should().NotBeEmpty(
                    $"domain '{_v2Domain}' was not yet VERIFIED (dcvStatus={rawStatus ?? "<no row>"}) — Enroll " +
                    "must stage a TXT record to exercise the publish path.");
                cleaned.Should().NotBeEmpty(
                    "a staged DCV TXT record must be cleaned up after the publish-path attempt.");
            }

            // Delta sync — this sandbox account has 1000+ historical orders.
            var synced = await RunSyncAsync(plugin, lastSync: DateTime.UtcNow.AddDays(-1), fullSync: false);
            var record = synced.FirstOrDefault(r => r.CARequestID == enrollResult.CARequestID);
            record.Should().NotBeNull(
                $"the enrolled V2 order ({enrollResult.CARequestID}) must appear in plugin.Synchronize results");

            _output.WriteLine($"Synced record status: {record!.Status}");

            if (record.Status == (int)EndEntityStatus.GENERATED)
            {
                record.Certificate.Should().NotBeNullOrWhiteSpace(
                    "Synchronize must populate the cert body for an issued V2 order (mirrors issue 0001 for V1)");
            }
        }

        // ---------------------------------------------------------------------------
        // Gap 14 — Key-algorithm issuance matrix, V2 path (opt-in)
        // ---------------------------------------------------------------------------

        [SkippableTheory]
        [MemberData(nameof(KeyAlgorithms.AsMemberData), MemberType = typeof(KeyAlgorithms))]
        public async Task EnrollWithDcvOn_V2_IssuesPerKeyAlgorithm(string tag)
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");
            Skip.If(Environment.GetEnvironmentVariable("CERTINEXT_V2_ALGO_MATRIX") != "1",
                "Opt-in: set CERTINEXT_V2_ALGO_MATRIX=1 to issue one real V2 cert per key algorithm.");
            Skip.If(!_dcvEnabled,
                "CERTINEXT_CF_API_TOKEN + CERTINEXT_CF_ZONE_ID required — DCV issuance must publish real TXT records.");

            var spec = KeyAlgorithms.For(tag);
            string suffix = Guid.NewGuid().ToString("N").Substring(0, 8);
            string cn = $"algo-{KeyAlgorithms.Slug(tag)}-{suffix}.{_v2Domain}";
            string csr = KeyAlgorithms.GenerateCsrPem(cn, spec);

            var plugin = BuildV2DcvPlugin(dcvEnabled: true);

            EnrollmentResult enrollResult;
            try
            {
                enrollResult = await plugin.Enroll(
                    csr:            csr,
                    subject:        $"CN={cn}",
                    san:            new Dictionary<string, string[]> { ["dns"] = new[] { cn } },
                    productInfo:    BuildV2ProductInfo(),
                    requestFormat:  RequestFormat.PKCS10,
                    enrollmentType: EnrollmentType.New);
            }
            catch (Exception ex)
            {
                string reason = KeyAlgorithms.ClassifyRejection(ex.Message);
                _output.WriteLine($"[SKIP] {tag}: {reason} — {ex.Message}");
                Skip.If(true, $"CERTInext did not issue a {tag} V2 cert: {reason}. CA message: {ex.Message}");
                return; // unreachable
            }

            enrollResult.Should().NotBeNull();
            enrollResult.CARequestID.Should().NotBeNullOrWhiteSpace($"{tag}: CA must return a CARequestID when it accepts the order");
            _output.WriteLine($"[{tag}] enrolled cn={cn} id={enrollResult.CARequestID} status={enrollResult.Status}");

            const int maxPolls = 6;
            const int delaySeconds = 15;
            AnyCAPluginCertificate record = null;
            for (int poll = 1; poll <= maxPolls; poll++)
            {
                record = await plugin.GetSingleRecord(enrollResult.CARequestID);
                int status = record?.Status ?? -1;
                _output.WriteLine($"[{tag}] poll #{poll}: status={status} certLen={record?.Certificate?.Length ?? 0}");

                if (status == (int)EndEntityStatus.GENERATED && !string.IsNullOrWhiteSpace(record?.Certificate))
                    break;
                if (status == (int)EndEntityStatus.FAILED)
                {
                    Skip.If(true, $"CERTInext FAILED the {tag} V2 order — algorithm not issuable on this account/profile.");
                    return; // unreachable
                }
                if (poll < maxPolls)
                    await Task.Delay(TimeSpan.FromSeconds(delaySeconds));
            }

            record.Should().NotBeNull($"{tag}: enrolled order {enrollResult.CARequestID} must be retrievable");
            if (record!.Status != (int)EndEntityStatus.GENERATED)
            {
                Skip.If(true, $"CERTInext accepted the {tag} V2 order but it did not reach GENERATED within the polling window " +
                    $"(Status={record.Status}).");
                return; // unreachable
            }

            record.Certificate.Should().NotBeNullOrWhiteSpace($"{tag}: issued V2 cert must carry a PEM body");
            AssertIssuedCertMatchesAlgorithm(record.Certificate, spec, tag);
            _output.WriteLine($"--- {tag}: V2 DCV-on issuance OK — order {enrollResult.CARequestID} GENERATED. ---");
        }

        // ---------------------------------------------------------------------------
        // Gap 15 — Bulk V2 enrollment + pagination smoke test (opt-in)
        // ---------------------------------------------------------------------------

        [SkippableFact]
        public async Task BulkV2Enrollment_AllOrdersIssue_AndPaginationWorks()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");
            Skip.If(Environment.GetEnvironmentVariable("CERTINEXT_V2_RUN_BULK_TEST") != "1",
                "Opt-in: set CERTINEXT_V2_RUN_BULK_TEST=1 to run the V2 volume/pagination test.");
            Skip.If(!_dcvEnabled,
                "CERTINEXT_CF_API_TOKEN + CERTINEXT_CF_ZONE_ID required — bulk test must publish real TXT records.");

            int count = int.TryParse(Environment.GetEnvironmentVariable("CERTINEXT_V2_BULK_TEST_COUNT"), out int c) ? c : 101;
            int parallel = int.TryParse(Environment.GetEnvironmentVariable("CERTINEXT_V2_BULK_TEST_PARALLEL"), out int p) ? p : 5;

            // PageSize=100 ensures the 101st order forces a second page during Synchronize.
            var plugin = BuildV2DcvPlugin(dcvEnabled: true, propagationDelaySeconds: 5, pageSize: 100);

            var enrolled = new ConcurrentBag<(int idx, string cn, EnrollmentResult result)>();
            var failures = new ConcurrentBag<(int idx, string error)>();
            var sw = System.Diagnostics.Stopwatch.StartNew();

            using (var sem = new SemaphoreSlim(parallel, parallel))
            {
                var tasks = Enumerable.Range(0, count).Select(async i =>
                {
                    await sem.WaitAsync();
                    try
                    {
                        string suffix = Guid.NewGuid().ToString("N").Substring(0, 8);
                        string cn = $"v2bulk-{suffix}.{_v2Domain}";
                        string csr = GenerateCsrPem(cn);

                        var result = await plugin.Enroll(
                            csr:            csr,
                            subject:        $"CN={cn}",
                            san:            new Dictionary<string, string[]> { ["dns"] = new[] { cn } },
                            productInfo:    BuildV2ProductInfo(),
                            requestFormat:  RequestFormat.PKCS10,
                            enrollmentType: EnrollmentType.New);

                        enrolled.Add((i, cn, result));
                        _output.WriteLine($"[{i:000}] OK   cn={cn}  id={result.CARequestID}  status={result.Status}");
                    }
                    catch (Exception ex)
                    {
                        failures.Add((i, ex.Message));
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

            failures.Should().BeEmpty($"every V2 Enroll() call must succeed; got {failures.Count} hard failures.");
            enrolled.Count.Should().Be(count, $"expected {count} successful V2 Enroll() calls");

            var enrolledIds = enrolled
                .Where(e => !string.IsNullOrEmpty(e.result.CARequestID))
                .Select(e => e.result.CARequestID)
                .ToHashSet();
            enrolledIds.Count.Should().Be(count, "every V2 enrollment must return a CARequestID");

            const int maxSyncPasses = 8;
            const int delayBetweenPassesSeconds = 30;

            List<AnyCAPluginCertificate> synced = null;
            int passesUsed = 0;

            for (int pass = 1; pass <= maxSyncPasses; pass++)
            {
                passesUsed = pass;
                synced = await RunSyncAsync(plugin, lastSync: DateTime.UtcNow.AddDays(-1), fullSync: false);

                int generated = synced.Count(r => enrolledIds.Contains(r.CARequestID) && r.Status == (int)EndEntityStatus.GENERATED);
                int failed    = synced.Count(r => enrolledIds.Contains(r.CARequestID) && r.Status == (int)EndEntityStatus.FAILED);
                int pending   = enrolledIds.Count - generated - failed;

                _output.WriteLine($"--- Sync pass #{pass}: {generated}/{enrolledIds.Count} GENERATED, {failed} FAILED, {pending} pending ---");

                if (failed > 0)
                {
                    var failedIds = synced
                        .Where(r => enrolledIds.Contains(r.CARequestID) && r.Status == (int)EndEntityStatus.FAILED)
                        .Select(r => r.CARequestID)
                        .Take(5);
                    Assert.Fail($"Pass #{pass}: {failed} V2 order(s) reached FAILED status: {string.Join(", ", failedIds)}");
                }

                if (pending == 0)
                    break;

                if (pass < maxSyncPasses)
                    await Task.Delay(TimeSpan.FromSeconds(delayBetweenPassesSeconds));
            }

            var syncedIds = synced!.Select(r => r.CARequestID).ToHashSet();
            var missing = enrolledIds.Where(id => !syncedIds.Contains(id)).ToList();
            missing.Should().BeEmpty(
                $"{missing.Count} enrolled V2 orders did not appear in sync results: {string.Join(", ", missing.Take(5))}");

            var lookup = synced!.Where(r => r.CARequestID != null).ToDictionary(r => r.CARequestID, r => r);
            var notIssued = enrolledIds
                .Where(id => lookup.TryGetValue(id, out var rec) && rec.Status != (int)EndEntityStatus.GENERATED)
                .Select(id => lookup[id])
                .ToList();

            notIssued.Should().BeEmpty(
                $"every enrolled V2 order should auto-issue after {maxSyncPasses} sync passes; {notIssued.Count} did not.");

            _output.WriteLine($"--- SUCCESS: {count}/{count} V2 orders enrolled and issued in {passesUsed} sync pass(es). ---");
        }
    }
}
#endif
