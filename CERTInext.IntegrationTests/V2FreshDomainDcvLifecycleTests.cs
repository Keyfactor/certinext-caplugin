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
//
// V2 release-candidate readiness: DCV against a FRESH, never-before-seen domain. Every DCV
// test in V2DcvLifecycleTests.cs targets CERTINEXT_DCV_DOMAIN, which this sandbox account has
// reused across dozens of prior test runs and is therefore typically already VERIFIED
// account-wide — so those tests observe staged=0 (the reuse path, issue 0020) and never actually
// exercise the TXT publish/verify/cleanup path. This file's test targets a freshly-generated
// subdomain instead, so a real TXT challenge must be staged and cleaned up (staged>0).

#if SUPPORTS_DCV
using System;
using System.Collections.Generic;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    public class V2FreshDomainDcvLifecycleTests : IClassFixture<IntegrationTestFixture>, IDisposable
    {
        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;
        private readonly List<IDisposable> _toDispose = new List<IDisposable>();

        private readonly string _v2ApiUrl;
        private readonly string _v2ClientId;
        private readonly string _v2ClientSecret;
        private readonly string _v2Domain;
        private readonly bool _v2Enabled;
        private readonly string _cfApiToken;
        private readonly string _cfZoneId;
        private readonly bool _dcvEnabled;

        public V2FreshDomainDcvLifecycleTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;

            var env = V2EnvHelper.LoadAndPromote();

            _v2ApiUrl       = V2EnvHelper.GetEnv(env, "CERTINEXT_API_URL");
            _v2ClientId     = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_ID");
            _v2ClientSecret = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_SECRET");
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

        private CERTInextConfig BuildV2Config()
        {
            return new CERTInextConfig
            {
                ApiUrl            = _v2ApiUrl,
                UseV2Api          = true,
                OAuthClientId     = _v2ClientId,
                OAuthClientSecret = _v2ClientSecret,

                V2SyncLookbackHours = 1,

                RequestorName         = _fixture.IsConfigured ? _fixture.Config.RequestorName : "Keyfactor Test",
                RequestorEmail        = _fixture.IsConfigured ? _fixture.Config.RequestorEmail : "test@example.com",
                RequestorIsdCode      = "1",
                RequestorMobileNumber = "0000000000",
                SignerPlace           = "Gateway Lab",
                SignerIp              = "127.0.0.1",

                PageSize = 100,

                DcvEnabled                 = true,
                DcvPropagationDelaySeconds = 5,
                DcvTimeoutMinutes          = 3
            };
        }

        /// <summary>
        /// Same revoke-if-issued / cancel-otherwise cleanup as V2FullLifecycleTests.
        /// CleanupOrderAsync — single attempt only, never retries a cancel, logs rather than
        /// throws so a cleanup problem never masks the test's own assertion result. Returns
        /// whether cleanup completed without throwing (true = revoked or cancelled successfully,
        /// or nothing to do), so a caller that wants to assert "nothing leaks" — e.g. the
        /// wildcard fresh-subdomain test below — has something other than log text to check.
        /// </summary>
        private async System.Threading.Tasks.Task<bool> CleanupOrderAsync(CERTInextCAPlugin plugin, string orderId)
        {
            if (string.IsNullOrWhiteSpace(orderId))
                return true;

            try
            {
                var current = await plugin.GetSingleRecord(orderId);
                if (current?.Status == (int)EndEntityStatus.GENERATED)
                {
                    int revokeResult = await plugin.Revoke(orderId, hexSerialNumber: string.Empty, revocationReason: 4 /* superseded */);
                    _output.WriteLine($"Cleanup: revoked issued order {orderId} -> {revokeResult}.");
                }
                else
                {
                    await V2RawProbeHelpers.CancelSslOrderRawAsync(
                        _v2ApiUrl, _v2ClientId, _v2ClientSecret, orderId,
                        "V2 fresh-domain DCV test cleanup — order not issued, cancelling.");
                    _output.WriteLine($"Cleanup: cancelled non-issued order {orderId} (status={current?.Status}).");
                }
                return true;
            }
            catch (Exception ex)
            {
                _output.WriteLine(
                    $"Cleanup FAILED for order {orderId}: {ex.GetType().Name}: {ex.Message}. " +
                    "Revoke/cancel it by hand in the CERTInext portal if it should not remain pending.");
                return false;
            }
        }

        // ---------------------------------------------------------------------------
        // 7. DCV against a fresh, never-before-verified subdomain
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Enrolls a DV order for a freshly-generated subdomain of CERTINEXT_DCV_DOMAIN that has
        /// never been requested on this sandbox account before, with DcvEnabled=true and a real
        /// Cloudflare-backed <see cref="IDomainValidatorFactory"/> wrapped in
        /// <see cref="RecordingDomainValidatorFactory"/>. Because the domain is guaranteed unseen,
        /// this is the one DCV test in the V2 suite that actually exercises the publish path:
        /// every existing V2DcvLifecycleTests case targets the long-reused CERTINEXT_DCV_DOMAIN,
        /// which this account has verified account-wide, so those always take the reuse path
        /// (issue 0020) and observe staged=0. Asserts staged&gt;0 and cleaned&gt;0.
        /// Expected sandbox order count: 1.
        /// </summary>
        [SkippableFact]
        public async System.Threading.Tasks.Task EnrollWithDcvOn_V2_FreshUnverifiedSubdomain_StagesAndCleansUpTxt()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");
            Skip.If(!_dcvEnabled,
                "CERTINEXT_CF_API_TOKEN and CERTINEXT_CF_ZONE_ID must be set so the plugin can publish a real TXT record.");
            Skip.If(Environment.GetEnvironmentVariable("CERTINEXT_V2_LIFECYCLE_FRESH_DCV") != "1",
                "CERTINEXT_V2_LIFECYCLE_FRESH_DCV=1 not set — this places a real sandbox order and publishes a live DNS TXT record. Skipping.");

            string freshDomain = $"dcv-fresh-{DateTime.UtcNow:yyyyMMddHHmmssfff}.{_v2Domain}";

            var config = BuildV2Config();
            var recordingFactory = new RecordingDomainValidatorFactory(BuildV2DnsFactory());
            var plugin = new CERTInextCAPlugin(new CERTInextClient(config), recordingFactory, config);

            string orderId = null;
            try
            {
                var result = await plugin.Enroll(
                    csr:            GenerateCsrPem(freshDomain),
                    subject:        $"CN={freshDomain}",
                    san:            new Dictionary<string, string[]> { ["dns"] = new[] { freshDomain } },
                    productInfo:    new EnrollmentProductInfo { ProductID = Constants.Products.DvSsl },
                    requestFormat:  RequestFormat.PKCS10,
                    enrollmentType: EnrollmentType.New);

                result.Should().NotBeNull();
                result.CARequestID.Should().NotBeNullOrWhiteSpace("Enroll must return a CARequestID even if DCV verification does not complete inline");
                orderId = result.CARequestID;
                _output.WriteLine($"Fresh-domain order {orderId} for '{freshDomain}': Status={result.Status}, Message={result.StatusMessage}");

                var staged = recordingFactory.StagedCalls;
                var cleaned = recordingFactory.CleanedUpFqdns;
                _output.WriteLine($"DNS provider calls: staged={staged.Count}, cleaned={cleaned.Count}");

                staged.Should().NotBeEmpty(
                    $"domain '{freshDomain}' is freshly generated and cannot already be VERIFIED on this " +
                    "account — unlike every pre-existing V2DcvLifecycleTests case (which targets the " +
                    "long-reused CERTINEXT_DCV_DOMAIN and always observes staged=0 via the reuse path, " +
                    "issue 0020), Enroll must actually stage a TXT record here.");
                cleaned.Should().NotBeEmpty(
                    "a staged DCV TXT record for a fresh domain must be cleaned up after the attempt.");

                new[] { (int)EndEntityStatus.EXTERNALVALIDATION, (int)EndEntityStatus.GENERATED }
                    .Should().Contain(result.Status,
                        $"DCV-on Enroll for a fresh domain must return pending or issued; got {result.Status}. Message: {result.StatusMessage}");
            }
            finally
            {
                await CleanupOrderAsync(plugin, orderId);
            }
        }

        // ---------------------------------------------------------------------------
        // 8. Wildcard DV DCV against a fresh, never-before-verified subdomain
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Wildcard-only CSR shape (CN = SAN = the wildcard) on a freshly-generated,
        /// never-before-seen subdomain — same freshness rationale as
        /// <see cref="EnrollWithDcvOn_V2_FreshUnverifiedSubdomain_StagesAndCleansUpTxt"/> above,
        /// but for <see cref="Constants.Products.DvSslWildcard"/>. What TXT hostname CERTInext's
        /// DCV flow actually stages for a wildcard domain (does it strip the leading "*." before
        /// handing the plugin a record name, or pass it through literally — which would be an
        /// invalid DNS label?) is NOT confirmed live by any existing test in this repo, so this
        /// test does not assert on that shape. It only records: (a) the FQDN
        /// <see cref="RecordingDomainValidatorFactory.StagedCalls"/> shows the plugin actually
        /// called <c>StageValidation</c> with, flagging whether it contains a literal '*', and
        /// (b) what Track Order's <c>verifications.domain.domains[].domain</c> echoes back for
        /// the same order. The only hard assertion is that cleanup (revoke-if-issued or cancel)
        /// succeeds, so this probe never leaks a live order on the sandbox regardless of what the
        /// TXT-hostname observation turns out to be.
        /// Expected sandbox order count: 1.
        /// </summary>
        [SkippableFact]
        public async System.Threading.Tasks.Task EnrollWithDcvOn_V2_WildcardFreshSubdomain_RecordsTxtHostnameAndCleansUp()
        {
            Skip.If(!_v2Enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");
            Skip.If(!_dcvEnabled,
                "CERTINEXT_CF_API_TOKEN and CERTINEXT_CF_ZONE_ID must be set so the plugin can publish a real TXT record.");
            Skip.If(Environment.GetEnvironmentVariable("CERTINEXT_V2_LIFECYCLE_FRESH_DCV") != "1",
                "CERTINEXT_V2_LIFECYCLE_FRESH_DCV=1 not set — this places a real sandbox order and publishes a live DNS TXT record. Skipping.");

            string freshSubdomain = $"dcv-fresh-{DateTime.UtcNow:yyyyMMddHHmmssfff}.{_v2Domain}";
            string wildcard = $"*.{freshSubdomain}";

            var config = BuildV2Config();
            var recordingFactory = new RecordingDomainValidatorFactory(BuildV2DnsFactory());
            var client = new CERTInextClient(config);
            var plugin = new CERTInextCAPlugin(client, recordingFactory, config);

            string orderId = null;
            try
            {
                var result = await plugin.Enroll(
                    csr:            GenerateCsrPem(wildcard),
                    subject:        $"CN={wildcard}",
                    san:            new Dictionary<string, string[]> { ["dns"] = new[] { wildcard } },
                    productInfo:    new EnrollmentProductInfo { ProductID = Constants.Products.DvSslWildcard },
                    requestFormat:  RequestFormat.PKCS10,
                    enrollmentType: EnrollmentType.New);

                result.Should().NotBeNull();
                _output.WriteLine($"Wildcard fresh-subdomain order ({wildcard}): Status={result.Status}, Message={result.StatusMessage}");

                if (!string.IsNullOrWhiteSpace(result.CARequestID))
                    orderId = result.CARequestID;

                var staged = recordingFactory.StagedCalls;
                var cleaned = recordingFactory.CleanedUpFqdns;
                _output.WriteLine($"DNS provider calls: staged={staged.Count}, cleaned={cleaned.Count}");
                foreach (var call in staged)
                    _output.WriteLine(
                        $"OBSERVATION: staged TXT hostname Fqdn='{call.Fqdn}' " +
                        $"(contains literal '*': {call.Fqdn?.Contains('*') == true} — UNVERIFIED territory, see this test's doc comment).");
                foreach (var fqdn in cleaned)
                    _output.WriteLine($"Cleaned-up TXT hostname: Fqdn='{fqdn}'.");

                if (!string.IsNullOrWhiteSpace(orderId))
                {
                    try
                    {
                        var tracked = await client.ResolveAndTrackOrderV2Async(orderId);
                        var domainEntries = tracked?.Verifications?.Domain?.Domains;
                        if (domainEntries != null && domainEntries.Count > 0)
                        {
                            foreach (var entry in domainEntries)
                                _output.WriteLine(
                                    $"OBSERVATION: Track Order verifications.domain.domains[]: domain='{entry.Domain}', dcvStatus={entry.DcvStatus ?? "<none>"}.");
                        }
                        else
                        {
                            _output.WriteLine("Track Order returned no verifications.domain.domains[] entries for this order.");
                        }
                    }
                    catch (Exception ex)
                    {
                        _output.WriteLine($"Track Order (for verifications detail) FAILED: {ex.GetType().Name}: {ex.Message}.");
                    }
                }
            }
            finally
            {
                bool cleanedUp = await CleanupOrderAsync(plugin, orderId);
                cleanedUp.Should().BeTrue(
                    "cleanup (revoke-if-issued or cancel) must succeed so this wildcard fresh-subdomain probe " +
                    "never leaves a live order on the sandbox, regardless of what the TXT-hostname/Track-Order " +
                    "observations above turn out to show — see the 'Cleanup FAILED' output above if this fails.");
            }
        }
    }
}
#endif
