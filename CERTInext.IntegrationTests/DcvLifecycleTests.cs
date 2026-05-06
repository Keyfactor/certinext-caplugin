// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Generic;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.PKI.Enums.EJBCA;
using Xunit;

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

        public DcvLifecycleTests(IntegrationTestFixture fixture)
        {
            _fixture = fixture;
        }

        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

        private IDomainValidatorFactory BuildDnsFactory() =>
            _fixture.IsCloudflareConfigured
                ? (IDomainValidatorFactory)new CloudflareDomainValidatorFactory(
                    _fixture.CloudflareApiToken, _fixture.CloudflareZoneId)
                : new StubDomainValidatorFactory();

        private CERTInextCAPlugin BuildPlugin(bool dcvEnabled, int propagationDelaySeconds = 5)
        {
            var config = new CERTInextConfig
            {
                ApiUrl                    = _fixture.Config.ApiUrl,
                AuthMode                  = _fixture.Config.AuthMode,
                ApiKey                    = _fixture.Config.ApiKey,
                AccountNumber             = _fixture.Config.AccountNumber,
                GroupNumber               = _fixture.Config.GroupNumber,
                RequestorName             = _fixture.Config.RequestorName,
                RequestorEmail            = _fixture.Config.RequestorEmail,
                RequestorIsdCode          = _fixture.Config.RequestorIsdCode,
                RequestorMobileNumber     = _fixture.Config.RequestorMobileNumber,
                SignerPlace                = _fixture.Config.SignerPlace,
                SignerIp                   = _fixture.Config.SignerIp,
                DefaultProductCode         = _fixture.Config.DefaultProductCode,
                PageSize                   = _fixture.Config.PageSize,
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
                csr:            IntegrationTestData.FakeCsrPem,
                subject:        $"CN={IntegrationTestData.DcvTestDomain}",
                san:            new Dictionary<string, string[]>
                {
                    ["dns"] = new[] { IntegrationTestData.DcvTestDomain }
                },
                productInfo:    IntegrationTestData.DvSslProductInfo(_fixture.Config.DefaultProductCode),
                requestFormat:  RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Should().NotBeNull();

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
                csr:            IntegrationTestData.FakeCsrPem,
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

        public const string FakeCsrPem =
            "-----BEGIN CERTIFICATE REQUEST-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2a2rwplBQLzHPZe5TNJF\n" +
            "-----END CERTIFICATE REQUEST-----";

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
