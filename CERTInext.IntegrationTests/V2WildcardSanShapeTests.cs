// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.
//
// Wildcard-in-the-SAN-only enrollments (issue 0099): the CSR's CN is the apex and the wildcard is
// only in the SAN set. CERTInext's wrapper decides "wildcard" from certificate.domain alone, so the
// plugin must send the wildcard as the domain. These probes place real sandbox orders and record
// what CERTInext accepts and which product it resolves; gated by CERTINEXT_V2_WILDCARD_SAN_PROBE=1.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Live probes for a DV order whose CSR CN is the apex and whose SAN set carries
    /// <c>*.apex</c>. Each places one sandbox order (or is rejected) and cancels it afterwards.
    /// The plugin's log, including the "V2 order placed" line with <c>ResolvedProductCode</c>, is
    /// routed to the test output.
    /// </summary>
    public class V2WildcardSanShapeTests : IClassFixture<IntegrationTestFixture>, IDisposable
    {
        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;
        private readonly Action _restoreLogging;
        private readonly string _v2ApiUrl;
        private readonly string _v2ClientId;
        private readonly string _v2ClientSecret;
        private readonly string _v2Domain;
        private readonly bool _enabled;

        public V2WildcardSanShapeTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;
            _restoreLogging = TestOutputLogging.RouteTo(output);

            var env = V2EnvHelper.LoadAndPromote();
            _v2ApiUrl = V2EnvHelper.GetEnv(env, "CERTINEXT_API_URL");
            _v2ClientId = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_ID");
            _v2ClientSecret = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_SECRET");
            _v2Domain = V2EnvHelper.GetEnv(env, "CERTINEXT_DCV_DOMAIN", "test.example.com");
            _enabled = !string.IsNullOrWhiteSpace(V2EnvHelper.GetEnv(env, "CERTINEXT_USE_V2_API"))
                       && !string.IsNullOrWhiteSpace(_v2ApiUrl)
                       && !string.IsNullOrWhiteSpace(_v2ClientId)
                       && !string.IsNullOrWhiteSpace(_v2ClientSecret);
        }

        public void Dispose() => _restoreLogging();

        private CERTInextConfig BuildV2Config() => new CERTInextConfig
        {
            ApiUrl                = _v2ApiUrl,
            UseV2Api              = true,
            V2InlineCsr           = V2EnvHelper.InlineCsrFromEnv,
            OAuthClientId         = _v2ClientId,
            OAuthClientSecret     = _v2ClientSecret,
            RequestorName         = _fixture.IsConfigured ? _fixture.Config.RequestorName : "Keyfactor Test",
            RequestorEmail        = _fixture.IsConfigured ? _fixture.Config.RequestorEmail : "test@example.com",
            RequestorIsdCode      = "1",
            RequestorMobileNumber = "0000000000",
            SignerPlace           = "Gateway Lab",
            SignerIp              = "127.0.0.1",
            PageSize              = 100,
            V2SyncLookbackHours   = 1,
            DcvEnabled            = false
        };

        /// <summary>RSA-2048 CSR with <c>CN=<paramref name="commonName"/></c> and the given DNS SANs.</summary>
        private static string GenerateCsrPem(string commonName, IReadOnlyList<string> dnsSans)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            var keyPair = keyGen.GenerateKeyPair();

            var names = new GeneralNames(dnsSans.Select(d => new GeneralName(GeneralName.DnsName, d)).ToArray());
            var extGen = new X509ExtensionsGenerator();
            extGen.AddExtension(X509Extensions.SubjectAlternativeName, false, names);
            var attrs = new DerSet(new AttributePkcs(
                PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extGen.Generate())));

            var csr = new Pkcs10CertificationRequest(
                "SHA256withRSA", new X509Name($"CN={commonName}"), keyPair.Public, attrs, keyPair.Private);
            return "-----BEGIN CERTIFICATE REQUEST-----\n"
                + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                + "\n-----END CERTIFICATE REQUEST-----";
        }

        /// <summary>
        /// Read-only: lists the account's live catalog entries with their productTypeID, so a run
        /// shows which Wildcard UCC products (typeID 21 DV / 22 OV) the plugin can resolve to.
        /// </summary>
        [SkippableFact]
        public async Task Catalog_ListsProductTypeIds()
        {
            Skip.If(!_enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");

            using var client = new CERTInextClient(BuildV2Config());
            var products = await client.GetProductDetailsV2Async();
            foreach (var p in products.OrderBy(p => p.ProductTypeId).ThenBy(p => p.ProductCode))
                _output.WriteLine($"CATALOG code={p.ProductCode} typeId={p.ProductTypeId} active={p.Active} " +
                                  $"type='{p.ProductType}' name='{p.ProductName}'");
            products.Should().NotBeEmpty();
        }

        public static IEnumerable<object[]> Shapes() => new[]
        {
            // shape, productId, pinned product code (null = unpinned), extra SAN, DomainName override
            new object[] { "A-pluginDefault-apexCn-wildcardSan",      Constants.Products.DvSsl,           null,  false, false },
            new object[] { "E-pluginDefault-apexCn-wildcardPlusOther", Constants.Products.DvSsl,          null,  true,  false },
            new object[] { "B-wildcardDomain-apexInCsr",              Constants.Products.DvSsl,           null,  false, true  },
            new object[] { "C-wildcardDomain-plusExtraSan",           Constants.Products.DvSsl,           null,  true,  true  },
            new object[] { "D-pinnedWildcardUcc-apexDomain",          Constants.Products.DvSslWildcardUcc, "845", false, false },
        };

        /// <summary>
        /// CN = a fresh apex under <c>CERTINEXT_DCV_DOMAIN</c>, SANs = apex + <c>*.apex</c> (+ one
        /// extra name for shape C). With <c>forceWildcardDomain</c> the <c>DomainName</c> enrollment
        /// parameter is set to <c>*.apex</c>, which the pre-fix plugin honours over the CN. Records
        /// the outcome rather than asserting on CA behaviour; the only assertion is that a placed
        /// order is cleaned up. Expected sandbox order count: 0 or 1 per row.
        /// </summary>
        [SkippableTheory]
        [MemberData(nameof(Shapes))]
        public async Task Probe_ApexCn_WildcardSan(
            string shape, string productId, string productCode, bool extraSan, bool forceWildcardDomain)
        {
            Skip.If(!_enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");
            Skip.If(Environment.GetEnvironmentVariable("CERTINEXT_V2_WILDCARD_SAN_PROBE") != "1",
                "CERTINEXT_V2_WILDCARD_SAN_PROBE=1 not set — this places real wildcard DV sandbox orders. Skipping.");

            string ts = DateTime.UtcNow.ToString("yyyyMMddHHmmssfff");
            string apex = $"wcsan-{ts}.{_v2Domain}";
            string wildcard = "*." + apex;
            var sans = new List<string> { apex, wildcard };
            if (extraSan) sans.Add($"extra-{ts}.{_v2Domain}");

            var parameters = new Dictionary<string, string> { [Constants.EnrollmentParam.ValidityYears] = "1" };
            if (productCode != null) parameters[Constants.EnrollmentParam.ProductCode] = productCode;
            if (forceWildcardDomain) parameters[Constants.EnrollmentParam.DomainName] = wildcard;

            var config = BuildV2Config();
            var plugin = new CERTInextCAPlugin(new CERTInextClient(config), config);

            _output.WriteLine($"SHAPE {shape}: CN={apex}, SANs=[{string.Join(", ", sans)}], " +
                              $"ProductId={productId}, ProductCode={productCode ?? "(none)"}, " +
                              $"DomainName={(forceWildcardDomain ? wildcard : "(CN)")}");

            string orderId = null;
            try
            {
                EnrollmentResult result;
                try
                {
                    result = await plugin.Enroll(
                        GenerateCsrPem(apex, sans), $"CN={apex}",
                        new Dictionary<string, string[]> { ["dns"] = sans.ToArray() },
                        new EnrollmentProductInfo { ProductID = productId, ProductParameters = parameters },
                        RequestFormat.PKCS10, EnrollmentType.New);
                }
                catch (Exception ex)
                {
                    _output.WriteLine($"RESULT {shape}: THREW {ex.GetType().Name}: {ex.Message}");
                    return;
                }

                orderId = string.IsNullOrWhiteSpace(result.CARequestID) ? null : result.CARequestID;
                _output.WriteLine($"RESULT {shape}: Status={result.Status}, OrderId={orderId ?? "(none)"}, " +
                                  $"Message={result.StatusMessage}");

                if (orderId != null)
                {
                    using var client = new CERTInextClient(config);
                    var (_, tracked) = await client.ResolveAndTrackOrderV2WithFamilyAsync(orderId);
                    _output.WriteLine($"TRACK {shape}: Status={tracked.Status}, Domain={tracked.Domain}");
                }
            }
            finally
            {
                if (orderId != null)
                {
                    using var client = new CERTInextClient(BuildV2Config());
                    await V2OrderCleanup.RevokeOrCancelAsync(
                        client, orderId, "V2 wildcard-SAN shape probe cleanup.", _output.WriteLine);
                }
            }
        }
    }
}
