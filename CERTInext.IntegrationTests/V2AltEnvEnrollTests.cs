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
// V2 DV enrollment against an account described by an arbitrary env file, rather than
// ~/.env_certinext[_v2]. Covers the plugin path and the equivalent direct API call, plus
// read-only probes of the account's catalog and group membership. Orders placed here are
// deliberately NOT revoked or cancelled afterwards.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums;
using Keyfactor.PKI.Enums.EJBCA;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using RestSharp;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Env vars (read from the real environment; account values come from the file only and are
    /// never promoted into process env, so other classes' sandbox fixtures are unaffected):
    /// <list type="bullet">
    ///   <item><c>CERTINEXT_ALT_ENV_FILE</c> — path to a KEY=VALUE file with the V2 keys
    ///     (<c>CERTINEXT_API_URL</c>, <c>CERTINEXT_CLIENT_ID</c>, <c>CERTINEXT_CLIENT_SECRET</c>,
    ///     optional <c>CERTINEXT_GROUP_NUMBER</c> / <c>CERTINEXT_ORG_NUMBER</c> / requestor keys).
    ///     Enough on its own for the read-only tests.</item>
    ///   <item><c>CERTINEXT_ALT_ENV_ENROLL=1</c> — arms the order-placing tests.</item>
    ///   <item><c>CERTINEXT_ALT_ENV_DOMAIN</c> — the name to order.</item>
    ///   <item><c>CERTINEXT_ALT_ENV_WILDCARD=1</c> — order <c>*.&lt;domain&gt;</c> (plus the bare
    ///     domain as a SAN on the plugin path) instead of the single name.</item>
    ///   <item><c>CERTINEXT_ALT_ENV_GROUP_NUMBER</c> overrides the file's group;
    ///     <c>CERTINEXT_ALT_ENV_OMIT_GROUP=1</c> sends none (the credential's default group).</item>
    ///   <item><c>CERTINEXT_ALT_ENV_PRODUCT_CODE</c> — optional ProductCode override.</item>
    ///   <item><c>CERTINEXT_ALT_ENV_ORDER_ID</c> — plugin test only: re-read an existing order
    ///     instead of placing a new one.</item>
    /// </list>
    /// </summary>
    public class V2AltEnvEnrollTests
    {
        private static readonly TimeSpan IssuanceTimeout = TimeSpan.FromMinutes(10);
        private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(15);

        private readonly ITestOutputHelper _output;

        public V2AltEnvEnrollTests(ITestOutputHelper output)
        {
            _output = output;
        }

        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

        private static string Opt(string name) => Environment.GetEnvironmentVariable(name);

        private static string Get(Dictionary<string, string> env, string key, string fallback = "") =>
            env.TryGetValue(key, out string v) && !string.IsNullOrWhiteSpace(v) ? v : fallback;

        private static Dictionary<string, string> LoadAltEnv()
        {
            string envFile = Opt("CERTINEXT_ALT_ENV_FILE");
            Skip.If(string.IsNullOrWhiteSpace(envFile) || !System.IO.File.Exists(envFile),
                "CERTINEXT_ALT_ENV_FILE not set or not found. Skipping.");
            var (env, _) = V2EnvHelper.LoadEnvFile(envFile);
            return env;
        }

        private static string RequireOrderDomain()
        {
            Skip.If(Opt("CERTINEXT_ALT_ENV_ENROLL") != "1",
                "CERTINEXT_ALT_ENV_ENROLL=1 not set — this places a real order on the account in CERTINEXT_ALT_ENV_FILE. Skipping.");
            string domain = Opt("CERTINEXT_ALT_ENV_DOMAIN");
            Skip.If(string.IsNullOrWhiteSpace(domain), "CERTINEXT_ALT_ENV_DOMAIN not set. Skipping.");
            return domain;
        }

        /// <summary>Group to send: the override, else the file's value; null when omitted.</summary>
        private static string ResolveGroup(Dictionary<string, string> env)
        {
            if (Opt("CERTINEXT_ALT_ENV_OMIT_GROUP") == "1")
                return null;
            string group = Opt("CERTINEXT_ALT_ENV_GROUP_NUMBER") is { Length: > 0 } g ? g : Get(env, "CERTINEXT_GROUP_NUMBER");
            return string.IsNullOrWhiteSpace(group) ? null : group;
        }

        private static bool WantWildcard => Opt("CERTINEXT_ALT_ENV_WILDCARD") == "1";

        private static string ScrubEmails(string s) =>
            s == null ? null : Regex.Replace(s, @"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+", "<email>");

        private static string GenerateCsrPem(string commonName)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            var keyPair = keyGen.GenerateKeyPair();

            var csr = new Pkcs10CertificationRequest(
                "SHA256withRSA", new X509Name($"CN={commonName}"), keyPair.Public, null, keyPair.Private);

            return "-----BEGIN CERTIFICATE REQUEST-----\n"
                + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                + "\n-----END CERTIFICATE REQUEST-----";
        }

        private async Task<string> RawGetAsync(string apiUrl, string token, string path)
        {
            using var api = V2RawHttpHelpers.NewApiClient(apiUrl.TrimEnd('/'));
            var req = new RestRequest(path, Method.Get);
            req.AddHeader("Authorization", $"Bearer {token}");
            var resp = await api.ExecuteAsync(req);
            _output.WriteLine($"GET {path} -> {(int)resp.StatusCode}\n{ScrubEmails(resp.Content)}");
            return resp.Content;
        }

        // ---------------------------------------------------------------------------
        // Read-only probes
        // ---------------------------------------------------------------------------

        /// <summary>Logs the account's V2 product catalog.</summary>
        [SkippableFact]
        public async Task ListCatalog_FromAltEnvFile()
        {
            var env = LoadAltEnv();
            var config = new CERTInextConfig
            {
                ApiUrl            = Get(env, "CERTINEXT_API_URL"),
                UseV2Api          = true,
                OAuthClientId     = Get(env, "CERTINEXT_CLIENT_ID"),
                OAuthClientSecret = Get(env, "CERTINEXT_CLIENT_SECRET"),
            };

            using var client = new CERTInextClient(config);
            var catalog = await client.GetProductDetailsV2Async();
            foreach (var p in catalog)
                _output.WriteLine($"productCode={p.ProductCode} productTypeID={p.ProductTypeId} name='{p.ProductName}'");
            catalog.Should().NotBeNull();
        }

        /// <summary>Logs <c>/auth/me</c> and <c>/groups</c>: which groups the credential belongs to.</summary>
        [SkippableFact]
        public async Task Raw_ListIdentityAndGroups_FromAltEnvFile()
        {
            var env = LoadAltEnv();
            string apiUrl = Get(env, "CERTINEXT_API_URL");
            string token = await V2RawHttpHelpers.GetV2AccessTokenAsync(
                apiUrl, Get(env, "CERTINEXT_CLIENT_ID"), Get(env, "CERTINEXT_CLIENT_SECRET"));

            await RawGetAsync(apiUrl, token, Constants.ApiV2.AuthMePath);
            await RawGetAsync(apiUrl, token, "/api/certinext/v2/groups");
        }

        // ---------------------------------------------------------------------------
        // Order-placing tests (opt-in; never revoked or cancelled)
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Direct <c>POST /ssl-certificates</c>, bypassing the plugin: DV, CSR inline, and no
        /// X-Product-Code unless CERTINEXT_ALT_ENV_PRODUCT_CODE is set.
        /// </summary>
        [SkippableFact]
        public async Task Raw_PlaceDvOrder_FromAltEnvFile()
        {
            string baseName = RequireOrderDomain();
            var env = LoadAltEnv();
            string apiUrl = Get(env, "CERTINEXT_API_URL");
            string token = await V2RawHttpHelpers.GetV2AccessTokenAsync(
                apiUrl, Get(env, "CERTINEXT_CLIENT_ID"), Get(env, "CERTINEXT_CLIENT_SECRET"));

            string group = ResolveGroup(env);
            string productCode = Opt("CERTINEXT_ALT_ENV_PRODUCT_CODE");
            string name = Get(env, "CERTINEXT_REQUESTOR_NAME", "Keyfactor Test").Trim('"', '\'');
            string email = Get(env, "CERTINEXT_REQUESTOR_EMAIL");
            string phone = "+1" + Get(env, "CERTINEXT_REQUESTOR_MOBILE", "0000000000");
            string domain = WantWildcard ? $"*.{baseName}" : baseName;

            var body = new Dictionary<string, object>
            {
                ["productVariant"] = "dv",
                ["emailNotifications"] = "consent-only",
                ["requestor"] = new { name, email, phone },
                ["certificate"] = new { domain, autoSecureWww = false },
                ["subscription"] = new { validityYears = 1, autoRenew = false, renewBeforeDays = 30 },
                ["agreement"] = new { signerName = name, signerPlace = "Gateway Lab", accepted = true },
                ["technicalPointOfContact"] = new { name, email, phone, designation = "Technical Contact" },
                ["csr"] = GenerateCsrPem(domain),
                ["remarks"] = "Keyfactor plugin test (direct API).",
            };
            if (group != null)
                body["groupNumber"] = group;

            using var api = V2RawHttpHelpers.NewApiClient(apiUrl.TrimEnd('/'), TimeSpan.FromSeconds(120));
            var req = new RestRequest(Constants.ApiV2.SslCertificatesPath, Method.Post);
            req.AddHeader("Authorization", $"Bearer {token}");
            req.AddHeader("Idempotency-Key", Guid.NewGuid().ToString());
            if (!string.IsNullOrWhiteSpace(productCode))
                req.AddHeader("X-Product-Code", productCode);
            req.AddJsonBody(body);
            var resp = await api.ExecuteAsync(req);

            string corr = resp.Headers?.FirstOrDefault(h => string.Equals(h.Name, "x-correlation-id", StringComparison.OrdinalIgnoreCase))?.Value?.ToString();
            _output.WriteLine($"POST {Constants.ApiV2.SslCertificatesPath} domain={domain} group={group ?? "(omitted)"} " +
                              $"productCode={(string.IsNullOrWhiteSpace(productCode) ? "(none)" : productCode)} " +
                              $"-> {(int)resp.StatusCode} x-correlation-id={corr}\n{ScrubEmails(resp.Content)}");
            resp.IsSuccessful.Should().BeTrue($"the order should be accepted; response: {ScrubEmails(resp.Content)}");
        }

        /// <summary>
        /// Plugin <c>Enroll</c> (DV SSL, or DV SSL Wildcard with the bare domain as a SAN), then
        /// <c>GetSingleRecord</c> until issued; logs the issued leaf's subject, issuer, serial,
        /// expiry, and SANs.
        /// </summary>
        [SkippableFact]
        public async Task Enroll_V2_Dv_FromAltEnvFile_Issues()
        {
            string baseName = RequireOrderDomain();
            var env = LoadAltEnv();

            var config = new CERTInextConfig
            {
                ApiUrl             = Get(env, "CERTINEXT_API_URL"),
                UseV2Api           = true,
                OAuthClientId      = Get(env, "CERTINEXT_CLIENT_ID"),
                OAuthClientSecret  = Get(env, "CERTINEXT_CLIENT_SECRET"),
                AccountNumber      = Get(env, "CERTINEXT_ACCOUNT_NUMBER"),
                GroupNumber        = ResolveGroup(env) ?? string.Empty,
                OrganizationNumber = Get(env, "CERTINEXT_ORG_NUMBER"),

                RequestorName         = Get(env, "CERTINEXT_REQUESTOR_NAME", "Keyfactor Test"),
                RequestorEmail        = Get(env, "CERTINEXT_REQUESTOR_EMAIL"),
                RequestorIsdCode      = Get(env, "CERTINEXT_REQUESTOR_ISD_CODE", "1"),
                RequestorMobileNumber = Get(env, "CERTINEXT_REQUESTOR_MOBILE", "0000000000"),
                SignerPlace           = "Gateway Lab",
                SignerIp              = "127.0.0.1",

                PageSize            = 100,
                V2SyncLookbackHours = 1,
                DcvEnabled          = false
            };

            config.OAuthClientId.Should().NotBeNullOrWhiteSpace("the alt env file must define CERTINEXT_CLIENT_ID");
            _output.WriteLine($"API host: {new Uri(config.ApiUrl).Host}, group configured: {!string.IsNullOrWhiteSpace(config.GroupNumber)}");

            using var client = new CERTInextClient(config);
            var plugin = new CERTInextCAPlugin(client, config);

            var parameters = new Dictionary<string, string>
            {
                [Constants.EnrollmentParam.ProductVariant] = Constants.ApiV2.ProductVariantDv,
            };
            string productCode = Opt("CERTINEXT_ALT_ENV_PRODUCT_CODE");
            if (!string.IsNullOrWhiteSpace(productCode))
                parameters[Constants.EnrollmentParam.ProductCode] = productCode;

            string commonName = WantWildcard ? $"*.{baseName}" : baseName;
            string[] dnsSans = WantWildcard ? new[] { commonName, baseName } : new[] { commonName };
            _output.WriteLine($"ProductCode: {(string.IsNullOrWhiteSpace(productCode) ? "(none)" : productCode)}, " +
                              $"SANs requested: {string.Join(", ", dnsSans)}");

            string existingOrderId = Opt("CERTINEXT_ALT_ENV_ORDER_ID");
            var enrollResult = !string.IsNullOrWhiteSpace(existingOrderId)
                ? new EnrollmentResult { CARequestID = existingOrderId, Status = (int)EndEntityStatus.EXTERNALVALIDATION }
                : await plugin.Enroll(
                    csr:            GenerateCsrPem(commonName),
                    subject:        $"CN={commonName}",
                    san:            new Dictionary<string, string[]> { ["dns"] = dnsSans },
                    productInfo:    new EnrollmentProductInfo
                    {
                        ProductID         = WantWildcard ? Constants.Products.DvSslWildcard : Constants.Products.DvSsl,
                        ProductParameters = parameters
                    },
                    requestFormat:  RequestFormat.PKCS10,
                    enrollmentType: EnrollmentType.New);

            _output.WriteLine($"Enroll: Status={enrollResult.Status}, CARequestID={enrollResult.CARequestID}, Message={enrollResult.StatusMessage}");
            enrollResult.Status.Should().NotBe((int)EndEntityStatus.FAILED, enrollResult.StatusMessage);
            enrollResult.CARequestID.Should().NotBeNullOrWhiteSpace();

            string certPem = enrollResult.Status == (int)EndEntityStatus.GENERATED ? enrollResult.Certificate : null;
            var deadline = DateTime.UtcNow + IssuanceTimeout;
            while (string.IsNullOrWhiteSpace(certPem) && DateTime.UtcNow < deadline)
            {
                await Task.Delay(PollInterval);
                var record = await plugin.GetSingleRecord(enrollResult.CARequestID);
                _output.WriteLine($"{DateTime.UtcNow:O} poll: Status={record?.Status}");
                record.Should().NotBeNull();
                record!.Status.Should().NotBe((int)EndEntityStatus.FAILED, "the order must not be rejected while waiting");
                if (record.Status == (int)EndEntityStatus.GENERATED)
                    certPem = record.Certificate;
            }

            certPem.Should().NotBeNullOrWhiteSpace(
                $"order {enrollResult.CARequestID} should issue within {IssuanceTimeout.TotalMinutes} minutes");

            // The certificate may arrive as one PEM block, a PEM chain, or bare base64 DER; the
            // BouncyCastle parser reads PEM itself and returns the first (leaf) certificate.
            int pemBlocks = Regex.Matches(certPem!, "-----BEGIN CERTIFICATE-----").Count;
            _output.WriteLine($"Certificate payload: {certPem!.Length} chars, {pemBlocks} PEM block(s)");
            byte[] certBytes = pemBlocks > 0
                ? System.Text.Encoding.ASCII.GetBytes(certPem)
                : Convert.FromBase64String(string.Concat(certPem.Where(c => !char.IsWhiteSpace(c))));
            var cert = new X509CertificateParser().ReadCertificate(certBytes);
            var sans = cert.GetSubjectAlternativeNames()?.Cast<IList<object>>().Select(s => s[1]?.ToString())
                       ?? Enumerable.Empty<string>();

            _output.WriteLine($"Issued. OrderId={enrollResult.CARequestID}");
            _output.WriteLine($"Subject    : {cert.SubjectDN}");
            _output.WriteLine($"Issuer     : {cert.IssuerDN}");
            _output.WriteLine($"Serial     : {cert.SerialNumber.ToString(16)}");
            _output.WriteLine($"Valid until: {cert.NotAfter:yyyy-MM-dd}");
            _output.WriteLine($"SANs       : {string.Join(", ", sans)}");
        }
    }
}
