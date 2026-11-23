// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.
//
// Re-runs the SSL.com order attempts in analysis/certinext-sslcom-order-attempts.md against the
// sandbox after CERTInext said SSL.com was enabled. Posts each create body directly and writes
// every exchange (request headers and body, response status, headers and body, the order's Track
// Order state and the cleanup outcome) to the JSON file named by CERTINEXT_RETEST_CAPTURE_PATH, so a
// results document can be rendered from it. Gated by CERTINEXT_V2_SSLCOM_RETEST=1.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using RestSharp;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Live sandbox retest of every SSL.com product shape. Each case places one order (or is rejected),
    /// records the exchange, and revokes or cancels what it placed.
    /// </summary>
    public class V2SslComRetestTests : IClassFixture<IntegrationTestFixture>, IDisposable
    {
        private static readonly JsonSerializerOptions BodyOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        private static readonly string[] CapturedResponseHeaders =
            { "date", "content-type", "x-correlation-id", "x-request-id", "x-api-version" };

        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;
        private readonly Action _restoreLogging;
        private readonly string _v2ApiUrl;
        private readonly string _v2ClientId;
        private readonly string _v2ClientSecret;
        private readonly string _v2Domain;
        private readonly string _groupNumber;
        private readonly string _orgNumber;
        private readonly bool _enabled;

        public V2SslComRetestTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;
            _restoreLogging = TestOutputLogging.RouteTo(output);

            var env = V2EnvHelper.LoadAndPromote();
            _v2ApiUrl = V2EnvHelper.GetEnv(env, "CERTINEXT_API_URL");
            _v2ClientId = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_ID");
            _v2ClientSecret = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_SECRET");
            _v2Domain = V2EnvHelper.GetEnv(env, "CERTINEXT_DCV_DOMAIN", "test.example.com");
            _groupNumber = V2EnvHelper.GetEnv(env, "CERTINEXT_GROUP_NUMBER");
            _orgNumber = V2EnvHelper.GetEnv(env, "CERTINEXT_ORG_NUMBER");
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
            V2InlineCsr           = true,
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

        /// <summary>RSA-2048 CSR; a null <paramref name="commonName"/> gives an empty subject.</summary>
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
                "SHA256withRSA", new X509Name(commonName == null ? string.Empty : $"CN={commonName}"),
                keyPair.Public, attrs, keyPair.Private);
            return "-----BEGIN CERTIFICATE REQUEST-----\n"
                + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks).Replace("\r", string.Empty)
                + "\n-----END CERTIFICATE REQUEST-----";
        }

        private sealed class Case
        {
            public string Title;        // section heading, after the number
            public string Description;  // one line under the heading
            public string Variant;      // dv | ov | ev
            public string ProductCode;  // null = no X-Product-Code header
            public string Shape;        // see BuildShape
        }

        /// <summary>
        /// Shapes (x = a fresh name under the DCV test domain):
        /// single; wildcard (domain *.x); ucc (x + extra.x); wcucc-new (domain *.x, additional x, CSR CN *.x);
        /// wcucc-old (domain x, additional *.x, CSR CN x); apexcn-wildcarddomain (domain *.x, additional x,
        /// CSR CN x); nocn-wildcarddomain (domain *.x, additional x, CSR with an empty subject).
        /// </summary>
        private static List<Case> Cases()
        {
            var list = new List<Case>();
            void Add(string title, string description, string variant, string code, string shape) =>
                list.Add(new Case { Title = title, Description = description, Variant = variant, ProductCode = code, Shape = shape });

            // DV
            foreach (var (code, name, shape, what) in new[]
            {
                ("1011", "DV SSL",              "single",    "Single domain, CSR inline."),
                ("1012", "DV SSL Wildcard",     "wildcard",  "Wildcard primary domain (CN and domain are the wildcard)."),
                ("1013", "DV SSL UCC",          "ucc",       "Primary domain plus one extra name."),
                ("1014", "DV SSL Wildcard UCC", "wcucc-new", "Wildcard primary domain (CN and domain), its plain name in additionalDomains: the shape CERTInext asked for."),
            })
            {
                Add($"{code} SSL.com {name}", what, "dv", code, shape);
                Add($"{name}, no product code", what + " No X-Product-Code.", "dv", null, shape);
            }
            const string oldShape = "CN and domain are the plain name, its wildcard is in additionalDomains: the shape the plugin sent before.";
            Add("1014 SSL.com DV SSL Wildcard UCC, old shape", oldShape, "dv", "1014", "wcucc-old");
            Add("DV SSL Wildcard UCC, old shape, no product code", oldShape + " No X-Product-Code.", "dv", null, "wcucc-old");

            // OV
            foreach (var (code, name, shape, what) in new[]
            {
                ("1015", "OV SSL",              "single",    "Single domain, productVariant ov with the organization block."),
                ("1016", "OV SSL Wildcard",     "wildcard",  "Wildcard primary domain, ov."),
                ("1017", "OV SSL UCC",          "ucc",       "Primary domain plus one extra name, ov."),
                ("1018", "OV SSL Wildcard UCC", "wcucc-new", "Wildcard primary domain, its plain name in additionalDomains, ov."),
            })
            {
                Add($"{code} SSL.com {name}", what, "ov", code, shape);
                Add($"{name}, no product code", what + " No X-Product-Code.", "ov", null, shape);
            }

            // EV
            foreach (var (code, name, shape, what) in new[]
            {
                ("1019", "EV SSL",     "single", "Single domain, productVariant ev with the organization block."),
                ("1020", "EV SSL UCC", "ucc",    "Primary domain plus one extra name, ev."),
            })
            {
                Add($"{code} SSL.com {name}", what, "ev", code, shape);
                Add($"{name}, no product code", what + " No X-Product-Code.", "ev", null, shape);
            }

            // Shapes the plugin builds for a wildcard SAN request
            Add("DV SSL Wildcard UCC, CSR CN is the plain name, no product code",
                "The CSR's CN is the plain name; domain is the wildcard and the plain name is in additionalDomains. No X-Product-Code.",
                "dv", null, "apexcn-wildcarddomain");
            Add("DV SSL Wildcard UCC, CSR with no CN, no product code",
                "The CSR has an empty subject and SANs for the plain name and its wildcard; domain is the wildcard and the plain name is in additionalDomains. This is the body the plugin sends for such a request. No X-Product-Code.",
                "dv", null, "nocn-wildcarddomain");
            return list;
        }

        private V2CreateSslOrderRequest BuildRequest(Case c, CERTInextConfig config, string ts)
        {
            string apex = $"sslcom-{ts}.{_v2Domain}";
            string wildcard = "*." + apex;
            string domain; string csrCn; List<string> additional = null; List<string> csrSans;
            switch (c.Shape)
            {
                case "single":    domain = csrCn = apex; csrSans = new() { apex }; break;
                case "wildcard":  domain = csrCn = wildcard; csrSans = new() { wildcard }; break;
                case "ucc":
                    domain = csrCn = apex; additional = new() { "extra." + apex };
                    csrSans = new() { apex, additional[0] }; break;
                case "wcucc-new":
                    domain = csrCn = wildcard; additional = new() { apex };
                    csrSans = new() { wildcard, apex }; break;
                case "wcucc-old":
                    domain = csrCn = apex; additional = new() { wildcard };
                    csrSans = new() { apex, wildcard }; break;
                case "apexcn-wildcarddomain":
                    domain = wildcard; csrCn = apex; additional = new() { apex };
                    csrSans = new() { apex, wildcard }; break;
                case "nocn-wildcarddomain":
                    domain = wildcard; csrCn = null; additional = new() { apex };
                    csrSans = new() { apex, wildcard }; break;
                default: throw new ArgumentException($"Unknown shape '{c.Shape}'.");
            }

            var request = new V2CreateSslOrderRequest
            {
                ProductVariant     = c.Variant,
                EmailNotifications = Constants.ApiV2.EmailNotificationsConsentOnly,
                Requestor = new V2Requestor { Name = config.RequestorName, Email = config.RequestorEmail, Phone = "+10000000000" },
                Certificate = new V2CertificateParams { Domain = domain, AutoSecureWww = false, AdditionalDomains = additional },
                Subscription = new V2SubscriptionParams { ValidityYears = 1, AutoRenew = false, RenewBeforeDays = 30 },
                Agreement = new V2AgreementParams { SignerName = config.RequestorName, SignerPlace = config.SignerPlace, Accepted = true },
                TechnicalPointOfContact = new V2TechnicalPointOfContact
                {
                    Name = config.RequestorName, Email = config.RequestorEmail,
                    Phone = "+10000000000", Designation = "Technical Contact"
                },
                Csr = GenerateCsrPem(csrCn, csrSans),
                Remarks = "Issued via Keyfactor Command AnyCA REST Gateway.",
                GroupNumber = string.IsNullOrWhiteSpace(_groupNumber) ? null : _groupNumber
            };
            if (c.Variant != "dv")
                request.Organization = new V2OrganizationParams { OrganizationNumber = _orgNumber, PreVetted = true };
            return request;
        }

        [SkippableFact]
        public async Task Retest_SslCom_CaptureAll()
        {
            Skip.If(!_enabled, "CERTINEXT_USE_V2_API not set or V2 credentials not configured — skipping.");
            Skip.If(Environment.GetEnvironmentVariable("CERTINEXT_V2_SSLCOM_RETEST") != "1",
                "CERTINEXT_V2_SSLCOM_RETEST=1 not set — this places real SSL.com sandbox orders. Skipping.");
            string outPath = Environment.GetEnvironmentVariable("CERTINEXT_RETEST_CAPTURE_PATH");
            Skip.If(string.IsNullOrWhiteSpace(outPath), "CERTINEXT_RETEST_CAPTURE_PATH not set — nowhere to write the capture. Skipping.");

            var config = BuildV2Config();
            using var api = V2RawHttpHelpers.NewApiClient(_v2ApiUrl.TrimEnd('/'), TimeSpan.FromSeconds(180));
            using var client = new CERTInextClient(config);
            var records = new List<Dictionary<string, object>>();
            int n = 0;

            try
            {
                foreach (var c in Cases())
                {
                    n++;
                    string ts = DateTime.UtcNow.ToString("yyyyMMddHHmmssfff");
                    var request = BuildRequest(c, config, ts);
                    string json = JsonSerializer.Serialize(request, BodyOptions);
                    string idempotencyKey = Guid.NewGuid().ToString();
                    string token = await V2RawHttpHelpers.GetV2AccessTokenAsync(_v2ApiUrl, _v2ClientId, _v2ClientSecret);

                    var req = new RestRequest(Constants.ApiV2.SslCertificatesPath, Method.Post);
                    req.AddHeader("Authorization", $"Bearer {token}");
                    req.AddHeader("Accept", "application/json");
                    req.AddHeader("Idempotency-Key", idempotencyKey);
                    if (c.ProductCode != null) req.AddHeader("X-Product-Code", c.ProductCode);
                    req.AddStringBody(json, DataFormat.Json);

                    var resp = await api.ExecuteAsync(req);

                    var headers = new Dictionary<string, string>();
                    foreach (var h in (resp.Headers ?? Enumerable.Empty<HeaderParameter>())
                                 .Concat(resp.ContentHeaders ?? Enumerable.Empty<HeaderParameter>()))
                        if (h.Name != null && h.Value != null
                            && CapturedResponseHeaders.Contains(h.Name.ToLowerInvariant()))
                            headers[h.Name.ToLowerInvariant()] = h.Value.ToString();

                    var record = new Dictionary<string, object>
                    {
                        ["n"] = n,
                        ["title"] = c.Title,
                        ["description"] = c.Description,
                        ["productCode"] = c.ProductCode,
                        ["idempotencyKey"] = idempotencyKey,
                        ["requestBody"] = json,
                        ["httpVersion"] = resp.Version != null && resp.Version.Major >= 2 ? "HTTP/2" : "HTTP/1.1",
                        ["status"] = (int)resp.StatusCode,
                        ["responseHeaders"] = headers,
                        ["responseBody"] = resp.Content
                    };

                    string orderId = null;
                    if ((int)resp.StatusCode == 201 && !string.IsNullOrWhiteSpace(resp.Content))
                    {
                        try
                        {
                            orderId = JsonSerializer.Deserialize<V2CreateOrderResponse>(resp.Content, BodyOptions)?.OrderId;
                        }
                        catch (JsonException) { /* recorded as-is */ }
                    }
                    record["orderId"] = orderId;

                    if (!string.IsNullOrWhiteSpace(orderId))
                    {
                        try
                        {
                            var (_, _, body) = await client.ProbeV2GetAsync($"{Constants.ApiV2.SslCertificatesPath}/{orderId}");
                            using var doc = JsonDocument.Parse(body);
                            string Get(string p) => doc.RootElement.TryGetProperty(p, out var v) ? v.ToString() : null;
                            record["track"] = new Dictionary<string, string>
                            {
                                ["status"] = Get("status"), ["orderState"] = Get("orderState"),
                                ["certificateState"] = Get("certificateState"),
                                ["issuedAt"] = Get("issuedAt"), ["expiresAt"] = Get("expiresAt")
                            };
                        }
                        catch (Exception ex)
                        {
                            record["track"] = new Dictionary<string, string> { ["error"] = ex.GetType().Name + ": " + ex.Message };
                        }

                        string cleanup = null;
                        await V2OrderCleanup.RevokeOrCancelAsync(client, orderId, "SSL.com retest cleanup.", m => cleanup = m);
                        record["cleanup"] = cleanup;
                    }

                    records.Add(record);
                    _output.WriteLine($"{n}. {c.Title}: HTTP {(int)resp.StatusCode}, orderId={orderId ?? "(none)"}");
                }
            }
            finally
            {
                // Written even if a later case throws, so a partial run still has its evidence.
                File.WriteAllText(outPath, JsonSerializer.Serialize(
                    records, new JsonSerializerOptions { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }));
                _output.WriteLine($"Capture written to {outPath} ({records.Count} cases).");
            }
        }
    }
}
