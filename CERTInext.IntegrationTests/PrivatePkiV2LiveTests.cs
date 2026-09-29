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
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Opt-in live verification of the V2 <c>private-pki</c> enrollment path (issue 0033, commit
    /// 88845bf) end to end through the real plugin surface: <c>plugin.Enroll</c> with
    /// <c>ProductFamily=private-pki</c> / <c>ProductVariant=intranet-ssl</c> against the CERTInext
    /// sandbox, then <c>plugin.Revoke</c> (CRL reason 4, superseded) in cleanup.
    ///
    /// PLACES EXACTLY ONE REAL ORDER. Gated behind <c>CERTINEXT_PRIVATE_PKI_LIVE=1</c>, which must be
    /// exported in the shell (it is read from the process environment before the V2 env file is
    /// promoted). Skips with no network calls when the flag or the V2 OAuth2 credentials are absent.
    /// No retries anywhere: a thrown or FAILED enroll is reported, never re-attempted.
    ///
    /// Env:
    ///   CERTINEXT_PRIVATE_PKI_LIVE=1             required opt-in
    ///   CERTINEXT_PRIVATE_PKI_PRODUCT_CODE       default 149 (Sandbox emSign Intranet SSL 1 Year)
    ///   CERTINEXT_PRIVATE_PKI_CN                 default pki0033-&lt;UTC MMddHHmm&gt;.intranet.lab
    ///   V2 creds (CERTINEXT_API_URL / CERTINEXT_CLIENT_ID / CERTINEXT_CLIENT_SECRET) are loaded
    ///   from ~/.env_certinext_v2 by <see cref="V2EnvHelper"/>, same as <see cref="V2LifecycleTests"/>.
    /// </summary>
    [Collection(PrivatePkiV2LiveCollection.Name)]
    public class PrivatePkiV2LiveTests : IClassFixture<IntegrationTestFixture>
    {
        private const string OptInFlag = "CERTINEXT_PRIVATE_PKI_LIVE";
        private const string IpSan     = "10.0.0.50";

        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;

        private readonly bool _optedIn;
        private readonly string _v2ApiUrl;
        private readonly string _v2ClientId;
        private readonly string _v2ClientSecret;
        private readonly string _productCode;
        private readonly string _cnOverride;
        private readonly bool _v2CredsPresent;

        public PrivatePkiV2LiveTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output  = output;

            // Read the opt-in flag from the real process environment BEFORE promoting the V2 env
            // file, so leaving the flag in ~/.env_certinext_v2 cannot arm this order-placing test.
            _optedIn = Environment.GetEnvironmentVariable(OptInFlag)?.Trim() == "1";

            var env = V2EnvHelper.LoadAndPromote();
            _v2ApiUrl       = V2EnvHelper.GetEnv(env, "CERTINEXT_API_URL");
            _v2ClientId     = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_ID");
            _v2ClientSecret = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_SECRET");
            _productCode    = V2EnvHelper.GetEnv(env, "CERTINEXT_PRIVATE_PKI_PRODUCT_CODE", "149");
            _cnOverride     = V2EnvHelper.GetEnv(env, "CERTINEXT_PRIVATE_PKI_CN");

            _v2CredsPresent = !string.IsNullOrWhiteSpace(_v2ApiUrl)
                           && !string.IsNullOrWhiteSpace(_v2ClientId)
                           && !string.IsNullOrWhiteSpace(_v2ClientSecret);
        }

        /// <summary>
        /// V2 config for the private-pki order: mirrors <c>V2LifecycleTests.BuildV2Config</c> (V2
        /// mode, no V1-only fields, requestor placeholders) with DCV disabled. Private PKI has no DCV
        /// anyway; disabling it keeps the no-DCV and DCV builds on the same path.
        /// </summary>
        private CERTInextConfig BuildV2Config() => new CERTInextConfig
        {
            ApiUrl            = _v2ApiUrl,
            UseV2Api          = true,
            OAuthClientId     = _v2ClientId,
            OAuthClientSecret = _v2ClientSecret,

            RequestorName         = _fixture.IsConfigured ? _fixture.Config.RequestorName : "Keyfactor Test",
            RequestorEmail        = _fixture.IsConfigured ? _fixture.Config.RequestorEmail : "test@example.com",
            RequestorIsdCode      = "1",
            RequestorMobileNumber = "0000000000",
            SignerPlace           = "Gateway Lab",
            SignerIp              = "127.0.0.1",
            PageSize              = 100,

            DcvEnabled = false
        };

        /// <summary>
        /// BouncyCastle-only RSA-2048 PKCS#10 CSR with a SAN extension request. Same construction as
        /// <c>KfclabCsrEmitterTests.GenerateCsrPem</c> (which is private and DNS-only), extended to
        /// carry IP SANs.
        /// </summary>
        private static string GenerateCsrPem(string cn, IReadOnlyList<string> dnsSans, IReadOnlyList<string> ipSans)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            var kp = keyGen.GenerateKeyPair();

            var generalNames = dnsSans.Select(d => new GeneralName(GeneralName.DnsName, d))
                .Concat(ipSans.Select(ip => new GeneralName(GeneralName.IPAddress, ip)))
                .ToArray();
            var extGen = new X509ExtensionsGenerator();
            extGen.AddExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(generalNames));
            var attrs = new DerSet(new AttributePkcs(
                PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extGen.Generate())));

            var csr = new Pkcs10CertificationRequest(
                "SHA256withRSA", new X509Name($"CN={cn}"), kp.Public, attrs, kp.Private);
            return "-----BEGIN CERTIFICATE REQUEST-----\n"
                 + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                 + "\n-----END CERTIFICATE REQUEST-----\n";
        }

        /// <summary>Parses the first (leaf) PEM block of a possibly chained PEM string.</summary>
        private static X509Certificate ParseLeaf(string pem)
        {
            var m = Regex.Match(pem ?? string.Empty,
                @"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", RegexOptions.Singleline);
            if (!m.Success) return null;
            string b64 = m.Groups[1].Value.Replace("\r", string.Empty).Replace("\n", string.Empty).Trim();
            return new X509CertificateParser().ReadCertificate(Convert.FromBase64String(b64));
        }

        /// <summary>SAN entries as ("dns"|"ip"|"other:&lt;tag&gt;", value), read with BouncyCastle.</summary>
        private static List<(string Type, string Value)> ReadSans(X509Certificate cert)
        {
            var result = new List<(string, string)>();
            var ext = cert.GetExtensionValue(X509Extensions.SubjectAlternativeName);
            if (ext == null) return result;

            var names = GeneralNames.GetInstance(X509ExtensionUtilities.FromExtensionValue(ext));
            foreach (var gn in names.GetNames())
            {
                switch (gn.TagNo)
                {
                    case GeneralName.DnsName:
                        result.Add(("dns", DerIA5String.GetInstance(gn.Name).GetString()));
                        break;
                    case GeneralName.IPAddress:
                        // IPAddress parses raw octets only (no crypto) — not a BCL-crypto dependency.
                        result.Add(("ip", new IPAddress(Asn1OctetString.GetInstance(gn.Name).GetOctets()).ToString()));
                        break;
                    default:
                        result.Add(($"other:{gn.TagNo}", gn.Name.ToString()));
                        break;
                }
            }
            return result;
        }

        [SkippableFact]
        public async Task PrivatePki_V2_EnrollIntranetSsl_ThenRevoke_Live()
        {
            Skip.If(!_optedIn,
                $"{OptInFlag} is not set to 1 — this test places ONE real private-pki order; skipping (no network calls).");
            Skip.If(!_v2CredsPresent,
                "V2 OAuth2 credentials (CERTINEXT_API_URL / CERTINEXT_CLIENT_ID / CERTINEXT_CLIENT_SECRET) not configured — skipping (no network calls).");

            string cn = string.IsNullOrWhiteSpace(_cnOverride)
                ? $"pki0033-{DateTime.UtcNow:MMddHHmm}.intranet.lab"
                : _cnOverride.Trim();

            var config = BuildV2Config();
            var realClient = new CERTInextClient(config);
            // Pass-through proxy around the real client: records the order id the moment
            // PlaceOrderV2Async returns, so cleanup still knows the order if a later step inside
            // Enroll (CSR submit, track, download) throws before an EnrollmentResult exists.
            var recorder = OrderIdRecordingClientProxy.Wrap(realClient, out ICERTInextClient proxiedClient);
            var plugin = new CERTInextCAPlugin(proxiedClient, config);

            var productInfo = new EnrollmentProductInfo
            {
                ProductID         = _productCode,
                ProductParameters = new Dictionary<string, string>
                {
                    [Constants.EnrollmentParam.ProductFamily]  = "private-pki",
                    [Constants.EnrollmentParam.ProductVariant] = Constants.ApiV2.PrivatePkiVariantIntranetSsl,
                    [Constants.EnrollmentParam.ProductCode]    = _productCode,
                }
            };
            // Gateway SAN dictionary exactly as Command sends it ("dnsname" / "ipaddress" keys).
            var san = new Dictionary<string, string[]>
            {
                ["dnsname"]   = new[] { cn },
                ["ipaddress"] = new[] { IpSan },
            };

            _output.WriteLine("=== Issue 0033 private-pki live enrollment (ONE order, no retries) ===");
            _output.WriteLine($"Family=private-pki, Variant={Constants.ApiV2.PrivatePkiVariantIntranetSsl}, ProductCode={_productCode}");
            _output.WriteLine($"CN={cn}, SANs: dnsname=[{cn}], ipaddress=[{IpSan}]");

            string orderId = null;
            try
            {
                EnrollmentResult result = null;
                Exception enrollEx = null;
                try
                {
                    result = await plugin.Enroll(
                        csr:            GenerateCsrPem(cn, new[] { cn }, new[] { IpSan }),
                        subject:        $"CN={cn}",
                        san:            san,
                        productInfo:    productInfo,
                        requestFormat:  RequestFormat.PKCS10,
                        enrollmentType: EnrollmentType.New);
                }
                catch (Exception ex)
                {
                    enrollEx = ex;
                }

                orderId = !string.IsNullOrWhiteSpace(result?.CARequestID) ? result.CARequestID : recorder.PlacedOrderId;

                // Order id first — before anything below that can fail.
                _output.WriteLine($"CARequestID (order id): {orderId ?? "<none>"}");
                _output.WriteLine($"  (recorded from PlaceOrderV2Async: {recorder.PlacedOrderId ?? "<none>"}, " +
                                  $"initial CA status: {recorder.PlacedOrderStatus ?? "<none>"})");

                if (enrollEx != null)
                {
                    _output.WriteLine($"Enroll THREW {enrollEx.GetType().Name}: {enrollEx.Message}");
                    _output.WriteLine("Not retrying. NOTE: a client-side timeout does not prove no order exists — if the " +
                                      "order id above is <none>, check the CERTInext portal for a private-pki order " +
                                      $"with hostname '{cn}'.");
                    ExceptionDispatchInfo.Capture(enrollEx).Throw();
                }

                if (result == null)
                {
                    _output.WriteLine("Enroll returned a null EnrollmentResult. Not retrying.");
                    Assert.Fail("private-pki Enroll returned a null EnrollmentResult.");
                    return; // unreachable
                }

                _output.WriteLine($"Enroll status: {result.Status} ({(EndEntityStatus)result.Status})");
                _output.WriteLine($"Enroll message: {result.StatusMessage}");

                if (result.Status == (int)EndEntityStatus.FAILED)
                {
                    _output.WriteLine("Enroll returned FAILED. Not retrying; no further order will be placed.");
                    Assert.Fail($"private-pki Enroll returned FAILED: {result.StatusMessage}");
                }

                if (result.Status != (int)EndEntityStatus.GENERATED || string.IsNullOrWhiteSpace(result.Certificate))
                {
                    _output.WriteLine($"Order {orderId} is still pending (not issued within the plugin's pickup poll). " +
                                      "Not polling further; cleanup below will attempt revoke and otherwise print " +
                                      "manual-cleanup instructions.");
                    Assert.Fail($"INCONCLUSIVE: private-pki order '{orderId}' did not issue within the pickup poll " +
                                $"(status {result.Status}); end-to-end issuance not verified.");
                }

                var leaf = ParseLeaf(result.Certificate);
                leaf.Should().NotBeNull("the GENERATED result must carry a parseable leaf certificate PEM");

                var sans = ReadSans(leaf);
                _output.WriteLine($"Issued subject: {leaf.SubjectDN}");
                _output.WriteLine($"Issued issuer:  {leaf.IssuerDN}");
                _output.WriteLine($"Issued serial:  {leaf.SerialNumber.ToString(16).ToUpperInvariant()}");
                _output.WriteLine($"Issued SANs:    [{string.Join(", ", sans.Select(s => $"{s.Type}:{s.Value}"))}]");
                _output.WriteLine($"Validity:       {leaf.NotBefore:o} .. {leaf.NotAfter:o}");

                sans.Should().Contain(s => s.Type == "ip" && s.Value == IpSan,
                    "the IP SAN submitted via additionalHosts must appear on the issued certificate");
                sans.Should().Contain(s => s.Type == "dns" && string.Equals(s.Value, cn, StringComparison.OrdinalIgnoreCase),
                    "the CN (sent as hostname) must appear as a DNS SAN on the issued certificate");
            }
            finally
            {
                await CleanupAsync(plugin, realClient, orderId, cn);
                realClient.Dispose();
            }
        }

        /// <summary>
        /// Best-effort, single-attempt cleanup. Never throws (a cleanup failure must not mask the
        /// test's own result). Revokes via <c>plugin.Revoke</c> — whose pre-flight track only allows
        /// issued orders — and falls back to manual-cleanup instructions: the existing raw V2 cancel
        /// helpers (<c>EmailNotificationsV2ProbeTests</c>/<c>UccPendingSanOrderProbeTests</c>
        /// <c>CancelOrderRawAsync</c>) are hard-wired to the ssl-certificates path, so none supports
        /// the private-pki family. Finishes with one read-only GET on the private-pki order.
        /// </summary>
        private async Task CleanupAsync(CERTInextCAPlugin plugin, CERTInextClient client, string orderId, string cn)
        {
            _output.WriteLine("--- Cleanup ---");
            if (string.IsNullOrWhiteSpace(orderId))
            {
                _output.WriteLine("No order id captured — nothing to revoke. If Enroll threw after sending the create " +
                                  $"request, check the CERTInext portal for a private-pki order with hostname '{cn}'.");
                return;
            }

            try
            {
                int revokeResult = await plugin.Revoke(orderId, hexSerialNumber: string.Empty, revocationReason: 4 /* superseded */);
                _output.WriteLine($"Revoke(order={orderId}, reason=4 superseded) returned {revokeResult} ({(EndEntityStatus)revokeResult}).");
            }
            catch (Exception ex)
            {
                _output.WriteLine($"Revoke FAILED for order {orderId}: {ex.GetType().Name}: {ex.Message}");
                _output.WriteLine("Not retrying. MANUAL CLEANUP REQUIRED: in the CERTInext portal, cancel (if pending) or " +
                                  $"revoke (if issued) order id {orderId}, product family private-pki " +
                                  $"({Constants.ApiV2.PrivatePkiCertificatesPath}/{orderId}).");
            }

            try
            {
                var (status, _, body) = await client.ProbeV2GetAsync($"{Constants.ApiV2.PrivatePkiCertificatesPath}/{orderId}");
                _output.WriteLine($"Post-cleanup track (read-only GET, private-pki): HTTP {status}, " +
                                  $"status={Field(body, "status")}, certificateState={Field(body, "certificateState")}, " +
                                  $"orderState={Field(body, "orderState")}, revocation.status={Field(body, "revocation", "status")}, " +
                                  $"revocation.reason={Field(body, "revocation", "reason")}");
            }
            catch (Exception ex)
            {
                _output.WriteLine($"Post-cleanup track failed (read-only; not retried): {ex.GetType().Name}: {ex.Message}");
            }
        }

        /// <summary>Reads a (nested) string field from a JSON body; "&lt;none&gt;" when absent/unparseable.</summary>
        private static string Field(string json, params string[] path)
        {
            if (string.IsNullOrWhiteSpace(json)) return "<none>";
            try
            {
                using var doc = JsonDocument.Parse(json);
                var el = doc.RootElement;
                foreach (var p in path)
                {
                    if (el.ValueKind != JsonValueKind.Object || !el.TryGetProperty(p, out el))
                        return "<none>";
                }
                return el.ValueKind == JsonValueKind.String ? el.GetString() : el.ToString();
            }
            catch (JsonException)
            {
                return "<unparseable>";
            }
        }

        /// <summary>
        /// Offline sanity check (no network): the recording proxy can be generated for
        /// <see cref="ICERTInextClient"/>. A generation failure would otherwise only surface inside
        /// the live test, after the opt-in.
        /// </summary>
        [Fact]
        public void PrivatePki_V2_RecordingProxy_BuildsOffline()
        {
            using var client = new CERTInextClient(new CERTInextConfig { UseV2Api = true, ApiUrl = "https://invalid.example" });
            var recorder = OrderIdRecordingClientProxy.Wrap(client, out ICERTInextClient proxied);
            proxied.Should().NotBeNull();
            recorder.PlacedOrderId.Should().BeNull();
        }
    }

    /// <summary>
    /// Pass-through <see cref="DispatchProxy"/> over a real <see cref="ICERTInextClient"/> that
    /// records the order id returned by any <c>PlaceOrderV2Async</c> overload. Changes no behavior:
    /// every call is forwarded unchanged and its result/exception returned as-is.
    /// </summary>
    public class OrderIdRecordingClientProxy : DispatchProxy
    {
        private ICERTInextClient _inner;

        public string PlacedOrderId { get; private set; }
        public string PlacedOrderStatus { get; private set; }

        public static OrderIdRecordingClientProxy Wrap(ICERTInextClient inner, out ICERTInextClient proxied)
        {
            proxied = Create<ICERTInextClient, OrderIdRecordingClientProxy>();
            var recorder = (OrderIdRecordingClientProxy)(object)proxied;
            recorder._inner = inner;
            return recorder;
        }

        protected override object Invoke(MethodInfo targetMethod, object[] args)
        {
            object result;
            try
            {
                result = targetMethod.Invoke(_inner, args);
            }
            catch (TargetInvocationException tie) when (tie.InnerException != null)
            {
                ExceptionDispatchInfo.Capture(tie.InnerException).Throw();
                throw; // unreachable
            }

            if (targetMethod.Name == nameof(ICERTInextClient.PlaceOrderV2Async)
                && result is Task<V2CreateOrderResponse> placeTask)
                return RecordAsync(placeTask);

            return result;
        }

        private async Task<V2CreateOrderResponse> RecordAsync(Task<V2CreateOrderResponse> placeTask)
        {
            var resp = await placeTask;
            PlacedOrderId     = resp?.OrderId;
            PlacedOrderStatus = resp?.Status;
            return resp;
        }
    }

    /// <summary>
    /// Runs <see cref="PrivatePkiV2LiveTests"/> alone: its constructor promotes ~/.env_certinext_v2
    /// into process env (<see cref="V2EnvHelper.LoadAndPromote"/>).
    /// </summary>
    [CollectionDefinition(Name, DisableParallelization = true)]
    public sealed class PrivatePkiV2LiveCollection
    {
        public const string Name = "PrivatePkiV2Live-NoParallel";
    }
}
