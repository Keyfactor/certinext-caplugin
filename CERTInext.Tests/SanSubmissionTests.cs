// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Moq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Regression tests for UCC SAN submission.
    ///
    /// The defect these pin down: the AnyCA REST Gateway keys its SAN dictionary
    /// <c>dnsname</c>, but <c>MapSanType</c> only recognized <c>dns</c>. Every DNS SAN was
    /// therefore typed <c>"dnsname"</c>, filtered out by a DNS-only test when building
    /// <c>certificateInformation.additionalDomains</c>, and the order reached CERTInext with
    /// no additional domains at all — yielding a certificate holding only the CN. Because
    /// CERTInext ignores the CSR's subjectAltName extension entirely (measured; see
    /// <c>SanSubmissionProbeTests</c>), SANs present on the CSR did not compensate.
    ///
    /// The end-to-end tests below drive a real <see cref="CERTInextClient"/> against WireMock
    /// so they assert on the JSON actually put on the wire, not on an intermediate object.
    /// A test that only checked the mapping function would not have caught this bug, since
    /// the mapping "worked" — it was the interaction with the downstream filter that lost
    /// the names.
    /// </summary>
    public class SanSubmissionTests : IDisposable
    {
        private readonly WireMockServer _server;

        public SanSubmissionTests()
        {
            _server = WireMockServer.Start();
            StubHappyEnroll();
        }

        public void Dispose() => _server.Stop();

        // -----------------------------------------------------------------------
        // Harness
        // -----------------------------------------------------------------------

        private void StubHappyEnroll()
        {
            _server.Given(Request.Create().WithPath("/GenerateOrderSSL").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.GenerateOrderSuccessJson(MockCertificateData.OrderNumber1)));

            _server.Given(Request.Create().WithPath("/TrackOrder").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.TrackOrderIssuedJson(MockCertificateData.OrderNumber1)));

            _server.Given(Request.Create().WithPath("/GetCertificate").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.GetCertificateSuccessJson()));
        }

        private CERTInextClient BuildRealClient() => new CERTInextClient(new CERTInextConfig
        {
            ApiUrl                = _server.Urls[0],
            AuthMode              = "AccessKey",
            ApiKey                = "test-key",
            AccountNumber         = "12345",
            RequestorName          = "Default Requestor",
            RequestorEmail         = "default@example.com",
            RequestorIsdCode       = "1",
            RequestorMobileNumber  = "5550000000",
            SignerPlace            = "Austin",
            SignerIp               = "203.0.113.10",
            PageSize               = 100
        });

        /// <summary>
        /// Plugin wired to a real client pointed at WireMock. <c>PickupRetries = 0</c> is set on
        /// the plugin's own config (not the client's) — that is where the synchronous-pickup
        /// budget is read, and leaving it at the default would make every test here sit in a
        /// polling loop.
        /// </summary>
        private CERTInextCAPlugin BuildPlugin() =>
            new CERTInextCAPlugin(BuildRealClient(), new CERTInextConfig { PickupRetries = 0 });

        private static EnrollmentProductInfo MakeProductInfo(string profileId = "842") =>
            new EnrollmentProductInfo
            {
                ProductID = profileId,
                ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ProfileId"] = profileId
                }
            };

        /// <summary>The <c>orderDetails.certificateInformation</c> block actually POSTed.</summary>
        private JsonElement CapturedCertificateInformation()
        {
            var posts = _server.LogEntries
                .Where(e => e.RequestMessage.Path == "/GenerateOrderSSL")
                .ToList();
            posts.Should().HaveCount(1, "exactly one GenerateOrderSSL POST should have been emitted");

            string body = posts[0].RequestMessage.Body;
            body.Should().NotBeNullOrEmpty();

            return JsonDocument.Parse(body!).RootElement
                .GetProperty("orderDetails")
                .GetProperty("certificateInformation");
        }

        private static List<string> AdditionalDomains(JsonElement certificateInformation) =>
            certificateInformation.TryGetProperty("additionalDomains", out var el)
                ? el.EnumerateArray().Select(x => x.GetString()).ToList()
                : null;

        // -----------------------------------------------------------------------
        // CSR generation (BouncyCastle — project crypto policy)
        // -----------------------------------------------------------------------

        /// <summary>
        /// Builds a real PKCS#10 CSR for <paramref name="cn"/> carrying arbitrary
        /// <paramref name="names"/> in its subjectAltName extension — used to exercise
        /// GeneralName types that have no domain-name rendering.
        /// </summary>
        private static string GenerateCsrPemWithGeneralNames(string cn, params GeneralName[] names)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            AsymmetricCipherKeyPair kp = keyGen.GenerateKeyPair();

            var extGen = new X509ExtensionsGenerator();
            extGen.AddExtension(X509Extensions.SubjectAlternativeName, critical: false,
                extValue: new GeneralNames(names));

            var attributes = new DerSet(new AttributePkcs(
                PkcsObjectIdentifiers.Pkcs9AtExtensionRequest,
                new DerSet(extGen.Generate())));

            var csr = new Pkcs10CertificationRequest(
                "SHA256withRSA", new X509Name($"CN={cn}"), kp.Public, attributes, kp.Private);

            return "-----BEGIN CERTIFICATE REQUEST-----\n"
                 + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                 + "\n-----END CERTIFICATE REQUEST-----";
        }

        /// <summary>
        /// Builds a real PKCS#10 CSR for <paramref name="cn"/>, optionally carrying a
        /// subjectAltName extension holding <paramref name="dnsSans"/>.
        /// </summary>
        private static string GenerateCsrPem(string cn, params string[] dnsSans)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            AsymmetricCipherKeyPair kp = keyGen.GenerateKeyPair();

            Asn1Set attributes = null;
            if (dnsSans != null && dnsSans.Length > 0)
            {
                var names = new GeneralNames(
                    dnsSans.Select(d => new GeneralName(GeneralName.DnsName, d)).ToArray());

                var extGen = new X509ExtensionsGenerator();
                extGen.AddExtension(X509Extensions.SubjectAlternativeName, critical: false, extValue: names);

                attributes = new DerSet(new AttributePkcs(
                    PkcsObjectIdentifiers.Pkcs9AtExtensionRequest,
                    new DerSet(extGen.Generate())));
            }

            var csr = new Pkcs10CertificationRequest(
                "SHA256withRSA", new X509Name($"CN={cn}"), kp.Public, attributes, kp.Private);

            return "-----BEGIN CERTIFICATE REQUEST-----\n"
                 + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                 + "\n-----END CERTIFICATE REQUEST-----";
        }

        // =======================================================================
        // End-to-end: Command's SAN dictionary → the JSON on the wire
        // =======================================================================

        /// <summary>
        /// THE regression test. "dnsname" is the key the real gateway sends — verified against
        /// a customer gateway log:
        ///   SANs=dnsname:CLAUDIOTEST20.ucsd.edu; dnsname:CLAUDIOTEST20.ad.ucsd.edu
        /// Before the fix, additionalDomains was absent from the body entirely.
        /// </summary>
        [Fact]
        public async Task GatewayDnsNameKey_ReachesAdditionalDomains()
        {
            var plugin = BuildPlugin();

            await plugin.Enroll(
                csr: GenerateCsrPem("host.example.com"),
                subject: "CN=host.example.com",
                san: new Dictionary<string, string[]>
                {
                    ["dnsname"] = new[] { "host.example.com", "alt.example.com" }
                },
                productInfo: MakeProductInfo(),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            var certInfo = CapturedCertificateInformation();
            certInfo.GetProperty("domainName").GetString().Should().Be("host.example.com");

            AdditionalDomains(certInfo).Should().BeEquivalentTo(new[] { "alt.example.com" },
                "the extra SAN must reach additionalDomains, and the CN must not be repeated there");
        }

        /// <summary>
        /// The short "dns" spelling must keep working — some callers and older hosts use it.
        /// </summary>
        [Fact]
        public async Task ShortDnsKey_StillReachesAdditionalDomains()
        {
            var plugin = BuildPlugin();

            await plugin.Enroll(
                csr: GenerateCsrPem("host.example.com"),
                subject: "CN=host.example.com",
                san: new Dictionary<string, string[]>
                {
                    ["dns"] = new[] { "alt.example.com" }
                },
                productInfo: MakeProductInfo(),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            AdditionalDomains(CapturedCertificateInformation())
                .Should().BeEquivalentTo(new[] { "alt.example.com" });
        }

        /// <summary>
        /// SANs present only on the CSR must still reach additionalDomains. CERTInext does not
        /// read the CSR's SAN extension, so if we don't forward these the names never appear
        /// on the certificate.
        /// </summary>
        [Fact]
        public async Task CsrSans_ReachAdditionalDomains_WhenGatewaySuppliesNone()
        {
            var plugin = BuildPlugin();

            await plugin.Enroll(
                csr: GenerateCsrPem("host.example.com", "host.example.com", "fromcsr.example.com"),
                subject: "CN=host.example.com",
                san: null,
                productInfo: MakeProductInfo(),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            AdditionalDomains(CapturedCertificateInformation())
                .Should().BeEquivalentTo(new[] { "fromcsr.example.com" });
        }

        /// <summary>
        /// Union, not either/or: names unique to each source survive and the overlap collapses.
        /// </summary>
        [Fact]
        public async Task CsrOnlySans_AreIgnored_WhenGatewaySuppliesAnyEntries()
        {
            // Regression: this test used to assert the CSR was unioned in on top of whatever the
            // gateway supplied. Full-review's security lens found that risky: Command's SAN
            // dictionary is how an enrollment pattern's SAN policy is expressed, and a signed CSR —
            // usually generated by the subscriber's own tooling, not by Command — can legitimately
            // carry more names than that policy allows. Unioning them in would re-introduce a name
            // the policy excluded. The CSR is now consulted only as a fallback when the gateway
            // supplies nothing at all (see CsrSans_ReachAdditionalDomains_WhenGatewaySuppliesNone).
            var plugin = BuildPlugin();

            await plugin.Enroll(
                csr: GenerateCsrPem("host.example.com", "host.example.com", "csronly.example.com"),
                subject: "CN=host.example.com",
                san: new Dictionary<string, string[]>
                {
                    ["dnsname"] = new[] { "gatewayonly.example.com" }
                },
                productInfo: MakeProductInfo(),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            var domains = AdditionalDomains(CapturedCertificateInformation());

            domains.Should().BeEquivalentTo(new[] { "gatewayonly.example.com" },
                "the gateway supplied a (non-empty) SAN set, so the CSR's own SAN extension must be " +
                "ignored entirely, not merged in on top of it");
        }

        /// <summary>
        /// The CN is already submitted as domainName; repeating it in additionalDomains is
        /// suppressed. CERTInext collapses it anyway (measured), so this keeps the body matching
        /// what we log rather than relying on undocumented CA-side behaviour.
        /// </summary>
        [Fact]
        public async Task Cn_IsNotRepeatedInAdditionalDomains()
        {
            var plugin = BuildPlugin();

            await plugin.Enroll(
                csr: GenerateCsrPem("host.example.com", "host.example.com"),
                subject: "CN=host.example.com",
                san: new Dictionary<string, string[]>
                {
                    ["dnsname"] = new[] { "host.example.com" }
                },
                productInfo: MakeProductInfo(),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            var certInfo = CapturedCertificateInformation();
            certInfo.GetProperty("domainName").GetString().Should().Be("host.example.com");
            AdditionalDomains(certInfo).Should().BeNull(
                "with the CN as the only SAN there is nothing left to send, so the field is omitted");
        }

        /// <summary>
        /// Non-DNS SANs are submitted rather than silently discarded. CERTInext accepts them
        /// verbatim (measured) and the resulting order cannot pass validation — a visible
        /// failure, deliberately preferred over issuing a certificate that quietly lacks names
        /// the subscriber requested.
        /// </summary>
        [Fact]
        public async Task NonDnsSans_AreSubmitted_NotDropped()
        {
            var plugin = BuildPlugin();

            await plugin.Enroll(
                csr: GenerateCsrPem("host.example.com"),
                subject: "CN=host.example.com",
                san: new Dictionary<string, string[]>
                {
                    ["dnsname"]     = new[] { "alt.example.com" },
                    ["ipaddress"]   = new[] { "192.0.2.10" },
                    ["rfc822name"]  = new[] { "admin@example.com" }
                },
                productInfo: MakeProductInfo(),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            AdditionalDomains(CapturedCertificateInformation())
                .Should().BeEquivalentTo(new[] { "alt.example.com", "192.0.2.10", "admin@example.com" });
        }

        /// <summary>
        /// A CSR we cannot parse must not break enrollment — the gateway-supplied SANs still go.
        /// <c>FakeCsrPem</c> is deliberately truncated, so this also guards the many existing
        /// tests that pass it.
        /// </summary>
        [Fact]
        public async Task UnparseableCsr_DoesNotBlockGatewaySuppliedSans()
        {
            var plugin = BuildPlugin();

            await plugin.Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=host.example.com",
                san: new Dictionary<string, string[]>
                {
                    ["dnsname"] = new[] { "alt.example.com" }
                },
                productInfo: MakeProductInfo(),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            AdditionalDomains(CapturedCertificateInformation())
                .Should().BeEquivalentTo(new[] { "alt.example.com" });
        }

        /// <summary>
        /// No SANs from either source → the field is omitted rather than emitted as null/empty.
        /// </summary>
        [Fact]
        public async Task NoSansAnywhere_OmitsAdditionalDomains()
        {
            var plugin = BuildPlugin();

            await plugin.Enroll(
                csr: GenerateCsrPem("host.example.com"),
                subject: "CN=host.example.com",
                san: null,
                productInfo: MakeProductInfo(),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            AdditionalDomains(CapturedCertificateInformation()).Should().BeNull();
        }

        // =======================================================================
        // GeneralName types with no domain-name rendering
        // =======================================================================

        /// <summary>
        /// A UPN otherName and a directoryName must NOT be submitted.
        ///
        /// Regression: GeneralNameToValue's default branch returned BouncyCastle's ASN.1
        /// stringification, so a Windows-generated CSR carrying a UPN otherName put
        /// "[1.3.6.1.4.1.311.20.2.3, [CONTEXT 0]svc@corp.example.com]" into additionalDomains as if
        /// it were a domain name — breaking orders that previously succeeded, and contradicting the
        /// method's own doc comment. These types cannot become a certificate SAN via a domain-name
        /// field at all, which is why they are skipped (with a Warning) rather than submitted the way
        /// well-formed IP/email/URI SANs are.
        /// </summary>
        [Fact]
        public async Task CsrOtherNameAndDirectoryName_AreNotSubmittedAsDomains()
        {
            // UPN otherName, as emitted by Windows/AD certificate tooling.
            var upn = new GeneralName(GeneralName.OtherName, new DerSequence(
                new DerObjectIdentifier("1.3.6.1.4.1.311.20.2.3"),
                new DerTaggedObject(true, 0, new DerUtf8String("svc@corp.example.com"))));

            var directoryName = new GeneralName(
                GeneralName.DirectoryName, new X509Name("CN=host.example.com,O=Acme"));

            var plugin = BuildPlugin();

            await plugin.Enroll(
                csr: GenerateCsrPemWithGeneralNames(
                    "host.example.com",
                    new GeneralName(GeneralName.DnsName, "alt.example.com"),
                    upn,
                    directoryName),
                subject: "CN=host.example.com",
                san: null,
                productInfo: MakeProductInfo(),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            var domains = AdditionalDomains(CapturedCertificateInformation());

            domains.Should().BeEquivalentTo(new[] { "alt.example.com" },
                "only the renderable DNS name may be submitted");
            domains.Should().NotContain(d => d.Contains("1.3.6.1.4.1.311.20.2.3"),
                "an otherName must never be submitted as an ASN.1 dump");
            domains.Should().NotContain(d => d.Contains("CONTEXT"),
                "BouncyCastle ASN.1 debris must never reach the wire");
            domains.Should().NotContain(d => d.StartsWith("CN=", StringComparison.OrdinalIgnoreCase),
                "a directoryName must never be submitted as a domain");
        }

        // =======================================================================
        // Log-injection hardening (CWE-117)
        // =======================================================================

        /// <summary>
        /// SAN values reach the log from the CSR and from Command's SAN dictionary — i.e. from the
        /// requester. Structured message templates stop format-string abuse but not embedded
        /// newlines, so a value carrying CRLF could forge audit records in the very log lines added
        /// to make the submitted SAN set auditable. LogSanitizer is internal (not private) and
        /// shared between the plugin and the client, so this is a direct call, not reflection.
        /// </summary>
        [Theory]
        [InlineData("evil.example.com\r\nINFO forged record", "evil.example.com\\r\\nINFO forged record")]
        [InlineData("a\nb", "a\\nb")]
        [InlineData("a\tb", "a\\tb")]
        [InlineData("plain.example.com", "plain.example.com")]
        [InlineData("", "")]
        [InlineData(null, null)]
        public void SanitizeForLog_NeutralizesControlCharacters(string input, string expected)
        {
            var actual = Keyfactor.Extensions.CAPlugin.CERTInext.Models.LogSanitizer.Strip(input);

            actual.Should().Be(expected);
        }

        /// <summary>
        /// A CRLF-bearing SAN must not break enrollment, and the value is still submitted verbatim —
        /// the scrub is a logging concern and deliberately does not mutate the payload sent to the CA.
        /// </summary>
        [Fact]
        public async Task SanValueWithCrLf_DoesNotBreakEnrollment()
        {
            var plugin = BuildPlugin();

            await plugin.Enroll(
                csr: GenerateCsrPem("host.example.com"),
                subject: "CN=host.example.com",
                san: new Dictionary<string, string[]>
                {
                    ["dnsname"] = new[] { "alt.example.com\r\nforged log line" }
                },
                productInfo: MakeProductInfo(),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            AdditionalDomains(CapturedCertificateInformation())
                .Should().ContainSingle().Which.Should().Contain("alt.example.com");
        }

        // =======================================================================
        // SubmitNonDnsSans escape hatch
        // =======================================================================

        /// <summary>
        /// Submitting non-DNS SANs flips affected enrollments from "issues, silently missing the
        /// name" to "parks pending". SubmitNonDnsSans=false restores the pre-1.0.1 behaviour so an
        /// upgraded host has a way back that isn't a plugin downgrade.
        /// </summary>
        [Fact]
        public async Task SubmitNonDnsSansFalse_SubmitsDnsNamesOnly()
        {
            var plugin = new CERTInextCAPlugin(
                BuildRealClient(),
                new CERTInextConfig { PickupRetries = 0, SubmitNonDnsSans = false });

            await plugin.Enroll(
                csr: GenerateCsrPem("host.example.com"),
                subject: "CN=host.example.com",
                san: new Dictionary<string, string[]>
                {
                    ["dnsname"]    = new[] { "alt.example.com" },
                    ["ipaddress"]  = new[] { "192.0.2.10" },
                    ["rfc822name"] = new[] { "admin@example.com" }
                },
                productInfo: MakeProductInfo(),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            AdditionalDomains(CapturedCertificateInformation())
                .Should().BeEquivalentTo(new[] { "alt.example.com" },
                    "with the switch off, only DNS names are submitted");
        }

        /// <summary>
        /// The switch defaults to true, so the documented default behaviour is pinned independently
        /// of any test that sets it explicitly.
        /// </summary>
        [Fact]
        public void SubmitNonDnsSans_DefaultsToTrue()
        {
            new CERTInextConfig().SubmitNonDnsSans.Should().BeTrue();
        }

        /// <summary>
        /// Regression for a self-contradicting audit record: BuildSanList used to log "N SAN(s)
        /// ... have been added to the order" for CSR-fallback entries, then filter exactly those
        /// entries back out two lines later when SubmitNonDnsSans is false — a false claim in the
        /// same call. The fix reordered the method to filter first and log the final result, which
        /// this test exercises functionally: with the gateway supplying nothing (so the CSR fallback
        /// engages) and a non-DNS CSR SAN present, SubmitNonDnsSans=false must still result in that
        /// name being genuinely absent from the wire, not merely mis-described in the log.
        /// </summary>
        [Fact]
        public async Task CsrFallbackNonDnsSan_IsExcluded_WhenSubmitNonDnsSansFalse()
        {
            var plugin = new CERTInextCAPlugin(
                BuildRealClient(),
                new CERTInextConfig { PickupRetries = 0, SubmitNonDnsSans = false });

            await plugin.Enroll(
                csr: GenerateCsrPemWithGeneralNames(
                    "host.example.com",
                    new GeneralName(GeneralName.DnsName, "host.example.com"),
                    new GeneralName(GeneralName.DnsName, "alt.example.com"),
                    new GeneralName(GeneralName.Rfc822Name, "admin@example.com")),
                subject: "CN=host.example.com",
                san: null,
                productInfo: MakeProductInfo(),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            AdditionalDomains(CapturedCertificateInformation())
                .Should().BeEquivalentTo(new[] { "alt.example.com" },
                    "the CSR-fallback email SAN must be genuinely absent from the order, not just " +
                    "misreported as present");
        }

        // =======================================================================
        // Renew path — previously submitted no SANs at all
        // =======================================================================

        /// <summary>
        /// A renewal that goes through the CERTInext renew API must carry the same domain set
        /// as a new enrollment, and must take its primary domain from the subject's CN rather
        /// than from the prior order's requestor name.
        /// </summary>
        [Fact]
        public async Task RenewalRequest_CarriesSubjectAndSans()
        {
            var clientMock = new Mock<ICERTInextClient>(MockBehavior.Loose);
            RenewCertificateRequest captured = null;

            clientMock
                .Setup(c => c.RenewCertificateAsync(
                    It.IsAny<string>(),
                    It.IsAny<RenewCertificateRequest>(),
                    It.IsAny<CancellationToken>()))
                .Callback<string, RenewCertificateRequest, CancellationToken>((_, req, __) => captured = req)
                .ReturnsAsync(MockCertificateData.IssuedEnrollResponse());

            var readerMock = new Mock<ICertificateDataReader>(MockBehavior.Loose);
            readerMock
                .Setup(r => r.GetRequestIDBySerialNumber(It.IsAny<string>()))
                .ReturnsAsync("PRIOR-ORDER-1");

            // The renewal-window decision reads expiry from the data reader, not from the CA.
            // Put the prior cert 10 days out so it lands inside the 30-day window below and the
            // renew API path is actually taken.
            readerMock
                .Setup(r => r.GetExpirationDateByRequestId(It.IsAny<string>()))
                .Returns(DateTime.UtcNow.AddDays(10));

            var plugin = new CERTInextCAPlugin(clientMock.Object, readerMock.Object);

            var productInfo = MakeProductInfo();
            productInfo.ProductParameters["PriorCertSN"] = "AABBCCDDEEFF";
            productInfo.ProductParameters["RenewalWindowDays"] = "30";

            await plugin.Enroll(
                csr: GenerateCsrPem("host.example.com", "host.example.com", "alt.example.com"),
                subject: "CN=host.example.com",
                san: new Dictionary<string, string[]>
                {
                    ["dnsname"] = new[] { "host.example.com", "alt.example.com" }
                },
                productInfo: productInfo,
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.Renew);

            captured.Should().NotBeNull("the renew API path should have been taken");

            // Bind to a local so the compiler's null-flow analysis is satisfied — a
            // FluentAssertions NotBeNull() does not narrow the nullable reference.
            RenewCertificateRequest renewReq = captured!;

            renewReq.Subject.Should().Be("CN=host.example.com",
                "without the subject the renewal order has no usable primary domain");
            renewReq.Sans.Should().NotBeNull("renewals previously dropped every SAN");
            renewReq.Sans.Select(s => s.Value)
                .Should().BeEquivalentTo(new[] { "host.example.com", "alt.example.com" });
        }
    }
}
