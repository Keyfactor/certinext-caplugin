// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
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
        /// Plugin wired to a real client pointed at WireMock, so the assertions below run
        /// against the JSON actually serialized onto the wire.
        /// </summary>
        private CERTInextCAPlugin BuildPlugin() => new CERTInextCAPlugin(BuildRealClient());

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
        public async Task GatewayAndCsrSans_AreUnionedAndDeduplicated()
        {
            var plugin = BuildPlugin();

            await plugin.Enroll(
                csr: GenerateCsrPem("host.example.com", "shared.example.com", "csronly.example.com"),
                subject: "CN=host.example.com",
                san: new Dictionary<string, string[]>
                {
                    // "shared" appears in both sources, and in different case, to prove the
                    // de-duplication is case-insensitive.
                    ["dnsname"] = new[] { "SHARED.example.com", "gatewayonly.example.com" }
                },
                productInfo: MakeProductInfo(),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            var domains = AdditionalDomains(CapturedCertificateInformation());

            domains.Should().Contain("gatewayonly.example.com");
            domains.Should().Contain("csronly.example.com");
            domains.Count(d => d.Equals("shared.example.com", StringComparison.OrdinalIgnoreCase))
                .Should().Be(1, "the name present in both sources must appear exactly once");
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
