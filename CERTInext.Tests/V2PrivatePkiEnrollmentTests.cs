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
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using Moq;
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
    /// Tests that <c>EnrollV2Async</c> builds a family-specific create body rather than the
    /// SSL/TLS one (<see cref="V2CreateSslOrderRequest"/>) for every product family. A
    /// <c>ProductFamily=private-pki</c> template must place a
    /// <see cref="V2CreatePrivatePkiOrderRequest"/> (spec: <c>variant</c>, <c>hostname</c>,
    /// <c>additionalHosts</c>; no organization / certificate / agreement block) through the
    /// Private PKI client overload, with IP SANs carried into <c>additionalHosts</c>; a
    /// <c>ProductFamily=signature</c> template must fail fast with no CA call (open design
    /// decision). Driven end-to-end through <see cref="CERTInextCAPlugin.Enroll"/> against a Strict
    /// <see cref="ICERTInextClient"/> mock, plus WireMock-backed
    /// <see cref="CERTInextCAPlugin.ValidateProductInfo"/> coverage.
    /// </summary>
    public class V2PrivatePkiEnrollmentTests
    {
        private const string OrderId = "ord_pki_001";
        private const string Hostname = "intranet.acme.local";

        // Spec "Private PKI Certificates" field table — every key the create body may carry.
        private static readonly HashSet<string> SpecPrivatePkiTopLevelKeys = new HashSet<string>
        {
            "variant", "caProfileId", "masterProductId", "saveAsDraft", "requestId", "emailNotifications",
            "groupNumber", "requestor", "hostname", "additionalHosts", "subscription", "csr", "remarks",
            "tags", "customFields", "technicalPointOfContact"
        };

        private static Mock<ICERTInextClient> NewMock() =>
            new Mock<ICERTInextClient>(MockBehavior.Strict);

        private static CERTInextConfig BaseConfig() => new CERTInextConfig
        {
            UseV2Api          = true,
            ApiUrl            = "https://v2.certinext.io",
            OAuthClientId     = "my-client",
            OAuthClientSecret = "my-secret",
            RequestorName     = "DevOps Team",
            RequestorEmail    = "devops@acme.com",
            RequestorIsdCode  = "1",
            RequestorMobileNumber = "4155551234",
            SignerIp          = "1.2.3.4",
            SignerPlace       = "New York",
            PickupRetries     = 0
        };

        private static CERTInextCAPlugin BuildV2Plugin(ICERTInextClient client, CERTInextConfig config = null) =>
            new CERTInextCAPlugin(client, config ?? BaseConfig());

        private static EnrollmentProductInfo MakePrivatePkiProductInfo(
            string variant = "intranet-ssl", string productCode = "149", string domainName = Hostname)
        {
            var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ProductFamily"] = "private-pki"
            };
            if (variant != null) parameters["ProductVariant"] = variant;
            if (productCode != null) parameters["ProductCode"] = productCode;
            if (domainName != null) parameters["DomainName"] = domainName;

            // GetProductIds() only advertises SSL/TLS product names, so a real private-pki
            // template is necessarily attached to one of them.
            return new EnrollmentProductInfo { ProductID = Constants.Products.DvSsl, ProductParameters = parameters };
        }

        private static JsonSerializerOptions ClientEquivalentJsonOptions() => new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        /// <summary>
        /// Stubs the Private PKI placement + CSR submit + track (+ download when issued) and
        /// returns an accessor for the captured create body.
        /// </summary>
        private static Func<V2CreatePrivatePkiOrderRequest> StubPrivatePkiOrder(
            Mock<ICERTInextClient> mock, string trackStatus = "pending-approval")
        {
            V2CreatePrivatePkiOrderRequest captured = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<V2CreatePrivatePkiOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, V2CreatePrivatePkiOrderRequest, CancellationToken>((_, req, __) => captured = req)
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = OrderId, Status = "pending-csr" });

            mock.Setup(c => c.SubmitCsrV2Async(
                    Constants.ApiV2.FamilyPrivatePki, OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            mock.Setup(c => c.TrackOrderV2Async(Constants.ApiV2.FamilyPrivatePki, OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = trackStatus });

            if (trackStatus == "issued")
            {
                mock.Setup(c => c.DownloadCertificateV2Async(Constants.ApiV2.FamilyPrivatePki, OrderId, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new V2CertificateDownloadResponse
                    {
                        OrderId        = OrderId,
                        SerialNumber   = "0A1B2C",
                        CertificatePem = MockCertificateData.FakePemCertificate
                    });
            }

            return () => captured;
        }

        private static Task<EnrollmentResult> EnrollAsync(
            CERTInextCAPlugin plugin,
            EnrollmentProductInfo productInfo,
            Dictionary<string, string[]> san,
            string csr = null) =>
            plugin.Enroll(
                csr:            csr ?? MockCertificateData.FakeCsrPem,
                subject:        $"CN={Hostname}",
                san:            san,
                productInfo:    productInfo,
                requestFormat:  RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

        // BouncyCastle only (project crypto policy). DNS and IP SANs in the extensionRequest.
        private static string GenerateCsrPem(string cn, string[] dnsSans, string[] ipSans)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            AsymmetricCipherKeyPair kp = keyGen.GenerateKeyPair();

            var names = (dnsSans ?? Array.Empty<string>()).Select(d => new GeneralName(GeneralName.DnsName, d))
                .Concat((ipSans ?? Array.Empty<string>()).Select(ip => new GeneralName(GeneralName.IPAddress, ip)))
                .ToArray();

            Org.BouncyCastle.Asn1.Asn1Set attributes = null;
            if (names.Length > 0)
            {
                var extGen = new X509ExtensionsGenerator();
                extGen.AddExtension(X509Extensions.SubjectAlternativeName, critical: false,
                    extValue: new GeneralNames(names));
                attributes = new Org.BouncyCastle.Asn1.DerSet(new AttributePkcs(
                    PkcsObjectIdentifiers.Pkcs9AtExtensionRequest,
                    new Org.BouncyCastle.Asn1.DerSet(extGen.Generate())));
            }

            var csr = new Pkcs10CertificationRequest(
                "SHA256withRSA", new X509Name($"CN={cn}"), kp.Public, attributes, kp.Private);

            return "-----BEGIN CERTIFICATE REQUEST-----\n"
                 + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                 + "\n-----END CERTIFICATE REQUEST-----";
        }

        // ---------------------------------------------------------------------------
        // Body shape + routing
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_V2_PrivatePki_PlacesPrivatePkiBody_ThroughPrivatePkiOverload_NotTheSslBody()
        {
            var mock = NewMock();
            var captured = StubPrivatePkiOrder(mock, trackStatus: "issued");

            var config = BaseConfig();
            config.GroupNumber          = "GRP-9";
            config.EmailNotifications   = "1";
            config.RequestorDesignation = "Platform Engineering";
            config.SubscriptionAutoRenew = "1";
            config.SubscriptionRenewCriteriaDays = "20";
            // OV/EV-only and agreement-only settings must have no effect on a Private PKI body.
            config.OrganizationNumber = "ORG-001";
            config.AutoSecureWww      = "1";

            var result = await EnrollAsync(BuildV2Plugin(mock.Object, config), MakePrivatePkiProductInfo(),
                new Dictionary<string, string[]> { ["dnsname"] = new[] { Hostname, "portal.acme.local" } });

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            result.CARequestID.Should().Be(OrderId);

            var req = captured();
            req.Should().NotBeNull("a private-pki enrollment must use the Private PKI PlaceOrderV2Async overload");
            req.Variant.Should().Be("intranet-ssl");
            req.Hostname.Should().Be(Hostname);
            req.AdditionalHosts.Should().Equal("portal.acme.local");
            req.EmailNotifications.Should().Be("all");
            req.GroupNumber.Should().Be("GRP-9");
            req.Requestor.Name.Should().Be("DevOps Team");
            req.Requestor.Email.Should().Be("devops@acme.com");
            req.Requestor.Phone.Should().Be("+14155551234");
            req.Requestor.Designation.Should().Be("Platform Engineering");
            req.Subscription.ValidityYears.Should().Be(1);
            req.Subscription.AutoRenew.Should().BeTrue();
            req.Subscription.RenewBeforeDays.Should().Be(20);
            req.TechnicalPointOfContact.Name.Should().Be("DevOps Team", "blank TechnicalContact* falls back to Requestor*, same as SSL");
            req.TechnicalPointOfContact.Designation.Should().Be(Constants.ApiV2.DefaultTechnicalContactDesignation);

            // The SSL overload and the catalog lookup (SSL UCC detection only) are never touched.
            mock.Verify(c => c.PlaceOrderV2Async(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()),
                Times.Never);
            mock.Verify(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()), Times.Never);
            mock.Verify(c => c.PlaceOrderV2Async("149", It.IsAny<V2CreatePrivatePkiOrderRequest>(), It.IsAny<CancellationToken>()),
                Times.Once, "the explicit ProductCode is sent as X-Product-Code as-is");

            // CSR submit / track / download all hit the private-pki family.
            mock.Verify(c => c.SubmitCsrV2Async(Constants.ApiV2.FamilyPrivatePki, OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Once);
            mock.Verify(c => c.DownloadCertificateV2Async(Constants.ApiV2.FamilyPrivatePki, OrderId, It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task Enroll_V2_PrivatePki_SerializedBody_UsesOnlySpecFieldNames_AndNoSslBlocks()
        {
            var mock = NewMock();
            var captured = StubPrivatePkiOrder(mock);
            var config = BaseConfig();
            config.GroupNumber = "GRP-9";
            config.EmailNotifications = "1";
            config.RequestorDesignation = "Platform Engineering";

            await EnrollAsync(BuildV2Plugin(mock.Object, config), MakePrivatePkiProductInfo(),
                new Dictionary<string, string[]>
                {
                    ["dnsname"]   = new[] { Hostname, "portal.acme.local" },
                    ["ipaddress"] = new[] { "10.0.0.50" }
                });

            string json = JsonSerializer.Serialize(captured(), ClientEquivalentJsonOptions());
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var keys = root.EnumerateObject().Select(p => p.Name).ToList();

            keys.Should().BeEquivalentTo(new[]
            {
                "variant", "emailNotifications", "groupNumber", "requestor", "hostname", "additionalHosts",
                "subscription", "remarks", "technicalPointOfContact"
            });
            keys.Should().OnlyContain(k => SpecPrivatePkiTopLevelKeys.Contains(k),
                "every key must come from the spec's Private PKI field table");
            keys.Should().NotContain(new[] { "productVariant", "certificate", "organization", "agreement", "domain" },
                "Private PKI has no DCV, no organization block, and no Subscriber Agreement (spec)");

            root.GetProperty("variant").GetString().Should().Be("intranet-ssl");
            root.GetProperty("hostname").GetString().Should().Be(Hostname);
            root.GetProperty("additionalHosts").EnumerateArray().Select(e => e.GetString())
                .Should().Equal("portal.acme.local", "10.0.0.50");
            root.GetProperty("requestor").EnumerateObject().Select(p => p.Name)
                .Should().BeEquivalentTo(new[] { "name", "email", "phone", "designation" });
            root.GetProperty("technicalPointOfContact").EnumerateObject().Select(p => p.Name)
                .Should().BeEquivalentTo(new[] { "name", "email", "phone", "designation" });
            root.GetProperty("subscription").GetProperty("validityYears").GetInt32().Should().Be(1);
        }

        [Fact]
        public async Task Enroll_V2_PrivatePki_VariantMatchIsCaseInsensitive_AndSentInSpecCase()
        {
            var mock = NewMock();
            var captured = StubPrivatePkiOrder(mock);

            await EnrollAsync(BuildV2Plugin(mock.Object), MakePrivatePkiProductInfo(variant: " IGTF-Host "),
                new Dictionary<string, string[]> { ["dnsname"] = new[] { Hostname } });

            captured().Variant.Should().Be(Constants.ApiV2.PrivatePkiVariantIgtfHost);
        }

        [Fact]
        public async Task Enroll_V2_PrivatePki_HostnameFallsBackToSubjectCn_WhenDomainNameUnset()
        {
            var mock = NewMock();
            var captured = StubPrivatePkiOrder(mock);

            await EnrollAsync(BuildV2Plugin(mock.Object), MakePrivatePkiProductInfo(domainName: null),
                new Dictionary<string, string[]> { ["dnsname"] = new[] { Hostname } });

            captured().Hostname.Should().Be(Hostname, "spec: \"hostname - primary CN\"");
        }

        [Fact]
        public async Task Enroll_V2_PrivatePki_PendingApproval_ReturnsPendingWithOrderId()
        {
            var mock = NewMock();
            StubPrivatePkiOrder(mock, trackStatus: "pending-approval");

            var result = await EnrollAsync(BuildV2Plugin(mock.Object), MakePrivatePkiProductInfo(),
                new Dictionary<string, string[]> { ["dnsname"] = new[] { Hostname } });

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            result.CARequestID.Should().Be(OrderId, "the order was placed; sync must be able to find it");
        }

        // ---------------------------------------------------------------------------
        // SAN mapping -> additionalHosts
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_V2_PrivatePki_AdditionalHosts_CarriesDnsAndIpSans_ExcludesPrimaryDuplicatesAndNonHostTypes()
        {
            var mock = NewMock();
            var captured = StubPrivatePkiOrder(mock);

            await EnrollAsync(BuildV2Plugin(mock.Object), MakePrivatePkiProductInfo(),
                new Dictionary<string, string[]>
                {
                    ["dnsname"]    = new[] { Hostname, "portal.acme.local", "PORTAL.acme.local" },
                    ["ipaddress"]  = new[] { "10.0.0.50", "fd00::50" },
                    ["rfc822name"] = new[] { "ops@acme.com" },
                    ["uri"]        = new[] { "https://intranet.acme.local/" }
                });

            captured().AdditionalHosts.Should().Equal(
                new[] { "portal.acme.local", "10.0.0.50", "fd00::50" },
                "additionalHosts is a 'SAN list (DNS names or IPv4 / IPv6)' per the spec: IPs are kept, the " +
                "primary hostname is not repeated, duplicates collapse, and email/URI SANs are excluded");
        }

        [Fact]
        public async Task Enroll_V2_PrivatePki_CsrFallback_CarriesIpSansFromCsr_WhenGatewaySanDictionaryIsNull()
        {
            var mock = NewMock();
            var captured = StubPrivatePkiOrder(mock);
            string csr = GenerateCsrPem(Hostname,
                dnsSans: new[] { Hostname, "reports.acme.local" },
                ipSans: new[] { "10.0.0.60" });

            await EnrollAsync(BuildV2Plugin(mock.Object), MakePrivatePkiProductInfo(), san: null, csr: csr);

            captured().AdditionalHosts.Should().Equal(
                new[] { "reports.acme.local", "10.0.0.60" },
                "with no gateway SAN dictionary the CSR's SANs are used, IP SAN rendered as text");
        }

        [Fact]
        public async Task Enroll_V2_PrivatePki_MultiSanCsr_IsNotRejectedBySslSingleDomainGuard()
        {
            // The same CSR on a non-UCC SSL product is rejected before any order is placed (multi-SAN
            // guard). Private PKI's additionalHosts is multi-entry for every variant.
            var mock = NewMock();
            var captured = StubPrivatePkiOrder(mock);
            string csr = GenerateCsrPem(Hostname,
                dnsSans: new[] { Hostname, "portal.acme.local", "reports.acme.local" },
                ipSans: null);

            var result = await EnrollAsync(BuildV2Plugin(mock.Object), MakePrivatePkiProductInfo(),
                new Dictionary<string, string[]> { ["dnsname"] = new[] { Hostname, "portal.acme.local", "reports.acme.local" } },
                csr);

            result.Status.Should().NotBe((int)EndEntityStatus.FAILED);
            captured().AdditionalHosts.Should().Equal("portal.acme.local", "reports.acme.local");
        }

        [Fact]
        public async Task Enroll_V2_PrivatePki_SubmitNonDnsSansFalse_StillSubmitsIpSans()
        {
            var mock = NewMock();
            var captured = StubPrivatePkiOrder(mock);
            var config = BaseConfig();
            config.SubmitNonDnsSans = false;

            await EnrollAsync(BuildV2Plugin(mock.Object, config), MakePrivatePkiProductInfo(),
                new Dictionary<string, string[]>
                {
                    ["dnsname"]   = new[] { Hostname },
                    ["ipaddress"] = new[] { "10.0.0.50" }
                });

            captured().AdditionalHosts.Should().Equal(new[] { "10.0.0.50" },
                "IP literals are native to additionalHosts, so the V1-era SubmitNonDnsSans switch is not consulted");
        }

        [Fact]
        public async Task Enroll_V2_PrivatePki_NoAdditionalSans_OmitsAdditionalHostsFromWireBody()
        {
            var mock = NewMock();
            var captured = StubPrivatePkiOrder(mock);

            await EnrollAsync(BuildV2Plugin(mock.Object), MakePrivatePkiProductInfo(),
                new Dictionary<string, string[]> { ["dnsname"] = new[] { Hostname } });

            captured().AdditionalHosts.Should().BeNull();
            JsonSerializer.Serialize(captured(), ClientEquivalentJsonOptions())
                .Should().NotContain("additionalHosts");
        }

        // ---------------------------------------------------------------------------
        // Fail-fast validation (no CA call of any kind)
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData(null)]            // not set -> SSL-only "dv" default
        [InlineData("dv")]
        [InlineData("ov")]
        [InlineData("igtf-personal")] // appears only in the spec's create-*response* echo enum
        public async Task Enroll_V2_PrivatePki_InvalidOrMissingVariant_FailsFastWithoutAnyCaCall(string variant)
        {
            var mock = NewMock();

            var result = await EnrollAsync(BuildV2Plugin(mock.Object), MakePrivatePkiProductInfo(variant: variant),
                new Dictionary<string, string[]> { ["dnsname"] = new[] { Hostname } });

            result.Status.Should().Be((int)EndEntityStatus.FAILED);
            result.CARequestID.Should().BeEmpty();
            result.StatusMessage.Should().Contain("ProductVariant")
                .And.Contain("intranet-ssl").And.Contain("igtf-host");
            mock.Invocations.Should().BeEmpty("validation must happen before any CA call");
        }

        [Fact]
        public async Task Enroll_V2_PrivatePki_NoExplicitProductCode_FailsFastWithoutAnyCaCall()
        {
            // Without an override, the SSL ProductTypeIdsV2 table would resolve the attached SSL
            // product (DV SSL) — i.e. send an SSL product code to the Private PKI endpoint.
            var mock = NewMock();

            var result = await EnrollAsync(BuildV2Plugin(mock.Object), MakePrivatePkiProductInfo(productCode: null),
                new Dictionary<string, string[]> { ["dnsname"] = new[] { Hostname } });

            result.Status.Should().Be((int)EndEntityStatus.FAILED);
            result.StatusMessage.Should().Contain("ProductCode");
            mock.Invocations.Should().BeEmpty("validation must happen before any CA call");
        }

        // ---------------------------------------------------------------------------
        // signature (Document Signer): open design decision -> fail fast
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_V2_Signature_FailsFastWithoutAnyCaCall_InsteadOfSendingTheSslBody()
        {
            var mock = NewMock();
            var productInfo = new EnrollmentProductInfo
            {
                ProductID = Constants.Products.DvSsl,
                ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ProductFamily"] = "signature",
                    ["ProductCode"]   = "819"
                }
            };

            var result = await BuildV2Plugin(mock.Object).Enroll(
                csr: MockCertificateData.FakeCsrPem,
                subject: "CN=Sarah Johnson",
                san: new Dictionary<string, string[]>(),
                productInfo: productInfo,
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Status.Should().Be((int)EndEntityStatus.FAILED);
            result.CARequestID.Should().BeEmpty();
            result.StatusMessage.Should().Contain("signature").And.Contain("not yet supported");
            mock.Invocations.Should().BeEmpty(
                "nothing is sent to /signature-certificates (no SSL body is sent to the wrong family endpoint)");
        }

        // ---------------------------------------------------------------------------
        // ValidateProductInfo (builds its own CERTInextClient -> WireMock)
        // ---------------------------------------------------------------------------

        private static void StubToken(WireMockServer server) =>
            server.Given(Request.Create().WithPath("/oauth/token").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2TokenResponseJson()));

        private static void StubCatalog(WireMockServer server, string productCode, string productTypeId) =>
            server.Given(Request.Create().WithPath("/api/certinext/v2/catalog/products").UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody($"[{{\"productCode\":\"{productCode}\",\"productName\":\"Test Product\",\"productTypeID\":\"{productTypeId}\"}}]"));

        private static Dictionary<string, object> V2ConnectionInfo(string apiUrl) => new Dictionary<string, object>
        {
            ["UseV2Api"]          = true,
            ["ApiUrl"]            = apiUrl,
            ["OAuthClientId"]     = "my-client",
            ["OAuthClientSecret"] = "my-secret"
        };

        [Fact]
        public async Task ValidateProductInfo_V2_PrivatePki_Succeeds_WhenExplicitCodeIsAPrivatePkiProduct()
        {
            // The SSL ProductId (DV SSL -> productTypeID 13) must not be cross-checked against a
            // Private PKI code (productTypeID 39) — otherwise "does not correspond to the selected
            // product" would be thrown and no private-pki template could ever be saved.
            using var server = WireMockServer.Start();
            StubToken(server);
            StubCatalog(server, "149", Constants.ApiV2.PrivatePkiProductTypeId);

            Func<Task> act = () => BuildV2Plugin(NewMock().Object)
                .ValidateProductInfo(MakePrivatePkiProductInfo(), V2ConnectionInfo(server.Urls[0]));

            await act.Should().NotThrowAsync();
        }

        [Fact]
        public async Task ValidateProductInfo_V2_PrivatePki_Throws_WhenExplicitCodeIsNotAPrivatePkiProduct()
        {
            using var server = WireMockServer.Start();
            StubToken(server);
            StubCatalog(server, "842", "13"); // DV SSL

            Func<Task> act = () => BuildV2Plugin(NewMock().Object)
                .ValidateProductInfo(MakePrivatePkiProductInfo(productCode: "842"), V2ConnectionInfo(server.Urls[0]));

            await act.Should().ThrowAsync<AnyCAValidationException>().WithMessage("*not a Private PKI product*");
        }

        [Fact]
        public async Task ValidateProductInfo_V2_PrivatePki_Throws_WhenCodeNotInCatalog()
        {
            using var server = WireMockServer.Start();
            StubToken(server);
            StubCatalog(server, "100", Constants.ApiV2.PrivatePkiProductTypeId);

            Func<Task> act = () => BuildV2Plugin(NewMock().Object)
                .ValidateProductInfo(MakePrivatePkiProductInfo(productCode: "149"), V2ConnectionInfo(server.Urls[0]));

            await act.Should().ThrowAsync<AnyCAValidationException>().WithMessage("*not found*");
        }

        [Theory]
        [InlineData(null, "149", "ProductVariant")]
        [InlineData("dv", "149", "ProductVariant")]
        [InlineData("intranet-ssl", null, "ProductCode")]
        public async Task ValidateProductInfo_V2_PrivatePki_RejectsBadTemplateParams_BeforeAnyCatalogCall(
            string variant, string productCode, string expectedField)
        {
            using var server = WireMockServer.Start();
            StubToken(server);
            StubCatalog(server, "149", Constants.ApiV2.PrivatePkiProductTypeId);

            Func<Task> act = () => BuildV2Plugin(NewMock().Object)
                .ValidateProductInfo(MakePrivatePkiProductInfo(variant: variant, productCode: productCode),
                    V2ConnectionInfo(server.Urls[0]));

            await act.Should().ThrowAsync<AnyCAValidationException>().WithMessage($"*{expectedField}*");
            server.LogEntries.Should().NotContain(e => e.RequestMessage.Path == "/api/certinext/v2/catalog/products");
        }

        // ---------------------------------------------------------------------------
        // Shared validation helper
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData("intranet-ssl", "149", "intranet-ssl")]
        [InlineData("IGTF-HOST", "149", "igtf-host")]
        public void ValidatePrivatePkiEnrollmentParams_ValidParams_ReturnsNull_AndNormalizesVariant(
            string variant, string productCode, string expectedVariant)
        {
            var ep = new Models.EnrollmentParams(MakePrivatePkiProductInfo(variant: variant, productCode: productCode));

            CERTInextCAPlugin.ValidatePrivatePkiEnrollmentParams(ep, out string normalized).Should().BeNull();
            normalized.Should().Be(expectedVariant);
        }

        [Fact]
        public void ValidatePrivatePkiEnrollmentParams_UnsetVariant_SaysNotSetRatherThanEchoingTheSslDefault()
        {
            var ep = new Models.EnrollmentParams(MakePrivatePkiProductInfo(variant: null));

            string error = CERTInextCAPlugin.ValidatePrivatePkiEnrollmentParams(ep, out string normalized);

            error.Should().Contain("not set");
            normalized.Should().BeNull();
        }
    }
}
