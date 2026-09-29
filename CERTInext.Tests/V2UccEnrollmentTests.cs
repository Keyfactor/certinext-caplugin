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
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Regression tests for issues/f3-v2-multi-san-limitation.md: V2 UCC (multi-SAN) order-create
    /// support. <see cref="CERTInextCAPlugin.Enroll"/> (V2 path) is driven end-to-end against a
    /// Strict <see cref="ICERTInextClient"/> mock so the assertions exercise
    /// <c>EnrollV2Async</c>'s actual UCC-detection and <c>additionalDomains</c>-population logic,
    /// not a re-implementation of it.
    /// </summary>
    public class V2UccEnrollmentTests
    {
        private static Mock<ICERTInextClient> NewMock() =>
            new Mock<ICERTInextClient>(MockBehavior.Strict);

        private static CERTInextCAPlugin BuildV2Plugin(ICERTInextClient client) =>
            new CERTInextCAPlugin(client, new CERTInextConfig
            {
                UseV2Api          = true,
                ApiUrl            = "https://v2.certinext.io",
                OAuthClientId     = "my-client",
                OAuthClientSecret = "my-secret",
                RequestorName     = "Test User",
                RequestorEmail    = "test@example.com",
                SignerIp          = "1.2.3.4",
                SignerPlace       = "New York",
                PickupRetries     = 0
            });

        private static EnrollmentProductInfo MakeV2ProductInfo(string productCode) =>
            new EnrollmentProductInfo
            {
                ProductID = "DV SSL UCC",
                ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ProductCode"]    = productCode,
                    ["ProductFamily"]  = "ssl",
                    ["ProductVariant"] = "dv",
                    ["DomainName"]     = "example.com"
                }
            };

        private static void StubCatalog(Mock<ICERTInextClient> mock, string productCode, string productTypeId) =>
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = productCode, ProductTypeId = productTypeId, Active = true }
                });

        private static void StubHappyOrderPlacement(Mock<ICERTInextClient> mock, string orderId = "ord_ucc_001")
        {
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = orderId, Status = "pending-dcv" });

            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), orderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), orderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = orderId, Status = "pending-dcv" });
        }

        // ---------------------------------------------------------------------------
        // CSR generation (BouncyCastle — project crypto policy). Mirrors SanSubmissionTests'
        // helper of the same shape; duplicated locally per this repo's existing convention of
        // small per-test-file helpers (see NewMock()/BuildV2Plugin() duplicated across the V2
        // test files) rather than sharing test infrastructure across files.
        // ---------------------------------------------------------------------------

        private static string GenerateCsrPem(string cn, params string[] dnsSans)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            AsymmetricCipherKeyPair kp = keyGen.GenerateKeyPair();

            Org.BouncyCastle.Asn1.Asn1Set attributes = null;
            if (dnsSans != null && dnsSans.Length > 0)
            {
                var names = dnsSans.Select(d => new GeneralName(GeneralName.DnsName, d)).ToArray();
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
        // UCC detection + additionalDomains population
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_V2_UccProduct_PopulatesAdditionalDomainsFromGatewaySanDictionary()
        {
            var mock = NewMock();
            StubCatalog(mock, "844", "15"); // DV SSL Certificate UCC
            StubHappyOrderPlacement(mock);

            V2CreateSslOrderRequest captured = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>((_, __, req, ___) => captured = req)
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = "ord_ucc_001", Status = "pending-dcv" });

            var plugin = BuildV2Plugin(mock.Object);

            var result = await plugin.Enroll(
                csr: GenerateCsrPem("example.com"), // CSR carries ONLY the primary domain — spec requirement for UCC
                subject: "CN=example.com",
                san: new Dictionary<string, string[]>
                {
                    ["dns"] = new[] { "example.com", "san1.example.com", "san2.example.com" }
                },
                productInfo: MakeV2ProductInfo("844"),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.CARequestID.Should().Be("ord_ucc_001");
            captured.Should().NotBeNull();
            V2CreateSslOrderRequest req = captured!;
            req.Certificate.Domain.Should().Be("example.com");
            req.Certificate.AdditionalDomains.Should().BeEquivalentTo(
                new[] { "san1.example.com", "san2.example.com" },
                "the primary domain must not be repeated in additionalDomains, and the SAN dictionary " +
                "(not the CSR) is the source for a UCC order's additional domains");
        }

        [Fact]
        public async Task Enroll_V2_NonUccProduct_SanDictionaryCarriesExtras_StillFailsFastWithNoPlaceOrderCall()
        {
            // Issue 0061: the CSR alone carries only the primary domain, so the pre-0061 guard
            // (which looked at the CSR only) did not trigger, and the SAN dictionary's extra
            // domain silently vanished — a non-UCC order never sends additionalDomains at all, so
            // there was nowhere for it to go. The guard must now consider the SAN dictionary too
            // and reject, the same way it already rejects CSR-borne extras
            // (Enroll_V2_NonUccProduct_CsrCarriesExtraSans_StillFailsFastWithNoPlaceOrderCall).
            var mock = NewMock();
            StubCatalog(mock, "842", "13"); // DV SSL (non-UCC)

            var plugin = BuildV2Plugin(mock.Object);

            var result = await plugin.Enroll(
                csr: GenerateCsrPem("example.com"),
                subject: "CN=example.com",
                san: new Dictionary<string, string[]>
                {
                    ["dns"] = new[] { "example.com", "san1.example.com" }
                },
                productInfo: MakeV2ProductInfo("842"),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Status.Should().Be((int)EndEntityStatus.FAILED);
            result.StatusMessage.Should().Contain("1 SAN(s) beyond");
            result.StatusMessage.Should().Contain("single domain");

            mock.Verify(c => c.PlaceOrderV2Async(
                It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()), Times.Never,
                "a rejected non-UCC request must never reach order placement, whether the extra " +
                "SAN came from the CSR or the SAN dictionary");
        }

        [Fact]
        public async Task Enroll_V2_NonUccProduct_SanDictionaryHasOnlyPrimary_ButCsrCarriesExtraSan_StillFailsFastWithNoPlaceOrderCall()
        {
            // Regression for a union-vs-fallback bug introduced while first fixing issue 0061: a
            // non-null SAN dictionary that carries only the primary domain must not make the
            // guard defer to the dictionary and skip the CSR. SubmitCsrV2Async sends the CSR to
            // CERTInext verbatim regardless of what the SAN dictionary contains, so a
            // CSR-embedded extra domain still reaches the CA even when the dictionary is
            // single-domain — the guard must reject this exactly like the CSR-only case
            // (Enroll_V2_NonUccProduct_CsrCarriesExtraSans_StillFailsFastWithNoPlaceOrderCall).
            var mock = NewMock();
            StubCatalog(mock, "842", "13"); // DV SSL (non-UCC)

            var plugin = BuildV2Plugin(mock.Object);

            var result = await plugin.Enroll(
                csr: GenerateCsrPem("example.com", "example.com", "other.example.com"),
                subject: "CN=example.com",
                san: new Dictionary<string, string[]> { ["dns"] = new[] { "example.com" } },
                productInfo: MakeV2ProductInfo("842"),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Status.Should().Be((int)EndEntityStatus.FAILED);
            result.StatusMessage.Should().Contain("1 SAN(s) beyond");
            result.StatusMessage.Should().Contain("single domain");

            mock.Verify(c => c.PlaceOrderV2Async(
                It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()), Times.Never,
                "a non-null SAN dictionary carrying only the primary domain must not make the " +
                "guard defer to it and miss a CSR-embedded extra SAN");
        }

        [Fact]
        public async Task Enroll_V2_NonUccProduct_SanDictionaryHasOnlyPrimaryAndWwwVariant_Allowed()
        {
            // The guard's existing primary-domain / www.<primary> allowance must still apply when
            // those names arrive via the SAN dictionary rather than the CSR.
            var mock = NewMock();
            StubCatalog(mock, "842", "13"); // DV SSL (non-UCC)

            V2CreateSslOrderRequest captured = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>((_, __, req, ___) => captured = req)
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = "ord_nonucc_002", Status = "pending-dcv" });
            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), "ord_nonucc_002", It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), "ord_nonucc_002", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = "ord_nonucc_002", Status = "pending-dcv" });

            var plugin = BuildV2Plugin(mock.Object);

            var result = await plugin.Enroll(
                csr: GenerateCsrPem("example.com"),
                subject: "CN=example.com",
                san: new Dictionary<string, string[]>
                {
                    ["dns"] = new[] { "example.com", "www.example.com" }
                },
                productInfo: MakeV2ProductInfo("842"),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.CARequestID.Should().Be("ord_nonucc_002");
            captured.Should().NotBeNull();
            captured!.Certificate.AdditionalDomains.Should().BeNull(
                "non-UCC V2 products must keep the single-domain wire shape even when the " +
                "dictionary only ever carried allowed names");
        }

        [Fact]
        public async Task Enroll_V2_NonUccProduct_SanDictionaryHasOnlyNonDnsExtras_Allowed()
        {
            // dnsOnly semantics (issue 0046): a non-DNS SAN dictionary entry can never appear in
            // additionalDomains and must not trip the reject guard either.
            var mock = NewMock();
            StubCatalog(mock, "842", "13"); // DV SSL (non-UCC)

            V2CreateSslOrderRequest captured = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>((_, __, req, ___) => captured = req)
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = "ord_nonucc_003", Status = "pending-dcv" });
            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), "ord_nonucc_003", It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), "ord_nonucc_003", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = "ord_nonucc_003", Status = "pending-dcv" });

            var plugin = BuildV2Plugin(mock.Object);

            var result = await plugin.Enroll(
                csr: GenerateCsrPem("example.com"),
                subject: "CN=example.com",
                san: new Dictionary<string, string[]>
                {
                    ["dns"] = new[] { "example.com" },
                    ["rfc822name"] = new[] { "admin@example.com" }
                },
                productInfo: MakeV2ProductInfo("842"),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.CARequestID.Should().Be("ord_nonucc_003");
            captured.Should().NotBeNull();
            captured!.Certificate.AdditionalDomains.Should().BeNull(
                "a non-DNS dictionary entry must not trip the non-UCC reject guard");
        }

        [Fact]
        public async Task Enroll_V2_UccProduct_CsrCarriesExtraSans_OrderIsPlacedWithSansAsAdditionalDomains()
        {
            // Issue 0047: the CSR-SAN-count guard used to run unconditionally before UCC
            // detection, so a real UCC CSR enrollment (the CSR itself carries the extra DNS
            // SANs, as Command actually builds it for CSR-based enrollments — confirmed live
            // 2026-09-28) was always rejected before any CA order was placed. UCC products must
            // now be exempt: the guard should not fire, and BuildSanList's own CSR fallback
            // (triggered here via san: null) should carry those same CSR SANs into
            // additionalDomains, exactly like the gateway-SAN-dictionary case already covered by
            // Enroll_V2_UccProduct_PopulatesAdditionalDomainsFromGatewaySanDictionary above.
            var mock = NewMock();
            StubCatalog(mock, "844", "15"); // DV SSL Certificate UCC

            V2CreateSslOrderRequest captured = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>((_, __, req, ___) => captured = req)
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = "ord_ucc_002", Status = "pending-dcv" });
            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), "ord_ucc_002", It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), "ord_ucc_002", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = "ord_ucc_002", Status = "pending-dcv" });

            var plugin = BuildV2Plugin(mock.Object);

            var result = await plugin.Enroll(
                csr: GenerateCsrPem("example.com", "example.com", "extra1.example.com", "extra2.example.com"),
                subject: "CN=example.com",
                san: null, // no gateway SAN dictionary — BuildSanList falls back to the CSR's own SANs
                productInfo: MakeV2ProductInfo("844"), // UCC product code
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION,
                "the order should proceed to CA placement rather than fail fast");
            result.CARequestID.Should().Be("ord_ucc_002");
            captured.Should().NotBeNull();
            V2CreateSslOrderRequest req = captured!;
            req.Certificate.Domain.Should().Be("example.com");
            req.Certificate.AdditionalDomains.Should().BeEquivalentTo(
                new[] { "extra1.example.com", "extra2.example.com" },
                "a UCC product's CSR-embedded extra SANs must flow into additionalDomains instead of " +
                "tripping the single-domain guard");
        }

        [Fact]
        public async Task Enroll_V2_NonUccProduct_CsrCarriesExtraSans_StillFailsFastWithNoPlaceOrderCall()
        {
            // Counterpart to the UCC case above: a non-UCC product with the same multi-SAN CSR
            // must keep the pre-0047 fail-fast behavior — FAILED, no order placed — even though
            // the guard now necessarily runs after the (live) catalog lookup that determines
            // UCC-ness, rather than before it.
            var mock = NewMock();
            StubCatalog(mock, "842", "13"); // DV SSL (non-UCC)

            var plugin = BuildV2Plugin(mock.Object);

            var result = await plugin.Enroll(
                csr: GenerateCsrPem("example.com", "example.com", "extra1.example.com", "extra2.example.com"),
                subject: "CN=example.com",
                san: null,
                productInfo: MakeV2ProductInfo("842"), // non-UCC product code
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Status.Should().Be((int)EndEntityStatus.FAILED);
            result.StatusMessage.Should().Contain("2 SAN(s) beyond");
            result.StatusMessage.Should().Contain("single domain");
            result.StatusMessage.Should().NotContain("The V2 API only supports single-domain certificates",
                "the message must no longer claim V2 is single-domain-only in general — it's only true for non-UCC products");

            mock.Verify(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()), Times.Once,
                "UCC-ness can only be known after the catalog lookup, so the guard now runs after it");
            mock.Verify(c => c.PlaceOrderV2Async(
                It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()), Times.Never,
                "a rejected non-UCC request must never reach order placement");
        }

        [Fact]
        public async Task Enroll_V2_CatalogLookupFails_TreatedAsNonUcc_EnrollmentStillSucceeds()
        {
            var mock = NewMock();
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("simulated transient catalog failure"));

            V2CreateSslOrderRequest captured = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>((_, __, req, ___) => captured = req)
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = "ord_fallback_001", Status = "pending-dcv" });

            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), "ord_fallback_001", It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), "ord_fallback_001", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = "ord_fallback_001", Status = "pending-dcv" });

            var plugin = BuildV2Plugin(mock.Object);

            // Issue 0061: a catalog-lookup failure fails UCC-ness safe to false, so a non-empty
            // SAN dictionary extra here would now trip the (now dictionary-aware) non-UCC reject
            // guard instead of exercising this test's actual intent. Single-domain SAN data keeps
            // the test focused on the catalog-lookup fallback it's named for.
            var result = await plugin.Enroll(
                csr: GenerateCsrPem("example.com"),
                subject: "CN=example.com",
                san: new Dictionary<string, string[]> { ["dns"] = new[] { "example.com" } },
                productInfo: MakeV2ProductInfo("844"),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.CARequestID.Should().Be("ord_fallback_001",
                "a catalog lookup failure must not block enrollment");
            captured.Should().NotBeNull();
            V2CreateSslOrderRequest req = captured!;
            req.Certificate.AdditionalDomains.Should().BeNull(
                "on a catalog failure, UCC-ness must fail safe to false rather than guess");
        }
    }
}
