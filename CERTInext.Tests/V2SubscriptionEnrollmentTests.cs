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
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Regression tests for issues/0027-v2-request-builder-drops-config-fields.md items 2a/2b: the
    /// V2 order body's <c>subscription</c> block hardcoded <c>autoRenew=false</c> and
    /// <c>renewBeforeDays=30</c>, ignoring the connector's <c>SubscriptionAutoRenew</c>/
    /// <c>SubscriptionRenewCriteriaDays</c> config entirely. These tests exercise
    /// <c>EnrollV2Async</c> end-to-end (through <see cref="CERTInextCAPlugin.Enroll"/>) against a
    /// Strict <see cref="ICERTInextClient"/> mock, plus direct DTO serialization checks for
    /// <see cref="V2SubscriptionParams.RenewBeforeDays"/>.
    /// </summary>
    public class V2SubscriptionEnrollmentTests
    {
        private static Mock<ICERTInextClient> NewMock() =>
            new Mock<ICERTInextClient>(MockBehavior.Strict);

        // Defaults here intentionally match CERTInextConfig's own property defaults ("0"/"30") —
        // NOT a `?? "30"`-style fallback applied to the parameter, which would silently coerce an
        // explicitly-passed null (a real Theory case below) back to "30" and defeat that test case.
        private static CERTInextCAPlugin BuildV2Plugin(
            ICERTInextClient client,
            string subscriptionAutoRenew = "0",
            string subscriptionRenewCriteriaDays = "30") =>
            new CERTInextCAPlugin(client, new CERTInextConfig
            {
                UseV2Api                      = true,
                ApiUrl                        = "https://v2.certinext.io",
                OAuthClientId                 = "my-client",
                OAuthClientSecret             = "my-secret",
                RequestorName                 = "Test User",
                RequestorEmail                = "test@example.com",
                SignerIp                      = "1.2.3.4",
                SignerPlace                   = "New York",
                PickupRetries                 = 0,
                SubscriptionAutoRenew         = subscriptionAutoRenew,
                SubscriptionRenewCriteriaDays = subscriptionRenewCriteriaDays
            });

        private static EnrollmentProductInfo MakeV2ProductInfo(string productCode, string productVariant) =>
            new EnrollmentProductInfo
            {
                ProductID = "DV SSL",
                ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ProductCode"]    = productCode,
                    ["ProductFamily"]  = "ssl",
                    ["ProductVariant"] = productVariant,
                    ["DomainName"]     = "example.com"
                }
            };

        private static void StubCatalog(Mock<ICERTInextClient> mock, string productCode, string productTypeId) =>
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = productCode, ProductTypeId = productTypeId, Active = true }
                });

        private static void StubHappyOrderPlacement(Mock<ICERTInextClient> mock, string orderId)
        {
            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), orderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);

            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), orderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = orderId, Status = "pending-dcv" });
        }

        private static string GenerateCsrPem(string cn)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            AsymmetricCipherKeyPair kp = keyGen.GenerateKeyPair();

            var csr = new Pkcs10CertificationRequest(
                "SHA256withRSA", new X509Name($"CN={cn}"), kp.Public, null, kp.Private);

            return "-----BEGIN CERTIFICATE REQUEST-----\n"
                 + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                 + "\n-----END CERTIFICATE REQUEST-----";
        }

        private static async Task<(EnrollmentResult Result, V2CreateSslOrderRequest Captured)> RunEnrollAsync(
            Mock<ICERTInextClient> mock, CERTInextCAPlugin plugin, string orderId = "ord_sub_001")
        {
            V2CreateSslOrderRequest captured = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>((_, __, req, ___) => captured = req)
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = orderId, Status = "pending-dcv" });

            var result = await plugin.Enroll(
                csr: GenerateCsrPem("example.com"),
                subject: "CN=example.com",
                san: null,
                productInfo: MakeV2ProductInfo("842", "dv"),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            return (result, captured);
        }

        // ---------------------------------------------------------------------------
        // EnrollV2Async wiring — SubscriptionAutoRenew -> Subscription.AutoRenew
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_V2_SubscriptionAutoRenew_1_SetsAutoRenewTrue()
        {
            var mock = NewMock();
            StubCatalog(mock, "842", "13"); // DV SSL (non-UCC)
            StubHappyOrderPlacement(mock, "ord_sub_001");

            var plugin = BuildV2Plugin(mock.Object, subscriptionAutoRenew: "1");

            var (result, captured) = await RunEnrollAsync(mock, plugin);

            result.CARequestID.Should().Be("ord_sub_001");
            captured.Should().NotBeNull();
            captured!.Subscription.Should().NotBeNull();
            captured.Subscription.AutoRenew.Should().BeTrue(
                "SubscriptionAutoRenew=\"1\" must set Subscription.AutoRenew=true, the same bare " +
                "\"1\"-means-true comparison AutoSecureWww already uses");
        }

        [Theory]
        [InlineData("0")]
        [InlineData("")]
        [InlineData("yes")]
        [InlineData("true")]
        public async Task Enroll_V2_SubscriptionAutoRenew_NonOneValues_SetsAutoRenewFalse(string configValue)
        {
            var mock = NewMock();
            StubCatalog(mock, "842", "13");
            StubHappyOrderPlacement(mock, "ord_sub_002");

            var plugin = BuildV2Plugin(mock.Object, subscriptionAutoRenew: configValue);

            var (result, captured) = await RunEnrollAsync(mock, plugin, "ord_sub_002");

            result.CARequestID.Should().Be("ord_sub_002");
            captured!.Subscription.AutoRenew.Should().BeFalse(
                $"only the literal value \"1\" should set AutoRenew=true — '{configValue}' must not");
        }

        // ---------------------------------------------------------------------------
        // EnrollV2Async wiring — SubscriptionRenewCriteriaDays -> Subscription.RenewBeforeDays
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public async Task Enroll_V2_SubscriptionRenewCriteriaDays_Blank_OmitsRenewBeforeDays(string configValue)
        {
            var mock = NewMock();
            StubCatalog(mock, "842", "13");
            StubHappyOrderPlacement(mock, "ord_sub_003");

            var plugin = BuildV2Plugin(mock.Object, subscriptionRenewCriteriaDays: configValue);

            var (result, captured) = await RunEnrollAsync(mock, plugin, "ord_sub_003");

            result.CARequestID.Should().Be("ord_sub_003");
            captured!.Subscription.RenewBeforeDays.Should().BeNull(
                "a blank/unset SubscriptionRenewCriteriaDays must leave RenewBeforeDays null so the " +
                "field is omitted and the CA's documented default of 30 applies");
        }

        [Fact]
        public async Task Enroll_V2_SubscriptionRenewCriteriaDays_ValidValue_SetsRenewBeforeDays()
        {
            var mock = NewMock();
            StubCatalog(mock, "842", "13");
            StubHappyOrderPlacement(mock, "ord_sub_004");

            var plugin = BuildV2Plugin(mock.Object, subscriptionRenewCriteriaDays: "45");

            var (result, captured) = await RunEnrollAsync(mock, plugin, "ord_sub_004");

            result.CARequestID.Should().Be("ord_sub_004");
            captured!.Subscription.RenewBeforeDays.Should().Be(45,
                "a configured SubscriptionRenewCriteriaDays must be forwarded to RenewBeforeDays " +
                "as-is, independent of the AutoRenew value");
        }

        [Fact]
        public async Task Enroll_V2_SubscriptionRenewCriteriaDays_ZeroIsValid_SetsRenewBeforeDaysZero()
        {
            var mock = NewMock();
            StubCatalog(mock, "842", "13");
            StubHappyOrderPlacement(mock, "ord_sub_005");

            var plugin = BuildV2Plugin(mock.Object, subscriptionRenewCriteriaDays: "0");

            var (result, captured) = await RunEnrollAsync(mock, plugin, "ord_sub_005");

            result.CARequestID.Should().Be("ord_sub_005");
            captured!.Subscription.RenewBeforeDays.Should().Be(0,
                "zero is a valid non-negative integer and must be sent as-is, not treated as blank");
        }

        // ---------------------------------------------------------------------------
        // EnrollV2Async — bad SubscriptionRenewCriteriaDays fails fast, before any CA call
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData("abc")]
        [InlineData("-1")]
        public async Task Enroll_V2_SubscriptionRenewCriteriaDays_Invalid_FailsEnrollment_NoHttpCallMade(string configValue)
        {
            // Strict mock with NO setups at all: if EnrollV2Async made any client call before
            // failing validation, Moq would throw a MockException for the unstubbed invocation
            // and this test would fail — that, plus the explicit Verify(Times.Never) calls below,
            // together confirm zero HTTP requests are sent for an invalid config value.
            var mock = NewMock();

            var plugin = BuildV2Plugin(mock.Object, subscriptionRenewCriteriaDays: configValue);

            var result = await plugin.Enroll(
                csr: GenerateCsrPem("example.com"),
                subject: "CN=example.com",
                san: null,
                productInfo: MakeV2ProductInfo("842", "dv"),
                requestFormat: RequestFormat.PKCS10,
                enrollmentType: EnrollmentType.New);

            result.Status.Should().Be((int)EndEntityStatus.FAILED);
            result.StatusMessage.Should().Contain("SubscriptionRenewCriteriaDays",
                "the failure message must name the offending config field");

            mock.Verify(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()), Times.Never);
            mock.Verify(c => c.PlaceOrderV2Async(
                It.IsAny<string>(), It.IsAny<string>(),
                It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // DTO serialization — renewBeforeDays key present/absent on the wire
        //
        // Unlike GroupNumber/PreVettingToken (which carry their own per-property
        // [JsonIgnore(Condition = WhenWritingNull)]), RenewBeforeDays relies solely on the
        // client's global serializer options (CERTInextClient.GetJsonOptions,
        // DefaultIgnoreCondition = WhenWritingNull) to omit it when null — by design, per issue
        // 0027's fix. GetJsonOptions() is private, so these tests build an equivalent
        // JsonSerializerOptions inline to verify that global-option omission actually works for
        // this property, rather than relying on plain JsonSerializer.Serialize(req) (whose default
        // options do NOT ignore nulls and would show "renewBeforeDays":null instead of omitting it).
        // ---------------------------------------------------------------------------

        private static JsonSerializerOptions ClientEquivalentJsonOptions() => new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        [Fact]
        public void V2SubscriptionParams_Serialization_OmitsRenewBeforeDays_WhenNull()
        {
            var subscription = new V2SubscriptionParams
            {
                ValidityYears   = 1,
                AutoRenew       = false,
                RenewBeforeDays = null
            };

            string json = JsonSerializer.Serialize(subscription, ClientEquivalentJsonOptions());

            json.Should().NotContain("renewBeforeDays",
                "the renewBeforeDays key itself must be absent when unset, not present-but-null, " +
                "under the client's actual serializer options");
        }

        [Fact]
        public void V2SubscriptionParams_Serialization_IncludesRenewBeforeDays_WhenSet()
        {
            var subscription = new V2SubscriptionParams
            {
                ValidityYears   = 1,
                AutoRenew       = true,
                RenewBeforeDays = 45
            };

            string json = JsonSerializer.Serialize(subscription, ClientEquivalentJsonOptions());

            json.Should().Contain("\"renewBeforeDays\":45");
        }
    }
}
