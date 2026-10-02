// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Verifies the JSON body emitted by <c>BuildOrderRequestFromLegacyEnrollRequest</c>
    /// against the connector-level config fields that customers can set in the gateway
    /// admin UI.  Each test:
    ///   1. Builds a <see cref="CERTInextConfig"/> with specific field combinations,
    ///   2. Stubs <c>GenerateOrderSSL</c> + <c>TrackOrder</c> with a happy response,
    ///   3. Invokes <c>EnrollCertificateAsync</c>,
    ///   4. Reads the captured POST body from WireMock and asserts the shape.
    ///
    /// These tests pin the behaviour of the configurables documented in README.md →
    /// "CA Configuration"; if a future refactor accidentally omits one of them from
    /// the SSL order body, the corresponding test fails loudly.
    /// </summary>
    public class CERTInextClientRequestShapeTests : IDisposable
    {
        private readonly WireMockServer _server;
        private readonly string _baseUrl;

        public CERTInextClientRequestShapeTests()
        {
            _server = WireMockServer.Start();
            _baseUrl = _server.Urls[0];
        }

        public void Dispose() => _server.Stop();

        // -----------------------------------------------------------------------
        // Helpers
        // -----------------------------------------------------------------------

        private CERTInextClient BuildClient(CERTInextConfig config)
        {
            config.ApiUrl = _baseUrl;
            return new CERTInextClient(config);
        }

        private static CERTInextConfig MinimalConfig() => new CERTInextConfig
        {
            AuthMode = "AccessKey",
            ApiKey = "test-key",
            AccountNumber = "12345",
            RequestorName = "Default Requestor",
            RequestorEmail = "default@example.com",
            RequestorIsdCode = "1",
            RequestorMobileNumber = "5550000000",
            SignerPlace = "Austin",
            SignerIp = "203.0.113.10",
            PageSize = 100
        };

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

        private JsonElement CapturedOrderBody()
        {
            var generateOrderRequests = _server.LogEntries
                .Where(e => e.RequestMessage.Path == "/GenerateOrderSSL")
                .ToList();
            generateOrderRequests.Should().HaveCount(1,
                "exactly one GenerateOrderSSL POST should have been emitted");
            string body = generateOrderRequests[0].RequestMessage.Body;
            body.Should().NotBeNullOrEmpty();
            return JsonDocument.Parse(body!).RootElement.GetProperty("orderDetails");
        }

        private static EnrollCertificateRequest BasicEnrollRequest() => new EnrollCertificateRequest
        {
            ProfileId = "842",
            Csr = MockCertificateData.FakeCsrPem,
            Subject = "CN=test.example.com",
            Comment = "Unit test"
        };

        // -----------------------------------------------------------------------
        // OrganizationNumber → organizationDetails block
        // -----------------------------------------------------------------------

        [Fact]
        public async Task OrganizationNumber_Set_EmitsPreVettedOrganizationDetails()
        {
            StubHappyEnroll();
            var cfg = MinimalConfig();
            cfg.OrganizationNumber = "9876543210";

            await BuildClient(cfg).EnrollCertificateAsync(BasicEnrollRequest());

            var orderDetails = CapturedOrderBody();
            orderDetails.TryGetProperty("organizationDetails", out var orgDetails).Should().BeTrue(
                "organizationDetails must be present when OrganizationNumber is configured");
            orgDetails.GetProperty("preVetting").GetString().Should().Be("1",
                "preVetting=1 declares the org as already vetted, bypassing the manual queue");
            orgDetails.GetProperty("organizationNumber").GetString().Should().Be("9876543210");
        }

        [Fact]
        public async Task OrganizationNumber_Blank_OmitsOrganizationDetailsBlock()
        {
            StubHappyEnroll();
            var cfg = MinimalConfig();
            cfg.OrganizationNumber = string.Empty;

            await BuildClient(cfg).EnrollCertificateAsync(BasicEnrollRequest());

            var orderDetails = CapturedOrderBody();
            orderDetails.TryGetProperty("organizationDetails", out _).Should().BeFalse(
                "organizationDetails must be omitted when OrganizationNumber is unset (preserves legacy behavior)");
        }

        // -----------------------------------------------------------------------
        // Legacy (wrong) field placements must never reappear. CERTInext reads
        // groupNumber / autoSecureWWW from orderDetails and the technical contact as
        // poc* fields; the shapes below were ignored by the API.
        // -----------------------------------------------------------------------

        private static void AssertNoLegacyFieldShapes(JsonElement orderDetails)
        {
            orderDetails.TryGetProperty("delegationInformation", out _).Should().BeFalse(
                "delegationInformation{groupNumber} is not read by CERTInext — groupNumber belongs on orderDetails");
            orderDetails.GetProperty("certificateInformation").TryGetProperty("autoSecureWWW", out _).Should().BeFalse(
                "autoSecureWWW is read from orderDetails, not certificateInformation");
            CollectPropertyNames(orderDetails)
                .Where(n => n.StartsWith("tpc", StringComparison.Ordinal))
                .Should().BeEmpty("the technical contact uses poc* field names, not tpc*");
        }

        private static System.Collections.Generic.IEnumerable<string> CollectPropertyNames(JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in element.EnumerateObject())
                {
                    yield return prop.Name;
                    foreach (var nested in CollectPropertyNames(prop.Value))
                        yield return nested;
                }
            }
            else if (element.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in element.EnumerateArray())
                    foreach (var nested in CollectPropertyNames(item))
                        yield return nested;
            }
        }

        // -----------------------------------------------------------------------
        // GroupNumber → orderDetails.groupNumber
        // -----------------------------------------------------------------------

        [Fact]
        public async Task GroupNumber_Set_EmitsOrderDetailsGroupNumber()
        {
            StubHappyEnroll();
            var cfg = MinimalConfig();
            cfg.GroupNumber = "1000000001";

            await BuildClient(cfg).EnrollCertificateAsync(BasicEnrollRequest());

            var orderDetails = CapturedOrderBody();
            orderDetails.GetProperty("groupNumber").GetString().Should().Be("1000000001");
            AssertNoLegacyFieldShapes(orderDetails);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public async Task GroupNumber_Blank_OmitsGroupNumber(string blank)
        {
            StubHappyEnroll();
            var cfg = MinimalConfig();
            cfg.GroupNumber = blank;

            await BuildClient(cfg).EnrollCertificateAsync(BasicEnrollRequest());

            var orderDetails = CapturedOrderBody();
            orderDetails.TryGetProperty("groupNumber", out _).Should().BeFalse();
            AssertNoLegacyFieldShapes(orderDetails);
        }

        // -----------------------------------------------------------------------
        // technicalPointOfContact — poc* fields, name split, requestor fallback
        // -----------------------------------------------------------------------

        [Fact]
        public async Task TechnicalContact_AllSet_EmitsPocFields()
        {
            StubHappyEnroll();
            var cfg = MinimalConfig();
            cfg.TechnicalContactName = "Jane Q Smith";
            cfg.TechnicalContactEmail = "poc@example.com";
            cfg.TechnicalContactIsdCode = "44";
            cfg.TechnicalContactMobileNumber = "5559999999";

            await BuildClient(cfg).EnrollCertificateAsync(BasicEnrollRequest());

            var od = CapturedOrderBody();
            var poc = od.GetProperty("technicalPointOfContact");
            poc.GetProperty("pocFirstName").GetString().Should().Be("Jane");
            poc.GetProperty("pocLastName").GetString().Should().Be("Q Smith");
            poc.GetProperty("pocEmail").GetString().Should().Be("poc@example.com");
            poc.GetProperty("pocIsdCode").GetString().Should().Be("44");
            poc.GetProperty("pocMobileNumber").GetString().Should().Be("5559999999");
            AssertNoLegacyFieldShapes(od);
        }

        [Fact]
        public async Task TechnicalContact_AllBlank_FallsBackToRequestorDefaults()
        {
            StubHappyEnroll();
            var cfg = MinimalConfig();
            // All TechnicalContact* unset → must fall back to Requestor*
            cfg.TechnicalContactName = string.Empty;
            cfg.TechnicalContactEmail = string.Empty;
            cfg.TechnicalContactIsdCode = string.Empty;
            cfg.TechnicalContactMobileNumber = string.Empty;

            await BuildClient(cfg).EnrollCertificateAsync(BasicEnrollRequest());

            var poc = CapturedOrderBody().GetProperty("technicalPointOfContact");
            // MinimalConfig RequestorName = "Default Requestor"
            poc.GetProperty("pocFirstName").GetString().Should().Be("Default");
            poc.GetProperty("pocLastName").GetString().Should().Be("Requestor");
            poc.GetProperty("pocEmail").GetString().Should().Be(cfg.RequestorEmail);
            poc.GetProperty("pocIsdCode").GetString().Should().Be(cfg.RequestorIsdCode);
            poc.GetProperty("pocMobileNumber").GetString().Should().Be(cfg.RequestorMobileNumber);
        }

        [Fact]
        public async Task TechnicalContact_SingleTokenName_FillsFirstAndLast()
        {
            StubHappyEnroll();
            var cfg = MinimalConfig();
            cfg.TechnicalContactName = "  Operations  ";

            await BuildClient(cfg).EnrollCertificateAsync(BasicEnrollRequest());

            var poc = CapturedOrderBody().GetProperty("technicalPointOfContact");
            poc.GetProperty("pocFirstName").GetString().Should().Be("Operations");
            poc.GetProperty("pocLastName").GetString().Should().Be("Operations");
        }

        [Fact]
        public async Task TechnicalContact_PerFieldFallback_MixesOverridesAndRequestorValues()
        {
            StubHappyEnroll();
            var cfg = MinimalConfig();
            cfg.TechnicalContactName = string.Empty;           // → requestor name
            cfg.TechnicalContactEmail = "poc@example.com";     // override
            cfg.TechnicalContactIsdCode = string.Empty;        // → requestor ISD
            cfg.TechnicalContactMobileNumber = "5551112222";   // override

            await BuildClient(cfg).EnrollCertificateAsync(BasicEnrollRequest());

            var poc = CapturedOrderBody().GetProperty("technicalPointOfContact");
            poc.GetProperty("pocFirstName").GetString().Should().Be("Default");
            poc.GetProperty("pocLastName").GetString().Should().Be("Requestor");
            poc.GetProperty("pocEmail").GetString().Should().Be("poc@example.com");
            poc.GetProperty("pocIsdCode").GetString().Should().Be(cfg.RequestorIsdCode);
            poc.GetProperty("pocMobileNumber").GetString().Should().Be("5551112222");
        }

        [Fact]
        public async Task TechnicalContact_NoEmailResolved_OmitsBlock()
        {
            StubHappyEnroll();
            var cfg = MinimalConfig();
            cfg.RequestorEmail = string.Empty;
            cfg.TechnicalContactEmail = "   ";
            cfg.TechnicalContactName = "Jane Smith";

            await BuildClient(cfg).EnrollCertificateAsync(BasicEnrollRequest());

            var od = CapturedOrderBody();
            od.TryGetProperty("technicalPointOfContact", out _).Should().BeFalse(
                "a POC with no email would now be validated by CERTInext — omit it rather than reject the order");
            AssertNoLegacyFieldShapes(od);
        }

        // -----------------------------------------------------------------------
        // SSL order body defaults — AccountingModel / EmailNotifications /
        // SubscriptionAutoRenew / SubscriptionRenewCriteriaDays /
        // SubscriptionValidityYears / AutoSecureWww (→ orderDetails.autoSecureWWW)
        // -----------------------------------------------------------------------

        [Fact]
        public async Task SslBodyDefaults_AreEmitted_FromCustomConnectorValues()
        {
            StubHappyEnroll();
            var cfg = MinimalConfig();
            cfg.AccountingModel = "1";
            cfg.EmailNotifications = "1";
            cfg.SubscriptionValidityYears = "2";
            cfg.SubscriptionAutoRenew = "1";
            cfg.SubscriptionRenewCriteriaDays = "60";
            cfg.AutoSecureWww = "1";

            await BuildClient(cfg).EnrollCertificateAsync(BasicEnrollRequest());

            var od = CapturedOrderBody();
            od.GetProperty("accountingModel").GetString().Should().Be("1");
            od.GetProperty("emailNotifications").GetString().Should().Be("1");

            var sub = od.GetProperty("subscriptionDetails");
            sub.GetProperty("validity").GetString().Should().Be("2");
            sub.GetProperty("autoRenew").GetString().Should().Be("1");
            sub.GetProperty("renewCriteria").GetString().Should().Be("60");

            od.GetProperty("autoSecureWWW").GetString().Should().Be("1");
            AssertNoLegacyFieldShapes(od);
        }

        [Fact]
        public async Task SslBodyDefaults_AreSafeFallbacks_WhenConfigUntouched()
        {
            StubHappyEnroll();
            var cfg = MinimalConfig();
            // Leave new fields at their CERTInextConfig defaults

            await BuildClient(cfg).EnrollCertificateAsync(BasicEnrollRequest());

            var od = CapturedOrderBody();
            od.GetProperty("accountingModel").GetString().Should().Be("2");
            od.GetProperty("emailNotifications").GetString().Should().Be("0");

            var sub = od.GetProperty("subscriptionDetails");
            sub.GetProperty("validity").GetString().Should().Be("1");
            sub.GetProperty("autoRenew").GetString().Should().Be("0");
            sub.GetProperty("renewCriteria").GetString().Should().Be("30");

            od.GetProperty("autoSecureWWW").GetString().Should().Be("0",
                "the documented AutoSecureWww default of 0 must actually be sent, or CERTInext applies its own default of 1");
            AssertNoLegacyFieldShapes(od);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public async Task AutoSecureWww_Blank_SendsZero(string blank)
        {
            StubHappyEnroll();
            var cfg = MinimalConfig();
            cfg.AutoSecureWww = blank;

            await BuildClient(cfg).EnrollCertificateAsync(BasicEnrollRequest());

            CapturedOrderBody().GetProperty("autoSecureWWW").GetString().Should().Be("0");
        }


        // -----------------------------------------------------------------------
        // ValidityDays request-parameter still overrides the connector default
        // -----------------------------------------------------------------------

        [Fact]
        public async Task ValidityDays_OnRequest_OverridesConnectorDefault()
        {
            StubHappyEnroll();
            var cfg = MinimalConfig();
            cfg.SubscriptionValidityYears = "1";   // connector default = 1 year

            var req = BasicEnrollRequest();
            req.ValidityDays = 730;                // 2 years

            await BuildClient(cfg).EnrollCertificateAsync(req);

            CapturedOrderBody().GetProperty("subscriptionDetails")
                .GetProperty("validity").GetString().Should().Be("2");
        }

        // -----------------------------------------------------------------------
        // RenewCertificateAsync — productCode resolution (issue #26 / local issues/0012)
        // Renewals go out as a fresh GenerateOrderSSL order; the product code must
        // come from the template (RenewCertificateRequest.ProfileId) when supplied,
        // falling back to the connector's DefaultProductCode only when it is not.
        // -----------------------------------------------------------------------

        [Fact]
        public async Task RenewCertificateAsync_ProfileIdSet_UsesTemplateProductCode()
        {
            StubHappyEnroll();
            var cfg = MinimalConfig();
            cfg.DefaultProductCode = "connector-default-code";

            var renewReq = new RenewCertificateRequest
            {
                Csr = MockCertificateData.FakeCsrPem,
                ProfileId = "template-product-code",
                ValidityDays = 365,
                Comment = "Renewal test"
            };

            await BuildClient(cfg).RenewCertificateAsync(MockCertificateData.OrderNumber1, renewReq);

            CapturedOrderBody().GetProperty("productCode").GetString()
                .Should().Be("template-product-code",
                    "the template's own product code must win over the connector default");
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public async Task RenewCertificateAsync_ProfileIdBlank_FallsBackToConnectorDefault(string blankProfileId)
        {
            StubHappyEnroll();
            var cfg = MinimalConfig();
            cfg.DefaultProductCode = "connector-default-code";

            var renewReq = new RenewCertificateRequest
            {
                Csr = MockCertificateData.FakeCsrPem,
                ProfileId = blankProfileId,
                ValidityDays = 365,
                Comment = "Renewal test"
            };

            await BuildClient(cfg).RenewCertificateAsync(MockCertificateData.OrderNumber1, renewReq);

            CapturedOrderBody().GetProperty("productCode").GetString()
                .Should().Be("connector-default-code",
                    "a blank ProfileId must fall back to the connector's DefaultProductCode, not an empty string");
        }

        // -----------------------------------------------------------------------
        // RenewCertificateAsync — full order-details shape. Renewal shares the
        // new-enrollment builder, so it must send every field a new order sends and
        // follow the connector's validity / autoRenew / emailNotifications /
        // accountingModel settings (previously hard-coded validity="1" and DTO
        // defaults autoRenew="1" / emailNotifications="1", and omitted groupNumber,
        // autoSecureWWW, technical contact, organizationDetails and remarks).
        // -----------------------------------------------------------------------

        private static CERTInextConfig FullyConfiguredConfig()
        {
            var cfg = MinimalConfig();
            cfg.GroupNumber = "1000000001";
            cfg.OrganizationNumber = "2000000002";
            cfg.AccountingModel = "1";
            cfg.EmailNotifications = "0";
            cfg.SubscriptionValidityYears = "3";
            cfg.SubscriptionAutoRenew = "0";
            cfg.SubscriptionRenewCriteriaDays = "60";
            cfg.AutoSecureWww = "0";
            cfg.TechnicalContactName = "Pat Example";
            cfg.TechnicalContactEmail = "poc@example.com";
            cfg.TechnicalContactIsdCode = "44";
            cfg.TechnicalContactMobileNumber = "5553334444";
            return cfg;
        }

        [Fact]
        public async Task RenewCertificateAsync_SendsFullOrderDetails_FromConnectorConfig()
        {
            StubHappyEnroll();
            var cfg = FullyConfiguredConfig();

            var renewReq = new RenewCertificateRequest
            {
                Csr = MockCertificateData.FakeCsrPem,
                Subject = "CN=renew.example.com,O=Example",
                ProfileId = "842",
                Sans = new System.Collections.Generic.List<SanEntry>
                {
                    new SanEntry { Type = "dns", Value = "renew.example.com" },
                    new SanEntry { Type = "dns", Value = "alt.example.com" }
                },
                ValidityYears = 2,
                RequesterName = "Renew Requester",
                RequesterEmail = "renew@example.com",
                Comment = "Renewed via Keyfactor Command. Prior ID: ORD-AAA-111."
            };

            await BuildClient(cfg).RenewCertificateAsync(MockCertificateData.OrderNumber1, renewReq);

            var od = CapturedOrderBody();
            od.GetProperty("productCode").GetString().Should().Be("842");
            od.GetProperty("accountingModel").GetString().Should().Be("1");
            od.GetProperty("saveAndHold").GetString().Should().Be("0");
            od.GetProperty("emailNotifications").GetString().Should().Be("0");
            od.GetProperty("groupNumber").GetString().Should().Be("1000000001");
            od.GetProperty("autoSecureWWW").GetString().Should().Be("0");

            var org = od.GetProperty("organizationDetails");
            org.GetProperty("preVetting").GetString().Should().Be("1");
            org.GetProperty("organizationNumber").GetString().Should().Be("2000000002");

            var requestor = od.GetProperty("requestorInformation");
            requestor.GetProperty("requestorName").GetString().Should().Be("Renew Requester");
            requestor.GetProperty("requestorEmail").GetString().Should().Be("renew@example.com");
            requestor.GetProperty("requestorIsdCode").GetString().Should().Be(cfg.RequestorIsdCode);
            requestor.GetProperty("requestorMobileNumber").GetString().Should().Be(cfg.RequestorMobileNumber);

            var sub = od.GetProperty("subscriptionDetails");
            sub.GetProperty("validity").GetString().Should().Be("2", "the plugin-supplied ValidityYears must win");
            sub.GetProperty("autoRenew").GetString().Should().Be("0");
            sub.GetProperty("renewCriteria").GetString().Should().Be("60");

            var ci = od.GetProperty("certificateInformation");
            ci.GetProperty("domainName").GetString().Should().Be("renew.example.com");
            ci.GetProperty("additionalDomains").EnumerateArray().Select(e => e.GetString())
                .Should().Equal("alt.example.com");

            var poc = od.GetProperty("technicalPointOfContact");
            poc.GetProperty("pocFirstName").GetString().Should().Be("Pat");
            poc.GetProperty("pocLastName").GetString().Should().Be("Example");
            poc.GetProperty("pocEmail").GetString().Should().Be("poc@example.com");
            poc.GetProperty("pocIsdCode").GetString().Should().Be("44");
            poc.GetProperty("pocMobileNumber").GetString().Should().Be("5553334444");

            od.GetProperty("csr").GetString().Should().Be(MockCertificateData.FakeCsrPem);
            od.GetProperty("agreementDetails").GetProperty("acceptAgreement").GetString().Should().Be("1");
            od.GetProperty("additionalInformation").GetProperty("remarks").GetString()
                .Should().Be("Renewed via Keyfactor Command. Prior ID: ORD-AAA-111.");

            AssertNoLegacyFieldShapes(od);
        }

        [Fact]
        public async Task RenewCertificateAsync_NoValidityOnRequest_UsesConnectorValidity()
        {
            StubHappyEnroll();
            var cfg = MinimalConfig();
            cfg.SubscriptionValidityYears = "3";

            var renewReq = new RenewCertificateRequest
            {
                Csr = MockCertificateData.FakeCsrPem,
                Subject = "CN=renew.example.com",
                ProfileId = "842"
            };

            await BuildClient(cfg).RenewCertificateAsync(MockCertificateData.OrderNumber1, renewReq);

            CapturedOrderBody().GetProperty("subscriptionDetails").GetProperty("validity").GetString()
                .Should().Be("3", "renewal must no longer hard-code validity=1");
        }

        [Fact]
        public async Task RenewCertificateAsync_ValidityDays_ConvertsToYears()
        {
            StubHappyEnroll();
            var cfg = MinimalConfig();
            cfg.SubscriptionValidityYears = "1";

            var renewReq = new RenewCertificateRequest
            {
                Csr = MockCertificateData.FakeCsrPem,
                Subject = "CN=renew.example.com",
                ProfileId = "842",
                ValidityDays = 730
            };

            await BuildClient(cfg).RenewCertificateAsync(MockCertificateData.OrderNumber1, renewReq);

            CapturedOrderBody().GetProperty("subscriptionDetails").GetProperty("validity").GetString()
                .Should().Be("2");
        }

        [Fact]
        public async Task RenewCertificateAsync_ConfigUntouched_UsesConnectorDefaultsNotDtoDefaults()
        {
            StubHappyEnroll();
            var cfg = MinimalConfig();

            var renewReq = new RenewCertificateRequest
            {
                Csr = MockCertificateData.FakeCsrPem,
                Subject = "CN=renew.example.com",
                ProfileId = "842"
            };

            await BuildClient(cfg).RenewCertificateAsync(MockCertificateData.OrderNumber1, renewReq);

            var od = CapturedOrderBody();
            od.GetProperty("accountingModel").GetString().Should().Be("2");
            od.GetProperty("emailNotifications").GetString().Should().Be("0",
                "the connector default (0) must apply, not the DTO default (1)");
            od.GetProperty("subscriptionDetails").GetProperty("autoRenew").GetString().Should().Be("0",
                "the connector default (0) must apply, not the DTO default (1)");
            od.GetProperty("subscriptionDetails").GetProperty("renewCriteria").GetString().Should().Be("30");
            od.GetProperty("autoSecureWWW").GetString().Should().Be("0");
            od.TryGetProperty("groupNumber", out _).Should().BeFalse();
            od.TryGetProperty("organizationDetails", out _).Should().BeFalse();
            od.GetProperty("technicalPointOfContact").GetProperty("pocEmail").GetString()
                .Should().Be(cfg.RequestorEmail);
            od.GetProperty("additionalInformation").GetProperty("remarks").GetString()
                .Should().NotBeNullOrWhiteSpace();
            AssertNoLegacyFieldShapes(od);
        }

        // -----------------------------------------------------------------------
        // SplitContactName — TechnicalContactName → pocFirstName / pocLastName
        // -----------------------------------------------------------------------

        [Theory]
        [InlineData("Jane Smith", "Jane", "Smith")]
        [InlineData("Jane Q Smith", "Jane", "Q Smith")]
        [InlineData("  Jane   Smith  ", "Jane", "Smith")]
        [InlineData("Jane\tSmith", "Jane", "Smith")]
        [InlineData("Jane  Q  Smith", "Jane", "Q  Smith")]
        [InlineData("Operations", "Operations", "Operations")]
        [InlineData("  Operations  ", "Operations", "Operations")]
        [InlineData("", "", "")]
        [InlineData("   ", "", "")]
        [InlineData(null, "", "")]
        public void SplitContactName_SplitsOnFirstWhitespaceRun(string input, string expectedFirst, string expectedLast)
        {
            var (first, last) = CERTInextClient.SplitContactName(input);

            first.Should().Be(expectedFirst);
            last.Should().Be(expectedLast);
        }
    }
}
