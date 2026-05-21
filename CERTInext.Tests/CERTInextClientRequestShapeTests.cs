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
        // GroupNumber → delegationInformation block
        // -----------------------------------------------------------------------

        [Fact]
        public async Task GroupNumber_Set_EmitsDelegationInformation()
        {
            StubHappyEnroll();
            var cfg = MinimalConfig();
            cfg.GroupNumber = "2171775848";

            await BuildClient(cfg).EnrollCertificateAsync(BasicEnrollRequest());

            var orderDetails = CapturedOrderBody();
            orderDetails.TryGetProperty("delegationInformation", out var delegation).Should().BeTrue();
            delegation.GetProperty("groupNumber").GetString().Should().Be("2171775848");
        }

        [Fact]
        public async Task GroupNumber_Blank_OmitsDelegationInformation()
        {
            StubHappyEnroll();
            var cfg = MinimalConfig();
            cfg.GroupNumber = string.Empty;

            await BuildClient(cfg).EnrollCertificateAsync(BasicEnrollRequest());

            var orderDetails = CapturedOrderBody();
            orderDetails.TryGetProperty("delegationInformation", out _).Should().BeFalse();
        }

        // -----------------------------------------------------------------------
        // technicalPointOfContact — overrides + requestor fallback
        // -----------------------------------------------------------------------

        [Fact]
        public async Task TechnicalContact_AllSet_EmitsExplicitValues()
        {
            StubHappyEnroll();
            var cfg = MinimalConfig();
            cfg.TechnicalContactName = "Jane Smith";
            cfg.TechnicalContactEmail = "tpc@example.com";
            cfg.TechnicalContactIsdCode = "44";
            cfg.TechnicalContactMobileNumber = "5559999999";

            await BuildClient(cfg).EnrollCertificateAsync(BasicEnrollRequest());

            var tpc = CapturedOrderBody().GetProperty("technicalPointOfContact");
            tpc.GetProperty("tpcName").GetString().Should().Be("Jane Smith");
            tpc.GetProperty("tpcEmail").GetString().Should().Be("tpc@example.com");
            tpc.GetProperty("tpcIsdCode").GetString().Should().Be("44");
            tpc.GetProperty("tpcMobileNumber").GetString().Should().Be("5559999999");
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

            var tpc = CapturedOrderBody().GetProperty("technicalPointOfContact");
            tpc.GetProperty("tpcName").GetString().Should().Be(cfg.RequestorName);
            tpc.GetProperty("tpcEmail").GetString().Should().Be(cfg.RequestorEmail);
            tpc.GetProperty("tpcIsdCode").GetString().Should().Be(cfg.RequestorIsdCode);
            tpc.GetProperty("tpcMobileNumber").GetString().Should().Be(cfg.RequestorMobileNumber);
        }

        // -----------------------------------------------------------------------
        // SSL order body defaults — AccountingModel / EmailNotifications /
        // SubscriptionAutoRenew / SubscriptionRenewCriteriaDays /
        // SubscriptionValidityYears / AutoSecureWww
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

            od.GetProperty("certificateInformation").GetProperty("autoSecureWWW").GetString().Should().Be("1");
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

            od.GetProperty("certificateInformation").GetProperty("autoSecureWWW").GetString().Should().Be("0");
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
    }
}
