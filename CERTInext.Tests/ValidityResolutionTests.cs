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
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Moq;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Pins the subscription-term rule <c>max(ValidityYears, ceil(ValidityDays / 365))</c> (each counted
    /// only when set), falling back to the connector's <c>SubscriptionValidityYears</c>. Both template
    /// fields default to one year, so a field left at its default must never beat an explicit value in
    /// the other (a template saved with ValidityDays=730 and the default ValidityYears=1 was a 2-year
    /// order in 1.0.0). Drives the real plugin over a real client against WireMock and asserts on the
    /// captured <c>subscriptionDetails.validity</c>.
    /// </summary>
    [Collection(LoggingStateCollection.Name)]
    public class ValidityResolutionTests : IDisposable
    {
        private readonly WireMockServer _server;

        public ValidityResolutionTests()
        {
            _server = WireMockServer.Start();
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

        public void Dispose() => _server.Stop();

        private CERTInextClient BuildClient(string connectorValidityYears) => new CERTInextClient(new CERTInextConfig
        {
            ApiUrl = _server.Urls[0],
            AuthMode = "AccessKey",
            ApiKey = "test-key",
            AccountNumber = "12345",
            RequestorName = "Default Requestor",
            RequestorEmail = "default@example.com",
            RequestorIsdCode = "1",
            RequestorMobileNumber = "5550000000",
            SignerPlace = "Austin",
            SignerIp = "203.0.113.10",
            PageSize = 100,
            SubscriptionValidityYears = connectorValidityYears
        });

        private static EnrollmentProductInfo MakeProductInfo(string years, string days, Dictionary<string, string> extras = null)
        {
            var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ProfileId"] = "842"
            };
            if (years != null) parameters["ValidityYears"] = years;
            if (days != null) parameters["ValidityDays"] = days;
            if (extras != null)
                foreach (var kv in extras)
                    parameters[kv.Key] = kv.Value;
            return new EnrollmentProductInfo { ProductID = "842", ProductParameters = parameters };
        }

        private string CapturedValidity()
        {
            var posts = _server.LogEntries.Where(e => e.RequestMessage.Path == "/GenerateOrderSSL").ToList();
            posts.Should().HaveCount(1, "exactly one GenerateOrderSSL POST should have been emitted");
            return JsonDocument.Parse(posts[0].RequestMessage.Body!).RootElement
                .GetProperty("orderDetails").GetProperty("subscriptionDetails").GetProperty("validity").GetString();
        }

        // years/days: null = parameter absent from the template; connector: SubscriptionValidityYears.
        [Theory]
        [InlineData("1", "730", "1", "2")]    // default years must not shorten an explicit days value (1.0.0 behavior)
        [InlineData("3", "365", "1", "3")]    // default days must not shorten an explicit years value
        [InlineData("2", "730", "1", "2")]
        [InlineData("1", "365", "1", "1")]    // both at defaults
        [InlineData(null, "45", "1", "1")]    // sub-year days round up to one year
        [InlineData(null, "400", "1", "2")]
        [InlineData(null, "365", "3", "1")]   // set template value beats connector default
        [InlineData("0", "0", "2", "2")]      // zero = unset -> connector value
        [InlineData(null, null, "2", "2")]    // neither set -> connector value
        [InlineData(null, null, "", "1")]     // neither set, blank connector config
        public async Task Enroll_New_FromTemplateParameters_SendsResolvedSubscriptionTerm(
            string years, string days, string connector, string expected)
        {
            var plugin = new CERTInextCAPlugin(BuildClient(connector), new CERTInextConfig { PickupRetries = 0 });

            await plugin.Enroll(
                MockCertificateData.FakeCsrPem, "CN=test.example.com",
                new Dictionary<string, string[]> { ["dns"] = new[] { "test.example.com" } },
                MakeProductInfo(years, days), RequestFormat.PKCS10, EnrollmentType.New);

            CapturedValidity().Should().Be(expected);
        }

        [Theory]
        [InlineData("1", "730", "1", "2")]
        [InlineData("3", "365", "1", "3")]
        [InlineData(null, null, "2", "2")]
        public async Task Enroll_RenewOrReissue_RenewalApi_FromTemplateParameters_UsesSameRule(
            string years, string days, string connector, string expected)
        {
            var reader = new Mock<ICertificateDataReader>();
            reader.Setup(r => r.GetRequestIDBySerialNumber(It.IsAny<string>()))
                .ReturnsAsync(MockCertificateData.CertId1);
            reader.Setup(r => r.GetExpirationDateByRequestId(MockCertificateData.CertId1))
                .Returns(DateTime.UtcNow.AddDays(30));

            var plugin = new CERTInextCAPlugin(BuildClient(connector), reader.Object);

            await plugin.Enroll(
                MockCertificateData.FakeCsrPem, "CN=test.example.com",
                new Dictionary<string, string[]> { ["dns"] = new[] { "test.example.com" } },
                MakeProductInfo(years, days, new Dictionary<string, string>
                {
                    ["PriorCertSN"] = "AABB",
                    ["RenewalWindowDays"] = "90"
                }),
                RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

            // Guard: the renewal API path (not the new-enroll fallback) must have produced the body.
            reader.Verify(r => r.GetExpirationDateByRequestId(MockCertificateData.CertId1), Times.Once);
            CapturedValidity().Should().Be(expected);
        }
    }
}
