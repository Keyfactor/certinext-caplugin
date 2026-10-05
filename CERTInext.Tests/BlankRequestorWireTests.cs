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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Microsoft.Extensions.Logging;
using Moq;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Pins the bytes actually POSTed to <c>GenerateOrderSSL</c> when the connector has
    /// <c>RequestorName=""</c> and <c>TechnicalContactName=""</c> (the configuration the opt-in live
    /// probe <c>BlankRequestorLiveTests</c> uses). Drives the real <see cref="CERTInextCAPlugin"/>
    /// enroll and renewal paths over a real <see cref="CERTInextClient"/> against WireMock, so the
    /// assertions are on the captured wire body, not on an intermediate object.
    ///
    /// Expected wire shape: <c>requestorInformation.requestorName == ""</c> (present, empty string —
    /// the plugin does not substitute a default for a blank-but-non-null connector value),
    /// no <c>technicalPointOfContact</c> key, and <c>agreementDetails.signerName</c> falls back to
    /// "Keyfactor Gateway".
    /// </summary>
    [Collection(LoggingStateCollection.Name)]
    public class BlankRequestorWireTests : IDisposable
    {
        private readonly WireMockServer _server;

        public BlankRequestorWireTests()
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

        private sealed class CapturingLogger : ILogger
        {
            public ConcurrentQueue<string> Messages { get; } = new();
            public IDisposable BeginScope<TState>(TState state) => null;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
                Func<TState, Exception, string> formatter) => Messages.Enqueue(formatter(state, exception));
        }

        private CERTInextClient BuildBlankRequestorClient(bool logSensitiveRequestData = false) => new CERTInextClient(new CERTInextConfig
        {
            LogSensitiveRequestData = logSensitiveRequestData,
            ApiUrl                = _server.Urls[0],
            AuthMode              = "AccessKey",
            ApiKey                = "test-key",
            AccountNumber         = "12345",
            RequestorName         = string.Empty,
            TechnicalContactName  = string.Empty,
            RequestorEmail        = "requestor@example.com",
            RequestorIsdCode      = "1",
            RequestorMobileNumber = "5550000000",
            SignerPlace           = "Austin",
            SignerIp              = "203.0.113.10",
            PageSize              = 100
        });

        private static EnrollmentProductInfo MakeProductInfo(Dictionary<string, string> extras = null)
        {
            var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ProfileId"] = "842"
            };
            if (extras != null)
                foreach (var kv in extras)
                    parameters[kv.Key] = kv.Value;
            return new EnrollmentProductInfo { ProductID = "842", ProductParameters = parameters };
        }

        private JsonElement CapturedRoot()
        {
            var posts = _server.LogEntries
                .Where(e => e.RequestMessage.Path == "/GenerateOrderSSL")
                .ToList();
            posts.Should().HaveCount(1, "exactly one GenerateOrderSSL POST should have been emitted");
            string body = posts[0].RequestMessage.Body;
            body.Should().NotBeNullOrEmpty();
            return JsonDocument.Parse(body!).RootElement;
        }

        private static void AssertBlankRequestorShape(JsonElement root)
        {
            var od = root.GetProperty("orderDetails");

            od.TryGetProperty("requestorInformation", out var ri).Should().BeTrue();
            ri.TryGetProperty("requestorName", out var name).Should().BeTrue(
                "requestorName is serialized even when blank");
            name.ValueKind.Should().Be(JsonValueKind.String);
            name.GetString().Should().Be(string.Empty,
                "a blank connector RequestorName reaches the wire as an empty string, not a substituted default");

            od.TryGetProperty("technicalPointOfContact", out _).Should().BeFalse(
                "no name resolves, so the technicalPointOfContact block is omitted entirely");

            od.GetProperty("agreementDetails").GetProperty("signerName").GetString()
                .Should().Be("Keyfactor Gateway", "blank requestor/signer name falls back to the built-in default");
        }

        [Fact]
        public async Task Enroll_New_BlankRequestorAndTechContact_WireBodyMatchesExpectedShape()
        {
            var plugin = new CERTInextCAPlugin(BuildBlankRequestorClient(), new CERTInextConfig { PickupRetries = 0 });

            await plugin.Enroll(
                MockCertificateData.FakeCsrPem, "CN=test.example.com",
                new Dictionary<string, string[]> { ["dns"] = new[] { "test.example.com" } },
                MakeProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            AssertBlankRequestorShape(CapturedRoot());
        }

        [Fact]
        public async Task Enroll_RenewOrReissue_RenewalApi_BlankRequestorAndTechContact_WireBodyMatchesExpectedShape()
        {
            var reader = new Mock<ICertificateDataReader>();
            reader.Setup(r => r.GetRequestIDBySerialNumber(It.IsAny<string>()))
                .ReturnsAsync(MockCertificateData.CertId1);
            reader.Setup(r => r.GetExpirationDateByRequestId(MockCertificateData.CertId1))
                .Returns(DateTime.UtcNow.AddDays(30));

            var plugin = new CERTInextCAPlugin(BuildBlankRequestorClient(), reader.Object);

            await plugin.Enroll(
                MockCertificateData.FakeCsrPem, "CN=test.example.com",
                new Dictionary<string, string[]> { ["dns"] = new[] { "test.example.com" } },
                MakeProductInfo(new Dictionary<string, string>
                {
                    ["PriorCertSN"] = "AABB",
                    ["RenewalWindowDays"] = "90"
                }),
                RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

            // Guard: the renewal API path (not the new-enroll fallback) must have produced the body.
            reader.Verify(r => r.GetExpirationDateByRequestId(MockCertificateData.CertId1), Times.Once);
            AssertBlankRequestorShape(CapturedRoot());
        }

        /// <summary>
        /// Justifies the live test capturing the Trace <c>PlaceOrderAsync request payload</c> dump
        /// (<c>LogSensitiveRequestData=true</c>) instead of the socket: apart from the redacted
        /// <c>meta.authKey</c>, the dump's <c>orderDetails</c> is identical to the body WireMock
        /// received.
        /// </summary>
        [Fact]
        public async Task TraceDump_OrderDetails_EqualsWireBody_WhenSensitiveLoggingOn()
        {
            string marker = $"wire-{Guid.NewGuid():N}.example.com";
            var plugin = new CERTInextCAPlugin(BuildBlankRequestorClient(logSensitiveRequestData: true),
                new CERTInextConfig { PickupRetries = 0 });

            var logger = new CapturingLogger();
            using (CERTInextClient.OverrideLoggerForTests(logger))
            {
                await plugin.Enroll(
                    MockCertificateData.FakeCsrPem, $"CN={marker}",
                    new Dictionary<string, string[]> { ["dns"] = new[] { marker } },
                    MakeProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);
            }

            const string prefix = "PlaceOrderAsync request payload: ";
            string dump = logger.Messages.Single(m => m.StartsWith(prefix, StringComparison.Ordinal) && m.Contains(marker));
            string dumpJson = dump.Substring(prefix.Length);

            dumpJson.Should().NotContain("test-key").And.Contain("***REDACTED***");
            var logged = JsonNode.Parse(dumpJson)!["orderDetails"];
            var wire = JsonNode.Parse(CapturedRoot().GetRawText())!["orderDetails"];
            JsonNode.DeepEquals(logged, wire).Should().BeTrue("the Trace dump must mirror the POSTed orderDetails");
            AssertBlankRequestorShape(JsonDocument.Parse(dumpJson).RootElement);
        }
    }
}
