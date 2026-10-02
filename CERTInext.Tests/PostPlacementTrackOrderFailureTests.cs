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
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.Extensions.CAPlugin.CERTInext.Models;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using Moq;
using WireMock;
using WireMock.Matchers;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using WireMock.Types;
using WireMock.Util;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Issue 0077: once <c>GenerateOrderSSL</c> has returned an order number, a failure of the
    /// follow-up <c>TrackOrder</c> (transient 5xx, a timeout, or an EMS-9xx "not found" during
    /// propagation lag that surfaces as <see cref="KeyNotFoundException"/>) must not fail Enroll or
    /// Renewal. A paid order already exists at CERTInext; failing here would hide its order number
    /// from Command and invite an operator retry that places a duplicate paid order. The client
    /// logs a Warning naming the order and returns a pending result carrying the order number, so
    /// sync and pickup finish the order later.
    ///
    /// Driven against WireMock with the real <see cref="CERTInextClient"/>. All data is synthetic.
    /// </summary>
    [Collection("CERTInextClientLogger-NoParallel")]
    public class PostPlacementTrackOrderFailureTests : IDisposable
    {
        private const string PriorOrder = MockCertificateData.OrderNumber1;
        private const string NewOrder = MockCertificateData.OrderNumber2;

        private readonly WireMockServer _server;

        public PostPlacementTrackOrderFailureTests()
        {
            _server = WireMockServer.Start();
        }

        public void Dispose() => _server.Stop();

        private sealed class CapturingLogger : ILogger
        {
            public ConcurrentQueue<(LogLevel Level, string Message, Exception Exception)> Entries { get; } = new();
            public IDisposable BeginScope<TState>(TState state) => null;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
                Func<TState, Exception, string> formatter) => Entries.Enqueue((logLevel, formatter(state, exception), exception));
        }

        private CERTInextConfig Config() => new CERTInextConfig
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
            // Plugin-level tests: keep the synchronous pickup poll out of the way.
            PickupRetries = 0
        };

        private CERTInextClient BuildClient() => new CERTInextClient(Config());

        private static EnrollCertificateRequest EnrollReq() => new EnrollCertificateRequest
        {
            ProfileId = "842",
            Csr = MockCertificateData.FakeCsrPem,
            Subject = "CN=test.example.com",
            Comment = "Unit test"
        };

        private static RenewCertificateRequest RenewReq() => new RenewCertificateRequest
        {
            Csr = MockCertificateData.FakeCsrPem,
            Subject = "CN=test.example.com",
            ProfileId = "842",
            Comment = "Unit test"
        };

        private void StubPlacement(string orderNumber) =>
            _server.Given(Request.Create().WithPath("/GenerateOrderSSL").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.GenerateOrderSuccessJson(orderNumber)));

        private void StubTrackOrderOk(string orderNumber, string body) =>
            _server.Given(Request.Create().WithPath("/TrackOrder").UsingPost()
                    .WithBody(new WildcardMatcher($"*{orderNumber}*")))
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json").WithBody(body));

        /// <summary>
        /// Makes TrackOrder for <paramref name="orderNumber"/> fail the way the issue describes.
        /// <c>http500</c> = transient server error, <c>ems100</c> = CA-reported failure,
        /// <c>http404</c> / <c>ems913</c> = "not found" (propagation lag) -> KeyNotFoundException.
        /// </summary>
        private void StubTrackOrderFailure(string orderNumber, string scenario)
        {
            var response = Response.Create().WithHeader("Content-Type", "application/json");
            switch (scenario)
            {
                case "http500":
                    response = response.WithStatusCode(500).WithBody(MockCertificateData.ServerErrorJson());
                    break;
                case "http404":
                    response = response.WithStatusCode(404).WithBody(MockCertificateData.ApiFailureJson("EMS-913", "Order not found"));
                    break;
                case "ems913":
                    response = response.WithStatusCode(200).WithBody(MockCertificateData.ApiFailureJson("EMS-913", "Order not found"));
                    break;
                case "ems100":
                    response = response.WithStatusCode(200).WithBody(MockCertificateData.ApiFailureJson("EMS-100", "An error occurred"));
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(scenario));
            }

            _server.Given(Request.Create().WithPath("/TrackOrder").UsingPost()
                    .WithBody(new WildcardMatcher($"*{orderNumber}*")))
                .RespondWith(response);
        }

        private int CallsTo(string path) => _server.LogEntries.Count(e => e.RequestMessage.Path == path);

        private static void AssertWarningNamesOrder(CapturingLogger logger, string orderNumber, bool expectKeyNotFound)
        {
            var warnings = logger.Entries
                .Where(e => e.Level == LogLevel.Warning && e.Message.Contains(orderNumber) && e.Exception != null)
                .ToList();
            warnings.Should().NotBeEmpty("the swallowed TrackOrder failure must be logged as a Warning naming the order");
            if (expectKeyNotFound)
                warnings.Should().Contain(w => w.Exception is KeyNotFoundException);
            else
                warnings.Should().Contain(w => !(w.Exception is KeyNotFoundException));
        }

        // ---------------------------------------------------------------------------
        // Client: enroll
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData("http500", false)]
        [InlineData("ems100", false)]
        [InlineData("http404", true)]
        [InlineData("ems913", true)]
        public async Task Enroll_TrackOrderFailsAfterPlacement_ReturnsPendingWithOrderNumber(string scenario, bool expectKeyNotFound)
        {
            StubPlacement(NewOrder);
            StubTrackOrderFailure(NewOrder, scenario);

            var logger = new CapturingLogger();
            EnrollCertificateResponse resp;
            using (CERTInextClient.OverrideLoggerForTests(logger))
                resp = await BuildClient().EnrollCertificateAsync(EnrollReq());

            resp.Id.Should().Be(NewOrder);
            resp.Certificate.Should().BeNull();
            StatusMapper.ToRequestDisposition(resp.Status).Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            CallsTo("/GenerateOrderSSL").Should().Be(1, "the order must not be placed twice");
            CallsTo("/GetCertificate").Should().Be(0, "no download is attempted when the status is unknown");
            AssertWarningNamesOrder(logger, NewOrder, expectKeyNotFound);
        }

        // ---------------------------------------------------------------------------
        // Client: renewal
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData("http500", false)]
        [InlineData("ems100", false)]
        [InlineData("http404", true)]
        [InlineData("ems913", true)]
        public async Task Renewal_TrackOrderFailsAfterPlacement_ReturnsPendingWithOrderNumber(string scenario, bool expectKeyNotFound)
        {
            // The prior-order TrackOrder (pre-placement) succeeds; only the new order's fails.
            StubTrackOrderOk(PriorOrder, MockCertificateData.TrackOrderIssuedJson(PriorOrder));
            StubPlacement(NewOrder);
            StubTrackOrderFailure(NewOrder, scenario);

            var logger = new CapturingLogger();
            EnrollCertificateResponse resp;
            using (CERTInextClient.OverrideLoggerForTests(logger))
                resp = await BuildClient().RenewCertificateAsync(PriorOrder, RenewReq());

            resp.Id.Should().Be(NewOrder);
            resp.Certificate.Should().BeNull();
            StatusMapper.ToRequestDisposition(resp.Status).Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            CallsTo("/GenerateOrderSSL").Should().Be(1, "the renewal order must not be placed twice");
            CallsTo("/GetCertificate").Should().Be(0);
            AssertWarningNamesOrder(logger, NewOrder, expectKeyNotFound);
        }

        // ---------------------------------------------------------------------------
        // Plugin: result carries CARequestID and nothing downstream throws on the missing status
        // ---------------------------------------------------------------------------

        private static EnrollmentProductInfo ProductInfo(string priorSerial = null)
        {
            var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["ProfileId"] = "842" };
            if (priorSerial != null)
            {
                parameters["PriorCertSN"] = priorSerial;
                parameters["RenewalWindowDays"] = "90";
            }
            return new EnrollmentProductInfo { ProductID = "842", ProductParameters = parameters };
        }

        [Theory]
        [InlineData("http500")]
        [InlineData("ems913")]
        public async Task Plugin_Enroll_New_TrackOrderFailsAfterPlacement_ReturnsPendingWithCARequestID(string scenario)
        {
            StubPlacement(NewOrder);
            StubTrackOrderFailure(NewOrder, scenario);
            var plugin = new CERTInextCAPlugin(BuildClient(), Config());

            var result = await plugin.Enroll(
                MockCertificateData.FakeCsrPem, "CN=test.example.com",
                new Dictionary<string, string[]> { ["dns"] = new[] { "test.example.com" } },
                ProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            result.CARequestID.Should().Be(NewOrder);
            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            result.Certificate.Should().BeNull();
            CallsTo("/GenerateOrderSSL").Should().Be(1);
        }

        [Theory]
        [InlineData("http500")]
        [InlineData("ems913")]
        public async Task Plugin_Enroll_RenewalApi_TrackOrderFailsAfterPlacement_ReturnsPendingWithCARequestID(string scenario)
        {
            StubTrackOrderOk(PriorOrder, MockCertificateData.TrackOrderIssuedJson(PriorOrder));
            StubPlacement(NewOrder);
            StubTrackOrderFailure(NewOrder, scenario);

            var reader = new Mock<ICertificateDataReader>();
            reader.Setup(r => r.GetRequestIDBySerialNumber(It.IsAny<string>())).ReturnsAsync(PriorOrder);
            reader.Setup(r => r.GetExpirationDateByRequestId(PriorOrder)).Returns(DateTime.UtcNow.AddDays(30));
            var plugin = new CERTInextCAPlugin(BuildClient(), reader.Object, Config());

            var result = await plugin.Enroll(
                MockCertificateData.FakeCsrPem, "CN=test.example.com",
                new Dictionary<string, string[]> { ["dns"] = new[] { "test.example.com" } },
                ProductInfo("AABB"), RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

            // Guard: the renewal API path (not the new-enroll fallback) produced the order.
            reader.Verify(r => r.GetExpirationDateByRequestId(PriorOrder), Times.Once);
            result.CARequestID.Should().Be(NewOrder);
            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            result.Certificate.Should().BeNull();
            CallsTo("/GenerateOrderSSL").Should().Be(1);
        }

        // ---------------------------------------------------------------------------
        // A real cancellation may still propagate
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_RealCancellationAfterPlacement_StillPropagates()
        {
            using var cts = new CancellationTokenSource();
            // Cancel the caller's token as the placement response is produced, so the follow-up
            // TrackOrder runs with a genuinely cancelled token.
            _server.Given(Request.Create().WithPath("/GenerateOrderSSL").UsingPost())
                .RespondWith(Response.Create().WithCallback(_ =>
                {
                    cts.Cancel();
                    return new ResponseMessage
                    {
                        StatusCode = 200,
                        BodyData = new BodyData
                        {
                            DetectedBodyType = BodyType.String,
                            BodyAsString = MockCertificateData.GenerateOrderSuccessJson(NewOrder)
                        }
                    };
                }));
            StubTrackOrderOk(NewOrder, MockCertificateData.TrackOrderPendingJson(NewOrder));

            Func<Task> act = () => BuildClient().EnrollCertificateAsync(EnrollReq(), cts.Token);

            await act.Should().ThrowAsync<OperationCanceledException>();
        }
    }
}
