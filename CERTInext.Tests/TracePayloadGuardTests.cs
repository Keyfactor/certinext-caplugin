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
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Microsoft.Extensions.Logging;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Finding #6 (perf): the PlaceOrder request dump and TrackOrder response dump are Trace logs
    /// whose argument is <c>ApplyLoggingRedaction(...)</c> (dozens of regex passes plus a JSON parse).
    /// C# evaluates that argument eagerly, and the <c>LogTrace</c> extension does not itself consult
    /// <c>IsEnabled</c> before calling <c>ILogger.Log</c>, so unguarded the cost was paid, and the
    /// payload handed to the logger, on every call even with Trace off. These tests use a logger
    /// that reports Trace disabled yet still records any <c>Log</c> call it receives: the payload
    /// line must never reach it when Trace is off, and must be byte-identical to
    /// <c>ApplyLoggingRedaction</c> output when Trace is on. All data is synthetic.
    /// </summary>
    [Collection("CERTInextClientLogger-NoParallel")]
    public class TracePayloadGuardTests : IDisposable
    {
        private const string RequestorName = "Jane Doe";
        private const string RequestorEmail = "jane.doe@example.com";

        private readonly WireMockServer _server;

        public TracePayloadGuardTests()
        {
            _server = WireMockServer.Start();
        }

        public void Dispose() => _server.Stop();

        private sealed class LevelGatedLogger : ILogger
        {
            private readonly LogLevel _min;
            public LevelGatedLogger(LogLevel min) => _min = min;
            public ConcurrentQueue<(LogLevel Level, string Message)> Entries { get; } = new();
            public IDisposable BeginScope<TState>(TState state) => null;
            public bool IsEnabled(LogLevel logLevel) => logLevel >= _min;
            // Deliberately records without re-checking IsEnabled, as the LogTrace extension would
            // reach it: any payload line seen here means the call site did not guard.
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
                Func<TState, Exception, string> formatter)
                => Entries.Enqueue((logLevel, formatter(state, exception)));
        }

        private CERTInextClient BuildClient(bool logSensitiveRequestData) => new CERTInextClient(new CERTInextConfig
        {
            ApiUrl = _server.Urls[0],
            AuthMode = "AccessKey",
            ApiKey = "synthetic-access-key",
            AccountNumber = "9988776655",
            LogSensitiveRequestData = logSensitiveRequestData
        });

        private static GenerateOrderSslRequest BuildOrder(string primaryDomain) => new GenerateOrderSslRequest
        {
            OrderDetails = new SslOrderDetails
            {
                ProductCode = "842",
                RequestorInformation = new RequestorInformation
                {
                    RequestorName = RequestorName,
                    RequestorMobileNumber = "5551234567",
                    RequestorEmail = RequestorEmail,
                    RequestorDesignation = "IT Administrator"
                },
                CertificateInformation = new CertificateInformation
                {
                    DomainName = primaryDomain,
                    AdditionalDomains = new List<string> { "www." + primaryDomain }
                },
                AgreementDetails = new AgreementDetails { SignerName = "John Signer", SignerPlace = "Austin", SignerIp = "203.0.113.10" }
            }
        };

        private void StubGenerateOrder() =>
            _server.Given(Request.Create().WithPath("/GenerateOrderSSL").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.GenerateOrderSuccessJson("ORD-GUARD-1")));

        private string StubTrackOrder(string orderNumber)
        {
            string body =
                "{\"meta\":{\"status\":\"1\"},\"orderDetails\":{\"orderNumber\":\"" + orderNumber + "\"," +
                "\"orderStatusId\":\"1\",\"certificateStatusId\":\"1\"," +
                "\"requestorInformation\":{\"requestorName\":\"" + RequestorName + "\",\"requestorEmail\":\"" + RequestorEmail + "\"}}}";
            _server.Given(Request.Create().WithPath("/TrackOrder").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json").WithBody(body));
            return body;
        }

        private static async Task<List<(LogLevel Level, string Message)>> CaptureAsync(
            LogLevel minLevel, string marker, Func<Task> act)
        {
            var logger = new LevelGatedLogger(minLevel);
            using (CERTInextClient.OverrideLoggerForTests(logger))
                await act();
            // The client logger is process-wide; scope to lines carrying this call's marker.
            return logger.Entries.Where(e => e.Message != null && e.Message.Contains(marker)).ToList();
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task TrackOrder_TraceDisabled_PayloadLogNotEmitted(bool logSensitiveRequestData)
        {
            string order = "ORD-" + Guid.NewGuid().ToString("N");
            StubTrackOrder(order);
            using var client = BuildClient(logSensitiveRequestData);

            var lines = await CaptureAsync(LogLevel.Debug, order, () => client.TrackOrderAsync(order));

            lines.Should().NotContain(l => l.Message.StartsWith("TrackOrderAsync response payload"),
                "redaction and the payload log must be skipped when Trace is disabled");
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task TrackOrder_TraceEnabled_PayloadMatchesApplyLoggingRedaction(bool logSensitiveRequestData)
        {
            string order = "ORD-" + Guid.NewGuid().ToString("N");
            string body = StubTrackOrder(order);
            using var client = BuildClient(logSensitiveRequestData);

            var lines = await CaptureAsync(LogLevel.Trace, order, () => client.TrackOrderAsync(order));

            var dump = lines.Single(l => l.Message.StartsWith("TrackOrderAsync response payload"));
            dump.Level.Should().Be(LogLevel.Trace);
            dump.Message.Should().Be(
                $"TrackOrderAsync response payload (Order={order}): " +
                CERTInextClient.ApplyLoggingRedaction(body, logSensitiveRequestData));
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task PlaceOrder_TraceDisabled_PayloadLogNotEmitted(bool logSensitiveRequestData)
        {
            string domain = "po-" + Guid.NewGuid().ToString("N") + ".example.com";
            StubGenerateOrder();
            using var client = BuildClient(logSensitiveRequestData);

            var lines = await CaptureAsync(LogLevel.Debug, domain, () => client.PlaceOrderAsync(BuildOrder(domain)));

            lines.Should().Contain(l => l.Message.StartsWith("Submitting order to CERTInext"),
                "precondition: the client logged this call, so the absence below is meaningful");
            lines.Should().NotContain(l => l.Message.StartsWith("PlaceOrderAsync request payload"),
                "redaction and the payload log must be skipped when Trace is disabled");
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task PlaceOrder_TraceEnabled_PayloadMatchesApplyLoggingRedaction(bool logSensitiveRequestData)
        {
            string domain = "po-" + Guid.NewGuid().ToString("N") + ".example.com";
            StubGenerateOrder();
            using var client = BuildClient(logSensitiveRequestData);

            var lines = await CaptureAsync(LogLevel.Trace, domain, () => client.PlaceOrderAsync(BuildOrder(domain)));

            var dump = lines.Single(l => l.Message.StartsWith("PlaceOrderAsync request payload"));
            dump.Level.Should().Be(LogLevel.Trace);
            string sentBody = _server.LogEntries.Last(e => e.RequestMessage.Path == "/GenerateOrderSSL").RequestMessage.Body;
            dump.Message.Should().Be(
                "PlaceOrderAsync request payload: " +
                CERTInextClient.ApplyLoggingRedaction(sentBody, logSensitiveRequestData));
        }
    }
}
