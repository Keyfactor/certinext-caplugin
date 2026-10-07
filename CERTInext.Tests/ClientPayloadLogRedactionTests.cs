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
    /// Issue 0040 regression coverage at the real log call sites in <see cref="CERTInextClient"/>:
    /// the <c>PlaceOrderAsync</c> Trace request dump (which used to write the replayable
    /// <c>meta.authKey</c> digest and requestor PII verbatim), the <c>TrackOrderAsync</c> Trace
    /// response dump, and the <c>LogApiFailure</c> response-body logger. Each test drives the client
    /// against WireMock and captures what the client actually logged through
    /// <c>CERTInextClient.OverrideLoggerForTests</c>.
    ///
    /// The client logger is process-wide, so other test classes running in parallel may log into
    /// the capture while it is installed; every assertion is scoped to lines carrying this call's
    /// unique marker. All data is synthetic.
    /// </summary>
    [Collection(LoggingStateCollection.Name)]
    public class ClientPayloadLogRedactionTests : IDisposable
    {
        private const string RequestorName = "Jane Doe";
        private const string RequestorEmail = "jane.doe@example.com";
        private const string MaskedRequestorEmail = "j***@example.com";
        private const string RequestorMobile = "5551234567";
        private const string PocEmail = "tech.contact@example.com";
        private const string MaskedPocEmail = "t***@example.com";
        private const string PocFirstName = "Terry";
        private const string PocLastName = "Techcontact";
        private const string PocMobile = "5559876543";
        private const string SignerName = "John Signer";
        private const string EmailSan = "alice@example.com";
        private const string MaskedEmailSan = "a***@example.com";

        private readonly WireMockServer _server;

        public ClientPayloadLogRedactionTests()
        {
            _server = WireMockServer.Start();
        }

        public void Dispose() => _server.Stop();

        private sealed class CapturingLogger : ILogger
        {
            public ConcurrentQueue<(LogLevel Level, string Message)> Entries { get; } = new();
            public IDisposable BeginScope<TState>(TState state) => null;
            public bool IsEnabled(LogLevel logLevel) => true;
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
            // Meta left null so PlaceOrderAsync computes a real authKey via BuildMetaAsync.
            OrderDetails = new SslOrderDetails
            {
                ProductCode = "842",
                RequestorInformation = new RequestorInformation
                {
                    RequestorName = RequestorName,
                    RequestorMobileNumber = RequestorMobile,
                    RequestorEmail = RequestorEmail,
                    RequestorDesignation = "IT Administrator"
                },
                CertificateInformation = new CertificateInformation
                {
                    DomainName = primaryDomain,
                    AdditionalDomains = new List<string> { "www." + primaryDomain, EmailSan }
                },
                AgreementDetails = new AgreementDetails { SignerName = SignerName, SignerPlace = "Austin", SignerIp = "203.0.113.10" },
                TechnicalPointOfContact = new TechnicalPointOfContact
                {
                    PocFirstName = PocFirstName, PocLastName = PocLastName, PocEmail = PocEmail,
                    PocIsdCode = "44", PocMobileNumber = PocMobile
                }
            }
        };

        private void StubGenerateOrder(string body) =>
            _server.Given(Request.Create().WithPath("/GenerateOrderSSL").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json").WithBody(body));

        /// <summary>Returns the meta.authKey the client actually sent on the wire.</summary>
        private string SentAuthKey()
        {
            var entry = _server.LogEntries.Last(e => e.RequestMessage.Path == "/GenerateOrderSSL");
            using var doc = JsonDocument.Parse(entry.RequestMessage.Body ?? "{}");
            string authKey = doc.RootElement.GetProperty("meta").GetProperty("authKey").GetString();
            authKey.Should().NotBeNullOrEmpty("precondition: AccessKey mode sends a computed authKey");
            return authKey;
        }

        private static async Task<List<(LogLevel Level, string Message)>> CaptureAsync(string marker, Func<Task> act)
        {
            var logger = new CapturingLogger();
            using (CERTInextClient.OverrideLoggerForTests(logger))
            {
                try { await act(); }
                catch (Exception) { /* failure-path tests expect a throw; assertions are on the logs */ }
            }
            return logger.Entries.Where(e => e.Message != null && e.Message.Contains(marker)).ToList();
        }

        // ---------------------------------------------------------------------------
        // PlaceOrderAsync Trace request dump
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task PlaceOrder_TracePayload_FlagOff_OmitsAuthKeyAndPii()
        {
            string domain = "po-" + Guid.NewGuid().ToString("N") + ".example.com";
            StubGenerateOrder(MockCertificateData.GenerateOrderSuccessJson("ORD-REDACT-1"));
            using var client = BuildClient(logSensitiveRequestData: false);

            var lines = await CaptureAsync(domain, () => client.PlaceOrderAsync(BuildOrder(domain)));
            string authKey = SentAuthKey();

            var dump = lines.Where(l => l.Message.StartsWith("PlaceOrderAsync request payload")).ToList();
            dump.Should().ContainSingle();
            dump[0].Level.Should().Be(LogLevel.Trace);
            string payload = dump[0].Message;

            payload.Should().NotContain(authKey, "the replayable authKey digest must never be logged");
            payload.Should().Contain("\"authKey\":\"***REDACTED***\"");
            payload.Should().NotContain(RequestorName).And.NotContain(RequestorEmail).And.NotContain(RequestorMobile)
                .And.NotContain(PocEmail).And.NotContain(SignerName).And.NotContain(EmailSan)
                .And.NotContain(PocFirstName).And.NotContain(PocLastName).And.NotContain(PocMobile)
                .And.NotContain("\"pocIsdCode\":\"44\"");
            payload.Should().Contain(MaskedPocEmail).And.Contain("\"pocFirstName\":\"***REDACTED***\"")
                .And.Contain("\"pocLastName\":\"***REDACTED***\"").And.Contain("\"pocIsdCode\":\"***REDACTED***\"")
                .And.Contain("\"pocMobileNumber\":\"***REDACTED***\"");
            payload.Should().Contain(MaskedRequestorEmail).And.Contain(MaskedEmailSan).And.Contain("www." + domain);

            lines.Should().NotContain(l => l.Message.Contains(authKey) || l.Message.Contains(EmailSan) || l.Message.Contains(RequestorEmail),
                "no client log line for this order may carry the authKey or unmasked email with the flag off");
        }

        [Fact]
        public async Task PlaceOrder_TracePayload_FlagOn_IncludesPiiButStillRedactsAuthKey()
        {
            string domain = "po-" + Guid.NewGuid().ToString("N") + ".example.com";
            StubGenerateOrder(MockCertificateData.GenerateOrderSuccessJson("ORD-REDACT-2"));
            using var client = BuildClient(logSensitiveRequestData: true);

            var lines = await CaptureAsync(domain, () => client.PlaceOrderAsync(BuildOrder(domain)));
            string authKey = SentAuthKey();

            string payload = lines.Single(l => l.Message.StartsWith("PlaceOrderAsync request payload")).Message;

            payload.Should().NotContain(authKey, "credentials are redacted regardless of LogSensitiveRequestData");
            payload.Should().Contain("\"authKey\":\"***REDACTED***\"");
            payload.Should().Contain(RequestorName).And.Contain(RequestorEmail).And.Contain(RequestorMobile)
                .And.Contain(PocEmail).And.Contain(SignerName).And.Contain(EmailSan)
                .And.Contain(PocFirstName).And.Contain(PocLastName).And.Contain(PocMobile)
                .And.Contain("\"pocIsdCode\":\"44\"");

            lines.Should().NotContain(l => l.Message.Contains(authKey));
        }

        [Fact]
        public async Task PlaceOrder_SubmittingOrderLine_MasksEmailSanUnlessFlagOn()
        {
            string domain = "po-" + Guid.NewGuid().ToString("N") + ".example.com";
            StubGenerateOrder(MockCertificateData.GenerateOrderSuccessJson("ORD-REDACT-3"));

            using (var off = BuildClient(logSensitiveRequestData: false))
            {
                var lines = await CaptureAsync(domain, () => off.PlaceOrderAsync(BuildOrder(domain)));
                lines.Single(l => l.Message.StartsWith("Submitting order to CERTInext")).Message
                    .Should().Contain(MaskedEmailSan).And.NotContain(EmailSan);
            }

            using (var on = BuildClient(logSensitiveRequestData: true))
            {
                var lines = await CaptureAsync(domain, () => on.PlaceOrderAsync(BuildOrder(domain)));
                lines.Single(l => l.Message.StartsWith("Submitting order to CERTInext")).Message
                    .Should().Contain(EmailSan);
            }
        }

        // ---------------------------------------------------------------------------
        // LogApiFailure — CA error body echoing request fields
        // ---------------------------------------------------------------------------

        private static string FailureBodyEchoingRequest(string domain) =>
            "{\"meta\":{\"status\":\"0\",\"errorCode\":\"EMS-100\",\"errorMessage\":\"Validation failed\"," +
            "\"authKey\":\"0f1e2d3c4b5a6978synthetic\"}," +
            "\"orderDetails\":{\"requestorInformation\":{\"requestorName\":\"" + RequestorName + "\",\"requestorEmail\":\"" + RequestorEmail + "\"}," +
            "\"certificateInformation\":{\"domainName\":\"" + domain + "\",\"additionalDomains\":[\"" + EmailSan + "\"]}}}";

        [Fact]
        public async Task PlaceOrder_ApiFailureBody_FlagOff_RedactsCredentialsAndPii()
        {
            string domain = "fail-" + Guid.NewGuid().ToString("N") + ".example.com";
            StubGenerateOrder(FailureBodyEchoingRequest(domain));
            using var client = BuildClient(logSensitiveRequestData: false);

            var lines = await CaptureAsync(domain, () => client.PlaceOrderAsync(BuildOrder(domain)));

            string failure = lines.Single(l => l.Message.StartsWith("CERTInext API non-success")).Message;
            failure.Should().NotContain("0f1e2d3c4b5a6978synthetic")
                .And.NotContain(RequestorName).And.NotContain(RequestorEmail).And.NotContain(EmailSan);
            failure.Should().Contain(MaskedRequestorEmail).And.Contain(MaskedEmailSan).And.Contain("EMS-100");
        }

        [Fact]
        public async Task PlaceOrder_ApiFailureBody_FlagOn_KeepsPiiButRedactsCredentials()
        {
            string domain = "fail-" + Guid.NewGuid().ToString("N") + ".example.com";
            StubGenerateOrder(FailureBodyEchoingRequest(domain));
            using var client = BuildClient(logSensitiveRequestData: true);

            var lines = await CaptureAsync(domain, () => client.PlaceOrderAsync(BuildOrder(domain)));

            string failure = lines.Single(l => l.Message.StartsWith("CERTInext API non-success")).Message;
            failure.Should().NotContain("0f1e2d3c4b5a6978synthetic");
            failure.Should().Contain(RequestorName).And.Contain(RequestorEmail).And.Contain(EmailSan);
        }

        // ---------------------------------------------------------------------------
        // TrackOrderAsync Trace response dump
        // ---------------------------------------------------------------------------

        private void StubTrackOrder(string orderNumber) =>
            _server.Given(Request.Create().WithPath("/TrackOrder").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(
                        "{\"meta\":{\"status\":\"1\"},\"orderDetails\":{\"orderNumber\":\"" + orderNumber + "\"," +
                        "\"orderStatusId\":\"1\",\"certificateStatusId\":\"1\"," +
                        "\"requestorInformation\":{\"requestorName\":\"" + RequestorName + "\",\"requestorEmail\":\"" + RequestorEmail + "\"}," +
                        "\"domainVerification\":{\"example.com\":{\"dcvStatus\":\"1\"},\"" + EmailSan + "\":{\"dcvStatus\":\"0\"},\"status\":\"0\"}}}"));

        [Fact]
        public async Task TrackOrder_TracePayload_FlagOff_OmitsPii()
        {
            string order = "ORD-" + Guid.NewGuid().ToString("N");
            StubTrackOrder(order);
            using var client = BuildClient(logSensitiveRequestData: false);

            var lines = await CaptureAsync(order, () => client.TrackOrderAsync(order));

            var dump = lines.Where(l => l.Message.StartsWith("TrackOrderAsync response payload")).ToList();
            dump.Should().ContainSingle();
            dump[0].Level.Should().Be(LogLevel.Trace);
            dump[0].Message.Should().NotContain(RequestorName).And.NotContain(RequestorEmail).And.NotContain(EmailSan);
            dump[0].Message.Should().Contain(MaskedRequestorEmail).And.Contain(MaskedEmailSan);
        }

        [Fact]
        public async Task TrackOrder_TracePayload_FlagOn_IncludesPii()
        {
            string order = "ORD-" + Guid.NewGuid().ToString("N");
            StubTrackOrder(order);
            using var client = BuildClient(logSensitiveRequestData: true);

            var lines = await CaptureAsync(order, () => client.TrackOrderAsync(order));

            lines.Single(l => l.Message.StartsWith("TrackOrderAsync response payload")).Message
                .Should().Contain(RequestorName).And.Contain(RequestorEmail).And.Contain(EmailSan);
        }
    }
}
