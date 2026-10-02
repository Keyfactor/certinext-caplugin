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
    /// A resolved SignerIp that is not an IP literal (for example a host name) is sent unchanged as
    /// <c>agreementDetails.signerIP</c> but logs a Warning naming the source (template or connector).
    /// Enroll and renewal share <c>BuildSslOrderDetails</c> -> <c>BuildAgreementDetails</c>, so both
    /// paths are covered. All values are synthetic (RFC 5737 / RFC 3849 documentation addresses).
    /// </summary>
    [Collection("CERTInextClientLogger-NoParallel")]
    public class SignerIpWarningTests : IDisposable
    {
        private readonly WireMockServer _server;

        public SignerIpWarningTests()
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
            public ConcurrentQueue<(LogLevel Level, string Message)> Entries { get; } = new();
            public IDisposable BeginScope<TState>(TState state) => null;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
                Func<TState, Exception, string> formatter) => Entries.Enqueue((logLevel, formatter(state, exception)));

            public string[] SignerIpWarnings => Entries
                .Where(e => e.Level == LogLevel.Warning && e.Message.Contains("SignerIp value"))
                .Select(e => e.Message).ToArray();
        }

        private CERTInextClient BuildClient(string connectorSignerIp) => new CERTInextClient(new CERTInextConfig
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
            SignerIp = connectorSignerIp,
            PageSize = 100
        });

        private string CapturedSignerIp()
        {
            var posts = _server.LogEntries.Where(e => e.RequestMessage.Path == "/GenerateOrderSSL").ToList();
            posts.Should().HaveCount(1);
            return JsonDocument.Parse(posts[0].RequestMessage.Body!).RootElement
                .GetProperty("orderDetails").GetProperty("agreementDetails").GetProperty("signerIP").GetString();
        }

        private static EnrollCertificateRequest EnrollReq(string templateSignerIp) => new EnrollCertificateRequest
        {
            ProfileId = "842",
            Csr = MockCertificateData.FakeCsrPem,
            Subject = "CN=test.example.com",
            Comment = "Unit test",
            SignerIp = templateSignerIp
        };

        private static RenewCertificateRequest RenewReq(string templateSignerIp) => new RenewCertificateRequest
        {
            Csr = MockCertificateData.FakeCsrPem,
            ProfileId = "842",
            Comment = "Unit test",
            SignerIp = templateSignerIp
        };

        [Fact]
        public async Task Enroll_InvalidTemplateSignerIp_WarnsNamingTemplate_AndSendsValueUnchanged()
        {
            var logger = new CapturingLogger();
            using (CERTInextClient.OverrideLoggerForTests(logger))
                await BuildClient("203.0.113.10").EnrollCertificateAsync(EnrollReq("gateway-host"));

            var warnings = logger.SignerIpWarnings;
            warnings.Should().ContainSingle();
            warnings[0].Should().Contain("template").And.Contain("gateway-host");
            CapturedSignerIp().Should().Be("gateway-host");
        }

        [Fact]
        public async Task Enroll_InvalidConnectorSignerIp_WarnsNamingConnector_AndSendsValueUnchanged()
        {
            var logger = new CapturingLogger();
            using (CERTInextClient.OverrideLoggerForTests(logger))
                await BuildClient("gateway-host").EnrollCertificateAsync(EnrollReq(null));

            var warnings = logger.SignerIpWarnings;
            warnings.Should().ContainSingle();
            warnings[0].Should().Contain("connector").And.Contain("gateway-host");
            CapturedSignerIp().Should().Be("gateway-host");
        }

        [Fact]
        public async Task Renewal_InvalidTemplateSignerIp_WarnsNamingTemplate_AndSendsValueUnchanged()
        {
            var logger = new CapturingLogger();
            using (CERTInextClient.OverrideLoggerForTests(logger))
                await BuildClient("203.0.113.10").RenewCertificateAsync(MockCertificateData.OrderNumber1, RenewReq("gateway-host"));

            var warnings = logger.SignerIpWarnings;
            warnings.Should().ContainSingle();
            warnings[0].Should().Contain("template").And.Contain("gateway-host");
            CapturedSignerIp().Should().Be("gateway-host");
        }

        [Fact]
        public async Task Enroll_InvalidSignerIpWithControlChars_LogLineHasNoRawCrLf()
        {
            var logger = new CapturingLogger();
            using (CERTInextClient.OverrideLoggerForTests(logger))
                await BuildClient("203.0.113.10").EnrollCertificateAsync(EnrollReq("bad\r\nhost"));

            var warnings = logger.SignerIpWarnings;
            warnings.Should().ContainSingle();
            warnings[0].Should().NotContain("\r").And.NotContain("\n").And.Contain("bad\\r\\nhost");
            CapturedSignerIp().Should().Be("bad\r\nhost");
        }

        [Theory]
        [InlineData("203.0.113.10")]
        [InlineData("2001:db8::1")]
        public async Task Enroll_ValidSignerIp_LogsNoSignerIpWarning(string ip)
        {
            var logger = new CapturingLogger();
            using (CERTInextClient.OverrideLoggerForTests(logger))
                await BuildClient("198.51.100.7").EnrollCertificateAsync(EnrollReq(ip));

            logger.SignerIpWarnings.Should().BeEmpty();
            CapturedSignerIp().Should().Be(ip);
        }

        [Theory]
        [InlineData("203.0.113.10")]
        [InlineData("2001:db8::1")]
        public async Task Enroll_ValidConnectorSignerIp_LogsNoSignerIpWarning(string ip)
        {
            var logger = new CapturingLogger();
            using (CERTInextClient.OverrideLoggerForTests(logger))
                await BuildClient(ip).EnrollCertificateAsync(EnrollReq(null));

            logger.SignerIpWarnings.Should().BeEmpty();
            CapturedSignerIp().Should().Be(ip);
        }

        [Theory]
        [InlineData("203.0.113.10")]
        [InlineData("2001:db8::1")]
        public async Task Renewal_ValidSignerIp_LogsNoSignerIpWarning(string ip)
        {
            var logger = new CapturingLogger();
            using (CERTInextClient.OverrideLoggerForTests(logger))
                await BuildClient("198.51.100.7").RenewCertificateAsync(MockCertificateData.OrderNumber1, RenewReq(ip));

            logger.SignerIpWarnings.Should().BeEmpty();
            CapturedSignerIp().Should().Be(ip);
        }

        [Fact]
        public async Task Enroll_BlankSignerIpEverywhere_FallsBackWithoutInvalidIpWarning()
        {
            var logger = new CapturingLogger();
            using (CERTInextClient.OverrideLoggerForTests(logger))
                await BuildClient("").EnrollCertificateAsync(EnrollReq(null));

            logger.SignerIpWarnings.Should().BeEmpty("the existing missing-SignerIp warning is a different message");
            CapturedSignerIp().Should().Be("127.0.0.1");
        }
    }
}
