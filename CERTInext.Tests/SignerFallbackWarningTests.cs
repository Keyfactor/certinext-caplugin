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
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Microsoft.Extensions.Logging;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// SOC1 accuracy-of-processing: when SignerName / SignerPlace fall back to the built-in
    /// placeholders ("Keyfactor Gateway" / "Gateway") the client must log a Warning naming what to
    /// configure, without changing the values sent in <c>agreementDetails</c>.
    /// </summary>
    [Collection(LoggingStateCollection.Name)]
    public class SignerFallbackWarningTests : IDisposable
    {
        private readonly WireMockServer _server;

        public SignerFallbackWarningTests()
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
                Func<TState, Exception, string> formatter)
                => Entries.Enqueue((logLevel, formatter(state, exception)));

            public List<string> Warnings(string contains) => Entries
                .Where(e => e.Level == LogLevel.Warning && e.Message.Contains(contains, StringComparison.Ordinal))
                .Select(e => e.Message).ToList();
        }

        private CERTInextClient BuildClient(string requestorName, string signerPlace) => new CERTInextClient(new CERTInextConfig
        {
            ApiUrl                = _server.Urls[0],
            AuthMode              = "AccessKey",
            ApiKey                = "test-key",
            AccountNumber         = "12345",
            RequestorName         = requestorName,
            RequestorEmail        = "requestor@example.com",
            RequestorIsdCode      = "1",
            RequestorMobileNumber = "5550000000",
            SignerPlace           = signerPlace,
            SignerIp              = "203.0.113.10",
            PageSize              = 100
        });

        private async Task<(CapturingLogger Logger, JsonElement Agreement)> EnrollAsync(
            CERTInextClient client, Dictionary<string, string> templateParams = null)
        {
            var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["ProfileId"] = "842" };
            if (templateParams != null)
                foreach (var kv in templateParams) parameters[kv.Key] = kv.Value;

            var plugin = new CERTInextCAPlugin(client, new CERTInextConfig { PickupRetries = 0 });
            var logger = new CapturingLogger();
            using (CERTInextClient.OverrideLoggerForTests(logger))
            {
                await plugin.Enroll(
                    MockCertificateData.FakeCsrPem, "CN=test.example.com",
                    new Dictionary<string, string[]> { ["dns"] = new[] { "test.example.com" } },
                    new EnrollmentProductInfo { ProductID = "842", ProductParameters = parameters },
                    RequestFormat.PKCS10, EnrollmentType.New);
            }

            var post = _server.LogEntries.Single(e => e.RequestMessage.Path == "/GenerateOrderSSL");
            var agreement = JsonDocument.Parse(post.RequestMessage.Body!).RootElement
                .GetProperty("orderDetails").GetProperty("agreementDetails").Clone();
            return (logger, agreement);
        }

        [Fact]
        public async Task SignerName_Unset_WarnsAndSendsPlaceholder()
        {
            var (logger, agreement) = await EnrollAsync(BuildClient(requestorName: "", signerPlace: "Austin"));

            var warnings = logger.Warnings("SignerName");
            warnings.Should().ContainSingle();
            warnings[0].Should().Contain("RequestorName").And.Contain("template");
            logger.Warnings("SignerPlace").Should().BeEmpty();
            agreement.GetProperty("signerName").GetString().Should().Be("Keyfactor Gateway");
            agreement.GetProperty("signerPlace").GetString().Should().Be("Austin");
        }

        [Fact]
        public async Task SignerPlace_Unset_WarnsAndSendsPlaceholder()
        {
            var (logger, agreement) = await EnrollAsync(BuildClient(requestorName: "Jane Doe", signerPlace: ""));

            var warnings = logger.Warnings("SignerPlace");
            warnings.Should().ContainSingle();
            warnings[0].Should().Contain("template").And.Contain("connector");
            logger.Warnings("SignerName").Should().BeEmpty();
            agreement.GetProperty("signerName").GetString().Should().Be("Jane Doe");
            agreement.GetProperty("signerPlace").GetString().Should().Be("Gateway");
        }

        [Fact]
        public async Task SignerFields_SetOnConnector_NoWarning_ValuesUnchanged()
        {
            var (logger, agreement) = await EnrollAsync(BuildClient(requestorName: "Jane Doe", signerPlace: "Austin"));

            logger.Warnings("SignerName").Should().BeEmpty();
            logger.Warnings("SignerPlace").Should().BeEmpty();
            agreement.GetProperty("signerName").GetString().Should().Be("Jane Doe");
            agreement.GetProperty("signerPlace").GetString().Should().Be("Austin");
        }

        [Fact]
        public async Task SignerFields_SetOnTemplate_NoWarning_TemplateWins()
        {
            var (logger, agreement) = await EnrollAsync(
                BuildClient(requestorName: "", signerPlace: ""),
                new Dictionary<string, string> { ["SignerName"] = "Template Signer", ["SignerPlace"] = "Denver" });

            logger.Warnings("SignerName").Should().BeEmpty();
            logger.Warnings("SignerPlace").Should().BeEmpty();
            agreement.GetProperty("signerName").GetString().Should().Be("Template Signer");
            agreement.GetProperty("signerPlace").GetString().Should().Be("Denver");
        }

        [Fact]
        public async Task SignerFields_BothUnset_WarnsForEach_AndSendsBothPlaceholders()
        {
            var (logger, agreement) = await EnrollAsync(BuildClient(requestorName: null, signerPlace: null));

            logger.Warnings("SignerName").Should().ContainSingle();
            logger.Warnings("SignerPlace").Should().ContainSingle();
            agreement.GetProperty("signerName").GetString().Should().Be("Keyfactor Gateway");
            agreement.GetProperty("signerPlace").GetString().Should().Be("Gateway");
        }
    }
}
