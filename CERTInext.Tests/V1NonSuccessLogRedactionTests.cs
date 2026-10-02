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
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Microsoft.Extensions.Logging;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Issue 0073 (port of 0044): an unrecognised V1 non-2xx error body is logged so it can be
    /// diagnosed, but only after <c>ApplyLoggingRedaction</c>: the authKey is always scrubbed and
    /// personal data is scrubbed unless <c>LogSensitiveRequestData</c> is on. Drives the real
    /// <c>DeserializeOrThrow</c> call site through WireMock and captures what the client logged via
    /// <c>CERTInextClient.OverrideLoggerForTests</c>. All data is synthetic.
    /// </summary>
    [Collection("CERTInextClientLogger-NoParallel")]
    public class V1NonSuccessLogRedactionTests : IDisposable
    {
        private const string AuthKey = "SYNTHETIC-AUTHKEY-0073";
        private const string Email = "jane.doe@example.com";
        private const string Name = "Jane Doe";

        private readonly WireMockServer _server;

        public V1NonSuccessLogRedactionTests()
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

        // Unrecognised shape (no meta.errorMessage/errorCode, no top-level message) that nevertheless
        // echoes a credential and personal data, which is the case redaction must cover.
        private static string BuildBody(string marker) =>
            "{\"timestamp\":\"2026-10-02T00:00:00.000+00:00\",\"status\":502,\"error\":\"Bad Gateway\"," +
            $"\"trace\":\"{marker}\",\"meta\":{{\"authKey\":\"{AuthKey}\"}}," +
            $"\"requestorEmail\":\"{Email}\",\"requestorName\":\"{Name}\"}}";

        private async Task<(Exception Error, List<(LogLevel Level, string Message)> Lines)> RunAsync(
            bool logSensitiveRequestData, int status, string body, string marker)
        {
            _server.Reset();
            _server.Given(Request.Create().WithPath("/GetProductDetails").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(status)
                    .WithHeader("Content-Type", "application/json").WithBody(body));

            var client = BuildClient(logSensitiveRequestData);
            var logger = new CapturingLogger();
            Exception error = null;
            using (CERTInextClient.OverrideLoggerForTests(logger))
            {
                try { await client.GetProductDetailsAsync(); }
                catch (Exception ex) { error = ex; }
            }

            // The client logger is process-wide; scope to lines carrying this call's marker.
            var lines = logger.Entries.Where(e => e.Message != null && e.Message.Contains(marker)).ToList();
            return (error, lines);
        }

        [Fact]
        public async Task UnrecognisedErrorBody_FlagOff_LogsBodyWithAuthKeyAndPiiRedacted()
        {
            string marker = "m-" + Guid.NewGuid().ToString("N");
            var (error, lines) = await RunAsync(false, 502, BuildBody(marker), marker);

            error.Should().NotBeNull();
            error.Message.Should().Contain("unrecognised error body (HTTP 502)");

            var failure = lines.Where(l => l.Message.StartsWith("CERTInext API non-success")).ToList();
            failure.Should().ContainSingle("the unrecognised body must be logged exactly once");
            failure[0].Level.Should().Be(LogLevel.Error);
            string msg = failure[0].Message;
            msg.Should().Contain("HttpStatus=502").And.Contain("Bad Gateway", "the diagnosable part of the body is kept");
            msg.Should().Contain("\"authKey\":\"***REDACTED***\"");
            msg.Should().NotContain(AuthKey).And.NotContain(Email).And.NotContain(Name);

            lines.Should().NotContain(l => l.Message.Contains(AuthKey) || l.Message.Contains(Email) || l.Message.Contains(Name));
        }

        [Fact]
        public async Task UnrecognisedErrorBody_FlagOn_KeepsPiiButStillRedactsAuthKey()
        {
            string marker = "m-" + Guid.NewGuid().ToString("N");
            var (_, lines) = await RunAsync(true, 502, BuildBody(marker), marker);

            var failure = lines.Where(l => l.Message.StartsWith("CERTInext API non-success")).ToList();
            failure.Should().ContainSingle();
            string msg = failure[0].Message;
            msg.Should().Contain(Email).And.Contain(Name);
            msg.Should().Contain("\"authKey\":\"***REDACTED***\"").And.NotContain(AuthKey);
            lines.Should().NotContain(l => l.Message.Contains(AuthKey));
        }

        [Fact]
        public async Task NonJsonErrorBody_FormEncodedAuthKey_IsRedactedInLog()
        {
            string marker = "m-" + Guid.NewGuid().ToString("N");
            string body = $"<html><body>Bad Gateway {marker} authKey={AuthKey}</body></html>";
            var (error, lines) = await RunAsync(false, 502, body, marker);

            error.Message.Should().Contain("unrecognised error body (HTTP 502)");
            var failure = lines.Where(l => l.Message.StartsWith("CERTInext API non-success")).ToList();
            failure.Should().ContainSingle();
            failure[0].Message.Should().Contain("Bad Gateway").And.Contain("authKey=***REDACTED***").And.NotContain(AuthKey);
        }

        [Fact]
        public async Task UnrecognisedErrorBody_ExceptionMessageDoesNotEmbedBody()
        {
            string marker = "m-" + Guid.NewGuid().ToString("N");
            var (error, _) = await RunAsync(false, 502, BuildBody(marker), marker);

            error.Message.Should().NotContain(AuthKey).And.NotContain(Email).And.NotContain(marker,
                "the raw body goes to the (redacted) log only, never into the exception surfaced to Command");
        }
    }
}
