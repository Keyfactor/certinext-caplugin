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
using Keyfactor.Extensions.CAPlugin.CERTInext.Models;
using Microsoft.Extensions.Logging;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// CA-supplied error text (<c>meta.errorMessage</c> / legacy <c>message</c>) may echo a request
    /// value such as an email. With <c>LogSensitiveRequestData</c> off, email-shaped tokens are masked
    /// (via <c>MaskEmail</c>) and CR/LF stripped in both the log line and the exception message that
    /// Command stores; the rest of the text is preserved. With the flag on the text is verbatim.
    /// All data is synthetic.
    /// </summary>
    [Collection(LoggingStateCollection.Name)]
    public class CaErrorTextMaskingTests : IDisposable
    {
        private const string Email = "jane.doe@example.com";
        private const string MaskedEmail = "j***@example.com";

        private readonly WireMockServer _server = WireMockServer.Start();

        public void Dispose() => _server.Stop();

        // ---------------------------------------------------------------------------
        // LogSanitizer.SanitizeCaText
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData("Invalid requestorEmail jane.doe@example.com for order", "Invalid requestorEmail j***@example.com for order")]
        [InlineData("Email 'jane.doe@example.com'.", "Email 'j***@example.com'.")]
        [InlineData("Sent to jane.doe@example.com.", "Sent to j***@example.com.")]
        [InlineData("a@b.example.org and c+tag@sub.example.co.uk differ", "a***@b.example.org and c***@sub.example.co.uk differ")]
        [InlineData("EMS-956 Invalid Request for this API.", "EMS-956 Invalid Request for this API.")]
        [InlineData("Inactive Account User.", "Inactive Account User.")]
        [InlineData("no at-sign, handle@ only, @example.com alone", "no at-sign, handle@ only, @example.com alone")]
        public void SanitizeCaText_FlagOff_MasksOnlyEmailTokens(string input, string expected)
        {
            LogSanitizer.SanitizeCaText(input, false).Should().Be(expected);
        }

        [Fact]
        public void SanitizeCaText_FlagOff_StripsCrLfAndTab()
        {
            LogSanitizer.SanitizeCaText("first\r\nsecond\tthird", false)
                .Should().Be("first\\r\\nsecond\\tthird");
        }

        [Fact]
        public void SanitizeCaText_FlagOn_IsVerbatim()
        {
            string text = "Bad " + Email + "\r\nline two";
            LogSanitizer.SanitizeCaText(text, true).Should().Be(text);
        }

        [Fact]
        public void SanitizeCaText_NullAndEmpty_PassThrough()
        {
            LogSanitizer.SanitizeCaText(null, false).Should().BeNull();
            LogSanitizer.SanitizeCaText(string.Empty, false).Should().BeEmpty();
        }

        [Fact]
        public void SanitizeCaText_IsIdempotent()
        {
            string once = LogSanitizer.SanitizeCaText("Bad " + Email, false);
            LogSanitizer.SanitizeCaText(once, false).Should().Be(once);
        }

        [Fact]
        public void SanitizeCaText_LargeInputWithoutAtSign_CompletesQuickly()
        {
            string big = new string('a', 64 * 1024);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            LogSanitizer.SanitizeCaText(big, false).Should().Be(big);
            sw.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(1));
        }

        // ---------------------------------------------------------------------------
        // ExtractErrorMessage
        // ---------------------------------------------------------------------------

        [Fact]
        public void ExtractErrorMessage_MetaBody_FlagOff_MasksEmailKeepsCodeAndStatus()
        {
            string body = "{\"meta\":{\"status\":\"0\",\"errorCode\":\"EMS-100\",\"errorMessage\":\"Invalid requestorEmail " + Email + " (field requestorEmail)\"}}";

            CERTInextClient.ExtractErrorMessage(body, "op", 400)
                .Should().Be($"CERTInext error during 'op' (HTTP 400): Invalid requestorEmail {MaskedEmail} (field requestorEmail) [EMS-100]");
        }

        [Fact]
        public void ExtractErrorMessage_MetaBody_FlagOn_IsVerbatim()
        {
            string body = "{\"meta\":{\"status\":\"0\",\"errorCode\":\"EMS-100\",\"errorMessage\":\"Invalid requestorEmail " + Email + "\"}}";

            CERTInextClient.ExtractErrorMessage(body, "op", 400, logSensitiveRequestData: true)
                .Should().Be($"CERTInext error during 'op' (HTTP 400): Invalid requestorEmail {Email} [EMS-100]");
        }

        [Fact]
        public void ExtractErrorMessage_MetaBody_FlagOff_StripsCrLf()
        {
            // JSON \r\n escapes decode to real CR/LF characters.
            string body = "{\"meta\":{\"errorCode\":\"EMS-100\",\"errorMessage\":\"line one\\r\\nforged line\"}}";

            string msg = CERTInextClient.ExtractErrorMessage(body, "op");

            msg.Should().NotContain("\r").And.NotContain("\n");
            msg.Should().Contain("line one\\r\\nforged line");
        }

        [Fact]
        public void ExtractErrorMessage_LegacyBody_FlagOffMasksFlagOnVerbatim()
        {
            string body = "{\"message\":\"Unknown user " + Email + "\"}";

            CERTInextClient.ExtractErrorMessage(body, "op", 503)
                .Should().Be($"CERTInext error during 'op' (HTTP 503): Unknown user {MaskedEmail}");
            CERTInextClient.ExtractErrorMessage(body, "op", 503, logSensitiveRequestData: true)
                .Should().Be($"CERTInext error during 'op' (HTTP 503): Unknown user {Email}");
        }

        [Fact]
        public void ExtractErrorMessage_OmittedFlag_FailsClosed()
        {
            string body = "{\"message\":\"Unknown user " + Email + "\"}";

            CERTInextClient.ExtractErrorMessage(body, "op").Should().NotContain(Email);
        }

        // ---------------------------------------------------------------------------
        // End to end through the client: log line and exception message
        // ---------------------------------------------------------------------------

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

        private async Task<(Exception Error, List<string> Lines)> RunAsync(
            bool logSensitiveRequestData, string path, int status, string body, string marker,
            Func<CERTInextClient, Task> call)
        {
            _server.Reset();
            _server.Given(Request.Create().WithPath("/" + path).UsingPost())
                .RespondWith(Response.Create().WithStatusCode(status)
                    .WithHeader("Content-Type", "application/json").WithBody(body));

            var client = BuildClient(logSensitiveRequestData);
            var logger = new CapturingLogger();
            Exception error = null;
            using (CERTInextClient.OverrideLoggerForTests(logger))
            {
                try { await call(client); }
                catch (Exception ex) { error = ex; }
            }

            // The client logger is process-wide; scope to lines carrying this call's marker.
            var lines = logger.Entries.Select(e => e.Message)
                .Where(m => m != null && m.Contains(marker)).ToList();
            return (error, lines);
        }

        private static string MetaFailureBody(string marker, string errorCode = "EMS-100") =>
            "{\"meta\":{\"status\":\"0\",\"errorCode\":\"" + errorCode + "\",\"errorMessage\":\"" + marker +
            " Invalid requestorEmail " + Email + " for field requestorEmail\\r\\nforged\"}}";

        // The ErrorMessage= field of the "CERTInext API non-success" line (the ResponseBody= field
        // that follows is redacted separately by ApplyLoggingRedaction).
        private static string ErrorMessageField(IEnumerable<string> lines)
        {
            string failure = lines.Single(l => l.StartsWith("CERTInext API non-success"));
            int start = failure.IndexOf("ErrorMessage=", StringComparison.Ordinal);
            int end = failure.IndexOf(", ResponseBody=", StringComparison.Ordinal);
            return failure.Substring(start, end - start);
        }

        [Fact]
        public async Task TrackOrder_MetaFailure_FlagOff_MasksEmailInLogAndException()
        {
            string marker = "m-" + Guid.NewGuid().ToString("N");
            var (error, lines) = await RunAsync(false, "TrackOrder", 200, MetaFailureBody(marker), marker,
                c => c.TrackOrderAsync("ORD-1"));

            error.Should().NotBeNull();
            error.Message.Should().Contain("Invalid requestorEmail " + MaskedEmail + " for field requestorEmail")
                .And.NotContain(Email).And.NotContain("\r").And.NotContain("\n");

            string errField = ErrorMessageField(lines);
            errField.Should().Contain("Invalid requestorEmail " + MaskedEmail + " for field requestorEmail")
                .And.NotContain(Email).And.NotContain("\r").And.NotContain("\n").And.Contain("\\r\\nforged");
            lines.Single(l => l.StartsWith("CERTInext API non-success")).Should().Contain("ErrorCode=EMS-100");
        }

        [Fact]
        public async Task TrackOrder_MetaFailure_FlagOn_IsVerbatimInLogAndException()
        {
            string marker = "m-" + Guid.NewGuid().ToString("N");
            var (error, lines) = await RunAsync(true, "TrackOrder", 200, MetaFailureBody(marker), marker,
                c => c.TrackOrderAsync("ORD-1"));

            error.Message.Should().Contain("Invalid requestorEmail " + Email + " for field requestorEmail");
            ErrorMessageField(lines).Should().Contain("Invalid requestorEmail " + Email + " for field requestorEmail");
        }

        [Fact]
        public async Task TrackOrder_NotFound_FlagOff_MasksEmailInKeyNotFoundMessage()
        {
            string marker = "m-" + Guid.NewGuid().ToString("N");
            var (error, _) = await RunAsync(false, "TrackOrder", 200, MetaFailureBody(marker, "EMS-913"), marker,
                c => c.TrackOrderAsync("ORD-1"));

            error.Should().BeOfType<KeyNotFoundException>();
            error.Message.Should().Contain(MaskedEmail).And.NotContain(Email);
        }

        [Fact]
        public async Task GetProductDetails_Non2xxMetaBody_FlagOff_MasksEmailInLogAndException()
        {
            string marker = "m-" + Guid.NewGuid().ToString("N");
            var (error, lines) = await RunAsync(false, "GetProductDetails", 400, MetaFailureBody(marker), marker,
                c => c.GetProductDetailsAsync());

            error.Message.Should().Contain("(HTTP 400)").And.Contain("[EMS-100]")
                .And.Contain("Invalid requestorEmail " + MaskedEmail + " for field requestorEmail")
                .And.NotContain(Email);
            ErrorMessageField(lines).Should().Contain(MaskedEmail).And.NotContain(Email);
        }

        [Fact]
        public async Task GetProductDetails_Non2xxMetaBody_FlagOn_IsVerbatimInLogAndException()
        {
            string marker = "m-" + Guid.NewGuid().ToString("N");
            var (error, lines) = await RunAsync(true, "GetProductDetails", 400, MetaFailureBody(marker), marker,
                c => c.GetProductDetailsAsync());

            error.Message.Should().Contain("Invalid requestorEmail " + Email + " for field requestorEmail");
            ErrorMessageField(lines).Should().Contain("Invalid requestorEmail " + Email + " for field requestorEmail");
        }

        [Fact]
        public void IsRateLimitSurface_StillMatchesRawTextContainingEmail()
        {
            CERTInextClient.IsRateLimitSurface("Inactive Account User. contact " + Email).Should().BeTrue();
            // And the masked form keeps the phrase, so masking never hides a rate-limit diagnosis.
            LogSanitizer.SanitizeCaText("Inactive Account User. contact " + Email, false)
                .Should().Contain("Inactive Account User.");
        }
    }
}
