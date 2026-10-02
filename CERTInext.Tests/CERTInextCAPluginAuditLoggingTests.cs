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
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Issue 0040: pins the on/off behavior of the "Enrollment attempt started" audit log line in
    /// <see cref="CERTInextCAPlugin.Enroll"/> for the <c>LogSensitiveRequestData</c> connector
    /// setting.
    ///
    /// <c>CERTInextCAPlugin._logger</c> is a per-instance field assigned from
    /// <c>LogHandler.GetClassLogger&lt;CERTInextCAPlugin&gt;()</c> at construction time (unlike
    /// <c>Client.CERTInextClient.Logger</c>, which is a <c>static readonly</c> field resolved once
    /// per process — not swappable after the fact). Swapping <see cref="LogHandler.Factory"/>
    /// before constructing a fresh plugin instance is therefore a genuine, narrow capture seam for
    /// this one log line. All tests in this class run in the "LogHandlerFactory-NoParallel"
    /// collection (sequential within the class by xUnit default; the named collection also blocks
    /// any other class opting into it from interleaving) and restore the original factory in a
    /// <c>finally</c> block so the global static mutation can't outlive a single test.
    /// </summary>
    [Collection("LogHandlerFactory-NoParallel")]
    public class CERTInextCAPluginAuditLoggingTests
    {
        private sealed class CapturingLoggerProvider : ILoggerProvider
        {
            public ConcurrentQueue<string> Messages { get; } = new();
            public ILogger CreateLogger(string categoryName) => new CapturingLogger(Messages);
            public void Dispose() { }

            private sealed class CapturingLogger : ILogger
            {
                private readonly ConcurrentQueue<string> _messages;
                public CapturingLogger(ConcurrentQueue<string> messages) => _messages = messages;
                public IDisposable BeginScope<TState>(TState state) => null;
                public bool IsEnabled(LogLevel logLevel) => true;
                public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
                    Func<TState, Exception, string> formatter)
                    => _messages.Enqueue(formatter(state, exception));
            }
        }

        private static Mock<ICERTInextClient> NewHappyPathMock()
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Loose);
            mock.Setup(c => c.EnrollCertificateAsync(It.IsAny<API.EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new API.EnrollCertificateResponse
                {
                    Id = "ORD-AUDIT-001",
                    Status = "issued",
                    Certificate = MockCertificateData.FakePemCertificate
                });
            return mock;
        }

        /// <summary>
        /// Runs <see cref="CERTInextCAPlugin.Enroll"/> once with a freshly-swapped capturing
        /// logger factory in place — constructing the plugin only after the swap, so its
        /// per-instance <c>_logger</c> field resolves through the capturing factory — and returns
        /// every rendered log message the plugin emitted. RequesterName/RequesterEmail are driven
        /// through the template parameters that <c>EnrollmentParams.RequesterName</c>/
        /// <c>RequesterEmail</c> read (<see cref="Constants.EnrollmentParam.RequesterName"/> /
        /// <c>RequesterEmail</c>), matching what the "Enrollment attempt started" line logs.
        /// </summary>
        private static async Task<(ConcurrentQueue<string> Messages, string SubjectMarker)> CaptureEnrollLogMessagesAsync(
            bool logSensitiveRequestData, string requesterName, string requesterEmail)
        {
            var provider = new CapturingLoggerProvider();
            var factory = LoggerFactory.Create(b => b.AddProvider(provider).SetMinimumLevel(LogLevel.Trace));

            // LogHandler.Factory is a shared static — other test classes construct their own
            // CERTInextCAPlugin instances concurrently (xUnit parallelizes across collections by
            // default) and, purely by coincidence of timing, some of those may resolve their
            // _logger through this same swapped factory while it's active, adding unrelated
            // "Enrollment attempt started" lines to provider.Messages. A per-call unique subject
            // is the only reliable way to pick this call's own line back out of that noise.
            string subjectMarker = "audit-" + Guid.NewGuid().ToString("N");
            try
            {
                LogHandler.Factory = factory;

                var mock = NewHappyPathMock();
                var config = new CERTInextConfig
                {
                    PickupRetries = 0,
                    LogSensitiveRequestData = logSensitiveRequestData
                };
                // Constructed AFTER the factory swap so its _logger field resolves through it.
                var plugin = new CERTInextCAPlugin(mock.Object, config);

                var productInfo = new EnrollmentProductInfo
                {
                    ProductID = "DV SSL",
                    ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["ProductCode"] = "842",
                        [Constants.EnrollmentParam.RequesterName] = requesterName,
                        [Constants.EnrollmentParam.RequesterEmail] = requesterEmail
                    }
                };

                await plugin.Enroll(
                    csr: MockCertificateData.FakeCsrPem,
                    subject: $"CN={subjectMarker}.example.com",
                    san: null,
                    productInfo: productInfo,
                    requestFormat: RequestFormat.PKCS10,
                    enrollmentType: EnrollmentType.New);
            }
            finally
            {
                // LogHandler.Factory is write-only (no getter to save/restore the prior value),
                // so reset to the same NullLoggerFactory the class defaults to absent any host
                // configuring a real one — matching every other test's ambient (unconfigured)
                // logging state.
                LogHandler.Factory = Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance;
                factory.Dispose();
            }

            return (provider.Messages, subjectMarker);
        }

        private static string FindEnrollmentAttemptLine(ConcurrentQueue<string> messages, string subjectMarker)
        {
            foreach (var m in messages)
            {
                if (m.Contains("Enrollment attempt started") && m.Contains(subjectMarker))
                    return m;
            }
            return null;
        }

        [Fact]
        public async Task Enroll_LogSensitiveRequestDataFalse_AuditLineOmitsNameAndMasksEmail()
        {
            var (messages, marker) = await CaptureEnrollLogMessagesAsync(
                logSensitiveRequestData: false, requesterName: "Jane Doe", requesterEmail: "jane.doe@example.com");

            string line = FindEnrollmentAttemptLine(messages, marker);
            line.Should().NotBeNull("the enrollment-attempt audit line must always be logged");
            line.Should().NotContain("Jane Doe", "the requester name must be dropped entirely when the flag is off");
            line.Should().NotContain("RequesterName=", "the RequesterName field itself must be absent from the line, not just blanked");
            line.Should().Contain("j***@example.com", "the requester email must be masked but keep its domain");
            line.Should().NotContain("jane.doe@example.com");
        }

        [Fact]
        public async Task Enroll_LogSensitiveRequestDataTrue_AuditLineIncludesNameAndEmailInFull()
        {
            var (messages, marker) = await CaptureEnrollLogMessagesAsync(
                logSensitiveRequestData: true, requesterName: "Jane Doe", requesterEmail: "jane.doe@example.com");

            string line = FindEnrollmentAttemptLine(messages, marker);
            line.Should().NotBeNull("the enrollment-attempt audit line must always be logged");
            line.Should().Contain("Jane Doe", "the requester name is logged in full when the flag is on");
            line.Should().Contain("jane.doe@example.com", "the requester email is logged in full when the flag is on");
        }
    }
}
