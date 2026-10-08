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
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Issue 0040 follow-up: with <c>LogSensitiveRequestData</c> off, email-type SAN values are
    /// masked in log lines (<see cref="LogSanitizer.MaskEmail"/>); DNS, IP and URI values stay
    /// verbatim. With the flag on, everything is logged in full.
    /// </summary>
    public class LogSanitizerFormatSansTests
    {
        [Theory]
        [InlineData("rfc822name")]
        [InlineData("RFC822Name")]
        [InlineData("rfc822")]
        [InlineData("email")]
        public void FormatSanValue_FlagOff_EmailType_IsMasked(string type)
            => LogSanitizer.FormatSanValue(type, "alice@example.com", false).Should().Be("a***@example.com");

        [Theory]
        [InlineData("rfc822name")]
        [InlineData("email")]
        [InlineData("otherName")]
        [InlineData(null)]
        public void FormatSanValue_FlagOn_IsVerbatim(string type)
            => LogSanitizer.FormatSanValue(type, "alice@example.com", true).Should().Be("alice@example.com");

        [Theory]
        [InlineData("dnsname", "www.example.com")]
        [InlineData("dns", "www.example.com")]
        [InlineData("ipaddress", "192.0.2.10")]
        [InlineData("ip", "2001:db8::1")]
        [InlineData("uri", "https://example.com/path")]
        [InlineData("uri", "https://host.example.com:8443/a/b?q=1#frag")]
        [InlineData("uniformresourceidentifier", "urn:example:thing")]
        [InlineData("uri", "https://example.com/path/@handle")]
        [InlineData("uri", "https://example.com/?contact=a@b.example")]
        public void FormatSanValue_DnsIpUri_VerbatimEitherWay(string type, string value)
        {
            LogSanitizer.FormatSanValue(type, value, false).Should().Be(value);
            LogSanitizer.FormatSanValue(type, value, true).Should().Be(value);
        }

        [Theory]
        [InlineData("uri", "mailto:jane.doe@example.com", "mailto:j***@example.com")]
        [InlineData("URI", "MAILTO:jane.doe@example.com", "MAILTO:j***@example.com")]
        [InlineData("uniformresourceidentifier", "sip:jane.doe@example.com", "sip:j***@example.com")]
        [InlineData("uri", "https://user:pw@host.example.com/", "https://***@host.example.com/")]
        [InlineData("uri", "https://user@host.example.com/", "https://***@host.example.com/")]
        [InlineData("uri", "ldaps://cn=a:p@ss@host.example.com:636/dc=x?q", "ldaps://***@host.example.com:636/dc=x?q")]
        [InlineData("uri", "https://user:pw@host.example.com", "https://***@host.example.com")]
        public void FormatSanValue_FlagOff_UriWithAt_IsMasked(string type, string value, string expected)
        {
            string masked = LogSanitizer.FormatSanValue(type, value, false);
            masked.Should().Be(expected);
            masked.Should().NotContain("jane.doe").And.NotContain("pw@").And.NotContain("user");
        }

        [Theory]
        [InlineData("uri", "mailto:jane.doe@example.com")]
        [InlineData("uri", "https://user:pw@host.example.com/")]
        [InlineData("uniformresourceidentifier", "https://user@host.example.com/")]
        public void FormatSanValue_FlagOn_UriIsVerbatim(string type, string value)
            => LogSanitizer.FormatSanValue(type, value, true).Should().Be(value);

        [Fact]
        public void FormatSans_Dictionary_FlagOff_MasksUriUserinfoAndMailto()
        {
            var san = new Dictionary<string, string[]>
            {
                ["uri"] = new[] { "mailto:jane.doe@example.com", "https://user:pw@host.example.com/", "https://example.com" }
            };

            string off = LogSanitizer.FormatSans(san, false);
            off.Should().Be("uri:mailto:j***@example.com; uri:https://***@host.example.com/; uri:https://example.com");
            off.Should().NotContain("jane.doe").And.NotContain("pw");
            LogSanitizer.FormatSans(san, true).Should().Contain("uri:mailto:jane.doe@example.com")
                .And.Contain("uri:https://user:pw@host.example.com/");
        }

        [Fact]
        public void FormatUntypedSans_FlagOff_UriWithAt_LeaksNoLocalPartOrUserinfo()
        {
            string line = LogSanitizer.FormatUntypedSans(
                new[] { "mailto:jane.doe@example.com", "https://user:pw@host.example.com/", "https://example.com/x" }, false);
            line.Should().NotContain("jane.doe").And.NotContain("user").And.NotContain("pw@")
                .And.Contain("https://example.com/x");
        }

        [Theory]
        [InlineData("upn")]
        [InlineData(null)]
        public void FormatSanValue_FlagOff_UnknownTypeWithAt_IsMasked(string type)
            => LogSanitizer.FormatSanValue(type, "bob@corp.example.com", false).Should().Be("b***@corp.example.com");

        [Fact]
        public void FormatSanValue_FlagOff_UnknownTypeWithoutAt_IsVerbatim()
            => LogSanitizer.FormatSanValue("upn", "host.example.com", false).Should().Be("host.example.com");

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void FormatSanValue_NullOrEmptyValue_ReturnedAsIs(string value)
        {
            LogSanitizer.FormatSanValue("rfc822name", value, false).Should().Be(value);
            LogSanitizer.FormatSanValue(null, value, false).Should().Be(value);
        }

        [Fact]
        public void FormatSans_Dictionary_FlagOff_MasksOnlyEmail()
        {
            var san = new Dictionary<string, string[]>
            {
                ["dnsname"] = new[] { "a.example.com", "b.example.com" },
                ["ipaddress"] = new[] { "192.0.2.10" },
                ["rfc822name"] = new[] { "alice@example.com" },
                ["uri"] = new[] { "https://example.com" }
            };

            LogSanitizer.FormatSans(san, false).Should().Be(
                "dnsname:a.example.com; dnsname:b.example.com; ipaddress:192.0.2.10; " +
                "rfc822name:a***@example.com; uri:https://example.com");
            LogSanitizer.FormatSans(san, true).Should().Contain("rfc822name:alice@example.com");
        }

        [Fact]
        public void FormatSans_Dictionary_NullOrEmpty_ReturnsNone()
        {
            LogSanitizer.FormatSans((Dictionary<string, string[]>)null, false).Should().Be("(none)");
            LogSanitizer.FormatSans(new Dictionary<string, string[]>(), false).Should().Be("(none)");
            LogSanitizer.FormatSans(new Dictionary<string, string[]> { ["dnsname"] = null }, false).Should().Be("(none)");
        }

        [Fact]
        public void FormatSans_SanEntries_FlagOff_MasksEmail_SkipsNullEntries()
        {
            var sans = new List<SanEntry>
            {
                new SanEntry { Type = "dns", Value = "a.example.com" },
                null,
                new SanEntry { Type = "email", Value = "alice@example.com" }
            };

            LogSanitizer.FormatSans(sans, false).Should().Be("dns:a.example.com; email:a***@example.com");
            LogSanitizer.FormatSans(sans, true).Should().Be("dns:a.example.com; email:alice@example.com");
            LogSanitizer.FormatSans((IEnumerable<SanEntry>)null, false).Should().Be("(none)");
        }

        [Fact]
        public void FormatSans_StillStripsControlCharacters()
            => LogSanitizer.FormatSans(new Dictionary<string, string[]> { ["dnsname"] = new[] { "a.example.com\nforged" } }, false)
                .Should().Be("dnsname:a.example.com\\nforged");

        [Fact]
        public void FormatUntypedSans_FlagOff_MasksAtValuesOnly()
        {
            var values = new[] { "a.example.com", "alice@example.com", "192.0.2.10" };
            LogSanitizer.FormatUntypedSans(values, false).Should().Be("a.example.com; a***@example.com; 192.0.2.10");
            LogSanitizer.FormatUntypedSans(values, true).Should().Be("a.example.com; alice@example.com; 192.0.2.10");
            LogSanitizer.FormatUntypedSans(values, false, ", ").Should().Be("a.example.com, a***@example.com, 192.0.2.10");
        }

        [Fact]
        public void FormatUntypedSans_NullOrEmpty_ReturnsNone()
        {
            LogSanitizer.FormatUntypedSans(null, false).Should().Be("(none)");
            LogSanitizer.FormatUntypedSans(Array.Empty<string>(), false).Should().Be("(none)");
        }
    }

    /// <summary>
    /// Plugin-level log capture for the issue 0040 follow-up: the "Enrollment attempt started"
    /// line and <c>BuildSanList</c>'s "Resolved N SAN(s)" / "submitted rather than dropped" lines
    /// must mask an email SAN with <c>LogSensitiveRequestData</c> off and log it in full with it
    /// on. Same <see cref="LogHandler.Factory"/> swap seam and non-parallel collection as
    /// <see cref="CERTInextCAPluginAuditLoggingTests"/>; only lines carrying this call's unique
    /// subject marker are considered.
    /// </summary>
    [Collection(LoggingStateCollection.Name)]
    public class SanLogMaskingPluginTests
    {
        private const string EmailSan = "alice@example.com";
        private const string MaskedEmailSan = "a***@example.com";
        private const string IpSan = "192.0.2.10";

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

        private static async Task<(List<string> Messages, string Primary, EnrollCertificateRequest Captured)> EnrollV1Async(
            bool logSensitiveRequestData)
        {
            string marker = "sanmask-" + Guid.NewGuid().ToString("N");
            string primary = marker + ".example.com";

            EnrollCertificateRequest captured = null;
            var mock = new Mock<ICERTInextClient>(MockBehavior.Loose);
            mock.Setup(c => c.EnrollCertificateAsync(It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .Callback<EnrollCertificateRequest, CancellationToken>((req, _) => captured = req)
                .ReturnsAsync(new EnrollCertificateResponse
                {
                    Id = "ORD-SANMASK", Status = "issued", Certificate = MockCertificateData.FakePemCertificate
                });

            var productInfo = new EnrollmentProductInfo
            {
                ProductID = "DV SSL",
                ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ProductCode"] = "842"
                }
            };
            var san = new Dictionary<string, string[]>
            {
                ["dnsname"]    = new[] { primary },
                ["ipaddress"]  = new[] { IpSan },
                ["rfc822name"] = new[] { EmailSan }
            };

            var provider = new CapturingLoggerProvider();
            var factory = LoggerFactory.Create(b => b.AddProvider(provider).SetMinimumLevel(LogLevel.Trace));
            try
            {
                LogHandler.Factory = factory;
                // Constructed AFTER the swap so _logger resolves through the capturing factory.
                var plugin = new CERTInextCAPlugin(mock.Object, new CERTInextConfig
                {
                    PickupRetries = 0,
                    LogSensitiveRequestData = logSensitiveRequestData
                });
                await plugin.Enroll(MockCertificateData.FakeCsrPem, $"CN={primary}", san, productInfo,
                    RequestFormat.PKCS10, EnrollmentType.New);
            }
            finally
            {
                LogHandler.Factory = Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance;
                factory.Dispose();
            }

            return (provider.Messages.Where(m => m != null && m.Contains(marker)).ToList(), primary, captured);
        }

        [Fact]
        public async Task Enroll_FlagOff_MasksEmailSan_KeepsDnsAndIpVerbatim_WireUnchanged()
        {
            var (messages, primary, captured) = await EnrollV1Async(logSensitiveRequestData: false);

            var start = messages.Where(m => m.StartsWith("Enrollment attempt started")).ToList();
            start.Should().ContainSingle();
            start[0].Should().Contain($"dnsname:{primary}")
                .And.Contain($"ipaddress:{IpSan}")
                .And.Contain($"rfc822name:{MaskedEmailSan}")
                .And.NotContain(EmailSan);

            var resolved = messages.Where(m => m.StartsWith("Resolved ")).ToList();
            resolved.Should().ContainSingle();
            resolved[0].Should().Contain($"dns:{primary}")
                .And.Contain($"ip:{IpSan}")
                .And.Contain($"email:{MaskedEmailSan}")
                .And.NotContain(EmailSan);

            messages.Should().NotContain(m => m.Contains(EmailSan),
                "no plugin log line for this enrollment may carry the unmasked email SAN with the flag off");

            captured.Should().NotBeNull();
            captured!.Sans.Select(s => s.Value).Should().Contain(EmailSan,
                "masking is log-only; the SAN still goes to CERTInext unchanged");
        }

        [Fact]
        public async Task Enroll_FlagOn_LogsEmailSanInFull()
        {
            var (messages, _, captured) = await EnrollV1Async(logSensitiveRequestData: true);

            messages.Where(m => m.StartsWith("Enrollment attempt started")).Should().ContainSingle()
                .Which.Should().Contain($"rfc822name:{EmailSan}");
            messages.Where(m => m.StartsWith("Resolved ")).Should().ContainSingle()
                .Which.Should().Contain($"email:{EmailSan}");
            messages.Should().NotContain(m => m.Contains(MaskedEmailSan));

            captured!.Sans.Select(s => s.Value).Should().Contain(EmailSan);
        }
    }
}
