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
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using Moq;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Regression tests for issue 0046: the V2 SSL UCC path reused <c>BuildSanList</c>, whose
    /// V1-worded warning claimed non-DNS SANs "are submitted rather than dropped on purpose" even
    /// though <c>EnrollV2Async</c> always strips them from <c>additionalDomains</c>. The V2 path
    /// must now log its own "excluded from V2 additionalDomains" message (SAN types only, no
    /// values), V1 must keep its original wording and wire behaviour, and private-pki must be
    /// unaffected.
    ///
    /// Log capture: <c>CERTInextCAPlugin._logger</c> is a per-instance field resolved from
    /// <see cref="LogHandler.Factory"/> at construction, so swapping the factory before building
    /// the plugin captures its messages (same seam as <see cref="CERTInextCAPluginAuditLoggingTests"/>,
    /// and the same non-parallel collection). Other test classes may log through the swapped
    /// factory concurrently, so assertions only consider messages carrying this call's unique
    /// subject marker.
    /// </summary>
    [Collection("LogHandlerFactory-NoParallel")]
    public class V2UccNonDnsSanLoggingTests
    {
        private const string V1SubmittedWording = "submitted rather than dropped";
        private const string V1DroppedWording = "DROPPED because SubmitNonDnsSans is false";
        private const string V2ExcludedWording = "non-DNS SAN(s) excluded from V2 additionalDomains";
        private const string EmailSan = "admin@example.com";

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

        /// <summary>
        /// Builds the plugin (after swapping <see cref="LogHandler.Factory"/>), runs
        /// <paramref name="enroll"/>, and returns every captured message mentioning
        /// <paramref name="marker"/>.
        /// </summary>
        private static async Task<List<string>> CaptureAsync(
            string marker, Func<CERTInextCAPlugin> buildPlugin, Func<CERTInextCAPlugin, Task> enroll)
        {
            var provider = new CapturingLoggerProvider();
            var factory = LoggerFactory.Create(b => b.AddProvider(provider).SetMinimumLevel(LogLevel.Trace));
            try
            {
                LogHandler.Factory = factory;
                var plugin = buildPlugin(); // constructed AFTER the swap so _logger resolves through it
                await enroll(plugin);
            }
            finally
            {
                LogHandler.Factory = Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance;
                factory.Dispose();
            }

            return provider.Messages.Where(m => m != null && m.Contains(marker)).ToList();
        }

        private static string NewMarker() => "sanlog-" + Guid.NewGuid().ToString("N");

        // BouncyCastle only (project crypto policy). CN only — UCC CSRs carry only the primary domain.
        private static string GenerateCsrPem(string cn)
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            AsymmetricCipherKeyPair kp = keyGen.GenerateKeyPair();
            var csr = new Pkcs10CertificationRequest(
                "SHA256withRSA", new X509Name($"CN={cn}"), kp.Public, null, kp.Private);
            return "-----BEGIN CERTIFICATE REQUEST-----\n"
                 + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                 + "\n-----END CERTIFICATE REQUEST-----";
        }

        private static Dictionary<string, string[]> MixedSans(string primary) => new()
        {
            ["dnsname"]    = new[] { primary, "san1." + primary },
            ["ipaddress"]  = new[] { "192.0.2.10" },
            ["rfc822name"] = new[] { EmailSan }
        };

        // ---------------------------------------------------------------------------
        // V2 SSL UCC
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task Enroll_V2_Ucc_NonDnsSans_LogsV2ExclusionNotV1Wording_WireStaysDnsOnly(bool submitNonDnsSans)
        {
            string marker = NewMarker();
            string primary = marker + ".example.com";

            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = "844", ProductTypeId = "15", Active = true } // DV SSL UCC
                });
            V2CreateSslOrderRequest captured = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>((_, __, req, ___) => captured = req)
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = "ord_0046", Status = "pending-dcv" });
            mock.Setup(c => c.SubmitCsrV2Async(
                    It.IsAny<string>(), "ord_0046", It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), "ord_0046", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = "ord_0046", Status = "pending-dcv" });

            var config = new CERTInextConfig
            {
                UseV2Api          = true,
                ApiUrl            = "https://v2.certinext.io",
                OAuthClientId     = "my-client",
                OAuthClientSecret = "my-secret",
                RequestorName     = "Test User",
                RequestorEmail    = "test@example.com",
                SignerIp          = "1.2.3.4",
                SignerPlace       = "New York",
                PickupRetries     = 0,
                SubmitNonDnsSans  = submitNonDnsSans
            };
            var productInfo = new EnrollmentProductInfo
            {
                ProductID = "DV SSL UCC",
                ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ProductCode"]    = "844",
                    ["ProductFamily"]  = "ssl",
                    ["ProductVariant"] = "dv",
                    ["DomainName"]     = primary
                }
            };

            var messages = await CaptureAsync(marker,
                () => new CERTInextCAPlugin(mock.Object, config),
                p => p.Enroll(GenerateCsrPem(primary), $"CN={primary}", MixedSans(primary), productInfo,
                    RequestFormat.PKCS10, EnrollmentType.New));

            // Wire unchanged: additionalDomains stays DNS-only regardless of SubmitNonDnsSans.
            captured.Should().NotBeNull();
            captured!.Certificate.AdditionalDomains.Should().Equal(new[] { "san1." + primary });

            messages.Should().NotContain(m => m.Contains(V1SubmittedWording),
                "V2 additionalDomains never carries non-DNS SANs, so the V1 'submitted' claim is false here");
            messages.Should().NotContain(m => m.Contains(V1DroppedWording),
                "SubmitNonDnsSans is a V1 switch and does not decide the V2 outcome");

            var v2 = messages.Where(m => m.Contains(V2ExcludedWording)).ToList();
            v2.Should().ContainSingle();
            v2[0].Should().StartWith("EnrollV2Async: 2 non-DNS SAN(s) excluded from V2 additionalDomains");
            v2[0].Should().Contain("Types=[ip, email]");

            // Scoped to the SAN-resolution log sites this path owns. The Enroll-wide "Enrollment
            // attempt started" audit line (shared with V1) logs the raw SAN dictionary and is
            // out of scope for issue 0046.
            v2[0].Should().NotContain(EmailSan,
                "an email SAN value is personal data; the V2 exclusion message logs SAN types only");
            messages.Where(m => m.StartsWith("Resolved ")).Should().ContainSingle()
                .Which.Should().NotContain(EmailSan,
                    "in DNS-only mode the resolved-SAN audit line describes only what V2 submits");
        }

        // ---------------------------------------------------------------------------
        // V1 — original wording and wire behaviour preserved
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_V1_NonDnsSans_StillLogsSubmittedWording_AndSubmitsThem()
        {
            string marker = NewMarker();
            string primary = marker + ".example.com";

            EnrollCertificateRequest captured = null;
            var mock = new Mock<ICERTInextClient>(MockBehavior.Loose);
            mock.Setup(c => c.EnrollCertificateAsync(It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .Callback<EnrollCertificateRequest, CancellationToken>((req, _) => captured = req)
                .ReturnsAsync(new EnrollCertificateResponse
                {
                    Id = "ORD-0046", Status = "issued", Certificate = MockCertificateData.FakePemCertificate
                });

            var productInfo = new EnrollmentProductInfo
            {
                ProductID = "DV SSL",
                ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ProductCode"] = "842"
                }
            };

            var messages = await CaptureAsync(marker,
                () => new CERTInextCAPlugin(mock.Object, new CERTInextConfig { PickupRetries = 0 }),
                p => p.Enroll(GenerateCsrPem(primary), $"CN={primary}", MixedSans(primary), productInfo,
                    RequestFormat.PKCS10, EnrollmentType.New));

            captured.Should().NotBeNull();
            captured!.Sans.Select(s => s.Value).Should().Contain(new[] { "192.0.2.10", EmailSan },
                "V1 submits non-DNS SANs on purpose when SubmitNonDnsSans is true (the default)");

            messages.Should().Contain(m => m.Contains(V1SubmittedWording));
            messages.Should().NotContain(m => m.Contains(V2ExcludedWording));
        }

        // ---------------------------------------------------------------------------
        // Private PKI — unaffected
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_V2_PrivatePki_IpSansStillInAdditionalHosts_NoSslSanWording()
        {
            string marker = NewMarker();
            const string hostname = "intranet.acme.local";

            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            V2CreatePrivatePkiOrderRequest captured = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<V2CreatePrivatePkiOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, V2CreatePrivatePkiOrderRequest, CancellationToken>((_, req, __) => captured = req)
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = "ord_pki_0046", Status = "pending-csr" });
            mock.Setup(c => c.SubmitCsrV2Async(
                    Constants.ApiV2.FamilyPrivatePki, "ord_pki_0046", It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.TrackOrderV2Async(Constants.ApiV2.FamilyPrivatePki, "ord_pki_0046", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = "ord_pki_0046", Status = "pending-approval" });

            var config = new CERTInextConfig
            {
                UseV2Api          = true,
                ApiUrl            = "https://v2.certinext.io",
                OAuthClientId     = "my-client",
                OAuthClientSecret = "my-secret",
                RequestorName     = "DevOps Team",
                RequestorEmail    = "devops@acme.com",
                RequestorIsdCode  = "1",
                RequestorMobileNumber = "4155551234",
                SignerIp          = "1.2.3.4",
                SignerPlace       = "New York",
                PickupRetries     = 0,
                SubmitNonDnsSans  = false
            };
            var productInfo = new EnrollmentProductInfo
            {
                ProductID = Constants.Products.DvSsl,
                ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ProductFamily"]  = "private-pki",
                    ["ProductVariant"] = "intranet-ssl",
                    ["ProductCode"]    = "149",
                    ["DomainName"]     = hostname
                }
            };

            var messages = await CaptureAsync(marker,
                () => new CERTInextCAPlugin(mock.Object, config),
                p => p.Enroll(MockCertificateData.FakeCsrPem, $"CN={hostname}, OU={marker}",
                    new Dictionary<string, string[]>
                    {
                        ["dnsname"]   = new[] { hostname },
                        ["ipaddress"] = new[] { "10.0.0.50" }
                    },
                    productInfo, RequestFormat.PKCS10, EnrollmentType.New));

            captured.Should().NotBeNull();
            captured!.AdditionalHosts.Should().Equal(new[] { "10.0.0.50" },
                "private-pki carries IP SANs natively and never consults SubmitNonDnsSans");

            messages.Should().NotContain(m => m.Contains(V2ExcludedWording));
            messages.Should().NotContain(m => m.Contains(V1SubmittedWording));
            messages.Should().NotContain(m => m.Contains(V1DroppedWording));
        }
    }
}
