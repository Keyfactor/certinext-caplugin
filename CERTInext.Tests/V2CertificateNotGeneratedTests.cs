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
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Download Certificate answers 422 EMS-1165 for a while after Track Order already reports
    /// <c>issued</c> (the certificate is not generated yet; ~20 s normally). That is expected, so it
    /// must not log a Warning per attempt: Debug per attempt plus one Info summary, the order stays
    /// pending, and any other download error keeps its Warning. Covers the enroll immediate
    /// download, the pickup poll, GetSingleRecord and Synchronize.
    /// </summary>
    [Collection(LoggingStateCollection.Name)]
    public class V2CertificateNotGeneratedTests
    {
        private const string OrderId = "ord_ng_001";

        private static readonly V2CertificateNotGeneratedException NotGenerated = new(
            "CERTInext V2 API error during 'V2 download certificate'. HTTP 422. Unprocessable Entity: EMS-1165 Invalid request status.");

        private static CERTInextConfig Config(int pickupRetries = 0, ICertificateDataReader _ = null) => new CERTInextConfig
        {
            UseV2Api             = true,
            ApiUrl               = "https://v2.certinext.io",
            OAuthClientId        = "my-client",
            OAuthClientSecret    = "my-secret",
            RequestorName        = "Test User",
            RequestorEmail       = "test@example.com",
            SignerPlace          = "New York",
            PickupRetries        = pickupRetries,
            PickupDelayInSeconds = 1
        };

        private static V2OrderStatusResponse IssuedButNotGenerated() => new V2OrderStatusResponse
        {
            OrderId = OrderId, Status = "issued", OrderState = "Order Accepted", CertificateState = "Approved by System"
        };

        private static Mock<ICERTInextClient> NewIssuedOrderMock()
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = OrderId, Status = "pending-csr" });
            mock.Setup(c => c.SubmitCsrV2Async(It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(IssuedButNotGenerated());
            return mock;
        }

        private static Task<EnrollmentResult> EnrollAsync(CERTInextCAPlugin plugin) =>
            plugin.Enroll(MockCertificateData.FakeCsrPem, "CN=example.com",
                new Dictionary<string, string[]> { ["dnsname"] = new[] { "example.com" } },
                new EnrollmentProductInfo
                {
                    ProductID = Constants.Products.DvSsl,
                    ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["ProductFamily"] = "ssl", ["DomainName"] = "example.com"
                    }
                },
                RequestFormat.PKCS10, EnrollmentType.New);

        // ---------------------------------------------------------------------------
        // Classifier
        // ---------------------------------------------------------------------------

        [Fact]
        public void IsCertificateNotGeneratedYet_RecognisesTheTypedExceptionAndTheEquivalentPlainMessage()
        {
            CERTInextCAPlugin.IsCertificateNotGeneratedYet(NotGenerated).Should().BeTrue();
            CERTInextCAPlugin.IsCertificateNotGeneratedYet(new Exception(
                "CERTInext V2 API error during 'V2 download certificate'. HTTP 422. EMS-1165 Invalid request status.")).Should().BeTrue();
        }

        [Theory]
        [InlineData("CERTInext V2 API error during 'V2 download certificate'. HTTP 422. EMS-1164 Domain Name is not matching.")]
        [InlineData("CERTInext V2 API error during 'V2 download certificate'. HTTP 500. EMS-1165 something")]
        [InlineData("HTTP 422 with no code")]
        public void IsCertificateNotGeneratedYet_OtherFailures_AreNotClassifiedAsNotGenerated(string message)
        {
            CERTInextCAPlugin.IsCertificateNotGeneratedYet(new Exception(message)).Should().BeFalse();
            CERTInextCAPlugin.IsCertificateNotGeneratedYet(null).Should().BeFalse();
        }

        // ---------------------------------------------------------------------------
        // Enroll: immediate download + pickup poll
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Enroll_IssuedButNotGeneratedForTheWholePickup_ReturnsPending_NoWarnings_OneInfoSummary()
        {
            using var capture = new PluginLogCapture();
            var mock = NewIssuedOrderMock();
            mock.Setup(c => c.DownloadCertificateV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ThrowsAsync(NotGenerated);
            var plugin = new CERTInextCAPlugin(mock.Object, Config(pickupRetries: 2));

            var result = await EnrollAsync(plugin);

            result.CARequestID.Should().Be(OrderId);
            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            result.Certificate.Should().BeNull();
            result.StatusMessage.Should().Contain("not generated yet");

            capture.Entries.Where(e => e.Level >= LogLevel.Warning).Should().BeEmpty(
                "an expected 422 EMS-1165 on an issued order must not log a Warning or Error per attempt");
            var summary = capture.Lines(LogLevel.Information, "not generated yet after");
            summary.Should().ContainSingle();
            summary[0].Should().Contain("2 of 2").And.Contain("EMS-1165")
                .And.Contain("CertificateState='Approved by System'").And.Contain("OrderState='Order Accepted'");
            // Debug per attempt: the immediate download plus both pickup attempts.
            capture.Entries.Count(e => e.Level == LogLevel.Debug && e.Message.Contains("not generated yet")).Should().Be(3);
            mock.Verify(c => c.DownloadCertificateV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()), Times.Exactly(3));
        }

        [Fact]
        public async Task Enroll_CertificateBecomesDownloadableDuringPickup_ReturnsIssued_WithoutWarnings()
        {
            using var capture = new PluginLogCapture();
            var mock = NewIssuedOrderMock();
            mock.SetupSequence(c => c.DownloadCertificateV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ThrowsAsync(NotGenerated)   // immediate attempt
                .ThrowsAsync(NotGenerated)   // pickup attempt 1
                .ReturnsAsync(new V2CertificateDownloadResponse
                {
                    OrderId = OrderId, SerialNumber = "0A1B", CertificatePem = MockCertificateData.FakePemCertificate
                });
            var plugin = new CERTInextCAPlugin(mock.Object, Config(pickupRetries: 3));

            var result = await EnrollAsync(plugin);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            result.Certificate.Should().StartWith("-----BEGIN CERTIFICATE-----");
            capture.Entries.Where(e => e.Level >= LogLevel.Warning).Should().BeEmpty();
            capture.Lines(LogLevel.Information, "not generated yet after").Should().BeEmpty(
                "the summary is only for a poll that ended without the certificate");
        }

        [Fact]
        public async Task Enroll_OtherDownloadErrors_StillWarnPerAttempt()
        {
            using var capture = new PluginLogCapture();
            var mock = NewIssuedOrderMock();
            mock.Setup(c => c.DownloadCertificateV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("CERTInext V2 API error during 'V2 download certificate'. HTTP 500. boom"));
            var plugin = new CERTInextCAPlugin(mock.Object, Config(pickupRetries: 2));

            var result = await EnrollAsync(plugin);

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            capture.Lines(LogLevel.Warning, "certificate download failed").Length.Should().Be(3,
                "the immediate download and both pickup attempts keep their Warning");
            capture.Lines(LogLevel.Information, "not generated yet after").Should().BeEmpty();
        }

        // ---------------------------------------------------------------------------
        // GetSingleRecord
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task GetSingleRecord_IssuedButNotGenerated_LogsInfoNotWarning_AndReturnsTheRecordWithoutABody()
        {
            using var capture = new PluginLogCapture();
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, IssuedButNotGenerated()));
            mock.Setup(c => c.ResolveAndDownloadCertificateV2Async(OrderId, It.IsAny<CancellationToken>()))
                .ThrowsAsync(NotGenerated);
            var plugin = new CERTInextCAPlugin(mock.Object, Config());

            var record = await plugin.GetSingleRecord(OrderId);

            record.CARequestID.Should().Be(OrderId);
            record.Certificate.Should().BeNull();
            capture.Entries.Where(e => e.Level >= LogLevel.Warning).Should().BeEmpty();
            var lines = capture.Lines(LogLevel.Information, "not generated yet");
            lines.Should().ContainSingle();
            lines[0].Should().Contain("CertificateState='Approved by System'");
        }

        [Fact]
        public async Task GetSingleRecord_OtherDownloadError_StillWarns()
        {
            using var capture = new PluginLogCapture();
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, IssuedButNotGenerated()));
            mock.Setup(c => c.ResolveAndDownloadCertificateV2Async(OrderId, It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("CERTInext V2 API error during 'V2 download certificate'. HTTP 500. boom"));
            var plugin = new CERTInextCAPlugin(mock.Object, Config());

            await plugin.GetSingleRecord(OrderId);

            capture.Lines(LogLevel.Warning, "certificate download failed").Should().ContainSingle();
        }

        // ---------------------------------------------------------------------------
        // Synchronize
        // ---------------------------------------------------------------------------

        private static async IAsyncEnumerable<OrderReportEntryV2> Rows(params OrderReportEntryV2[] rows)
        {
            foreach (var r in rows) yield return r;
            await Task.CompletedTask;
        }

        private static OrderReportEntryV2 IssuedRow() => new OrderReportEntryV2
        {
            OrderNumber       = OrderId,
            OrderStatus       = "Order Fulfilled",
            CertificateStatus = "Certificate Downloaded",
            DomainName        = "example.com",
            ProductCode       = "842",
            OrderDate         = DateTime.UtcNow.AddHours(-1).ToString("o")
        };

        [Fact]
        public async Task Synchronize_IssuedButNotGenerated_NoWarning_CountedInTheSummary_RecordEmittedWithoutBody()
        {
            using var capture = new PluginLogCapture();
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(Rows(IssuedRow()));
            mock.Setup(c => c.ResolveAndDownloadCertificateV2Async(OrderId, It.IsAny<CancellationToken>()))
                .ThrowsAsync(NotGenerated);
            var plugin = new CERTInextCAPlugin(mock.Object, Config());
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            var record = buffer.ToArray().Should().ContainSingle().Which;
            record.CARequestID.Should().Be(OrderId);
            record.Certificate.Should().BeNullOrEmpty();
            capture.Entries.Where(e => e.Level >= LogLevel.Warning).Should().BeEmpty();
            capture.Lines(LogLevel.Debug, "not generated yet").Should().ContainSingle();
            capture.Lines(LogLevel.Information, "synchronization complete").Should().ContainSingle()
                .Which.Should().Contain("IssuedNotGeneratedYet=1");
        }

        [Fact]
        public async Task Synchronize_OtherDownloadError_StillWarns_AndIsNotCountedAsNotGenerated()
        {
            using var capture = new PluginLogCapture();
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(Rows(IssuedRow()));
            mock.Setup(c => c.ResolveAndDownloadCertificateV2Async(OrderId, It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("CERTInext V2 API error during 'V2 download certificate'. HTTP 500. boom"));
            var plugin = new CERTInextCAPlugin(mock.Object, Config());
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            capture.Lines(LogLevel.Warning, "certificate download failed").Should().ContainSingle();
            capture.Lines(LogLevel.Information, "synchronization complete").Should().ContainSingle()
                .Which.Should().Contain("IssuedNotGeneratedYet=0");
        }
    }
}
