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
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using Moq;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// An SSL/TLS order that Track Order shows at <c>pending-agreement</c> is waiting for the
    /// Subscriber Agreement ("the CA will not release the certificate until this is done"). The plugin
    /// calls <c>POST /ssl-certificates/{orderId}/agreement</c> once per order per enroll call or sync
    /// pass, with the same resolved signer values as create, audit-logs the intent first, and never
    /// fails the enrollment or sync when the call fails.
    /// </summary>
    [Collection(LoggingStateCollection.Name)]
    public class V2AgreementAcceptTests : IDisposable
    {
        private const string OrderId = "ord_agr_001";
        private const string SignerNameValue = "Jordan Signer-Placeholder";
        private const string SignerPlaceValue = "Springfield";

        private readonly WireMockServer _server = WireMockServer.Start();
        public void Dispose() => _server.Stop();

        // ---------------------------------------------------------------------------
        // Client (WireMock): wire shape
        // ---------------------------------------------------------------------------

        private CERTInextClient BuildClient() => new CERTInextClient(new CERTInextConfig
        {
            ApiUrl            = _server.Urls[0],
            UseV2Api          = true,
            OAuthClientId     = "my-v2-client",
            OAuthClientSecret = "my-v2-secret",
            RequestorName     = "Test User",
            RequestorEmail    = "test@example.com",
            PageSize          = 100
        });

        private void StubToken() =>
            _server.Given(Request.Create().WithPath("/oauth/token").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2TokenResponseJson(3600)));

        [Fact]
        public async Task AcceptAgreementV2Async_PostsTheSpecBodyToTheSslAgreementPath()
        {
            StubToken();
            _server.Given(Request.Create().WithPath($"/api/certinext/v2/ssl-certificates/{OrderId}/agreement").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json").WithBody("{}"));

            using var client = BuildClient();
            await client.AcceptAgreementV2Async(Constants.ApiV2.FamilySsl, OrderId,
                new V2AgreementParams { SignerName = SignerNameValue, SignerPlace = SignerPlaceValue, Accepted = true });

            var entry = _server.LogEntries.Single(e => e.RequestMessage.Path.EndsWith("/agreement"));
            entry.RequestMessage.Method.Should().Be("POST");
            using var doc = JsonDocument.Parse(entry.RequestMessage.Body!);
            var root = doc.RootElement;
            root.EnumerateObject().Select(p => p.Name).Should().Equal("agreement");
            var agreement = root.GetProperty("agreement");
            agreement.GetProperty("signerName").GetString().Should().Be(SignerNameValue);
            agreement.GetProperty("signerPlace").GetString().Should().Be(SignerPlaceValue);
            agreement.GetProperty("accepted").GetBoolean().Should().BeTrue();
            agreement.EnumerateObject().Select(p => p.Name).Should().BeEquivalentTo(
                new[] { "signerName", "signerPlace", "accepted" }, "the AgreementAcceptRequest schema has exactly these members (no signerIp)");
        }

        [Theory]
        [InlineData(Constants.ApiV2.FamilyPrivatePki)]
        [InlineData(Constants.ApiV2.FamilySignature)]
        public async Task AcceptAgreementV2Async_NonSslFamily_ThrowsBeforeAnyRequest(string family)
        {
            using var client = BuildClient();
            Func<Task> act = () => client.AcceptAgreementV2Async(family, OrderId,
                new V2AgreementParams { SignerName = "A", SignerPlace = "B", Accepted = true });

            await act.Should().ThrowAsync<ArgumentException>();
            _server.LogEntries.Should().BeEmpty();
        }

        [Fact]
        public async Task AcceptAgreementV2Async_CaRejection_Throws()
        {
            StubToken();
            _server.Given(Request.Create().WithPath($"/api/certinext/v2/ssl-certificates/{OrderId}/agreement").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(422)
                    .WithHeader("Content-Type", "application/problem+json")
                    .WithBody("{\"title\":\"Unprocessable Entity\",\"status\":422,\"detail\":\"not in a state to accept\"}"));

            using var client = BuildClient();
            Func<Task> act = () => client.AcceptAgreementV2Async(Constants.ApiV2.FamilySsl, OrderId,
                new V2AgreementParams { SignerName = "A", SignerPlace = "B", Accepted = true });

            await act.Should().ThrowAsync<Exception>().WithMessage("*HTTP 422*");
        }

        // ---------------------------------------------------------------------------
        // Enroll
        // ---------------------------------------------------------------------------

        private static CERTInextConfig Config(int pickupRetries = 0, string signerPlace = SignerPlaceValue,
            string requestorName = "Connector Requestor") => new CERTInextConfig
        {
            UseV2Api             = true,
            ApiUrl               = "https://v2.certinext.io",
            OAuthClientId        = "my-client",
            OAuthClientSecret    = "my-secret",
            RequestorName        = requestorName,
            RequestorEmail       = "test@example.com",
            SignerPlace          = signerPlace,
            PickupRetries        = pickupRetries,
            PickupDelayInSeconds = 1
        };

        private static Mock<ICERTInextClient> NewOrderMock(string family, string trackStatus)
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            if (family == Constants.ApiV2.FamilySsl)
            {
                mock.Setup(c => c.PlaceOrderV2Async(
                        It.IsAny<string>(), It.IsAny<string>(),
                        It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new V2CreateOrderResponse { OrderId = OrderId, Status = "pending-csr" });
            }
            else
            {
                mock.Setup(c => c.PlaceOrderV2Async(
                        It.IsAny<string>(), It.IsAny<V2CreatePrivatePkiOrderRequest>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new V2CreateOrderResponse { OrderId = OrderId, Status = "pending-csr" });
            }
            mock.Setup(c => c.SubmitCsrV2Async(family, OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.TrackOrderV2Async(family, OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = trackStatus });
            return mock;
        }

        private static Task<EnrollmentResult> EnrollAsync(
            CERTInextCAPlugin plugin, string family = Constants.ApiV2.FamilySsl, string signerName = null)
        {
            var p = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ProductFamily"] = family == Constants.ApiV2.FamilySsl ? "ssl" : "private-pki",
                ["DomainName"]    = "example.com"
            };
            if (family != Constants.ApiV2.FamilySsl) p["ProductVariant"] = "intranet-ssl";
            if (signerName != null) p["SignerName"] = signerName;
            return plugin.Enroll(MockCertificateData.FakeCsrPem, "CN=example.com",
                new Dictionary<string, string[]> { ["dnsname"] = new[] { "example.com" } },
                new EnrollmentProductInfo { ProductID = Constants.Products.DvSsl, ProductParameters = p },
                RequestFormat.PKCS10, EnrollmentType.New);
        }

        [Fact]
        public async Task Enroll_PendingAgreement_AcceptsOncePerCall_WithTheCreateSignerValues_AndAuditsFirst()
        {
            using var capture = new PluginLogCapture();
            var mock = NewOrderMock(Constants.ApiV2.FamilySsl, "pending-agreement");
            V2AgreementParams sent = null;
            int calls = 0;
            mock.Setup(c => c.AcceptAgreementV2Async(Constants.ApiV2.FamilySsl, OrderId, It.IsAny<V2AgreementParams>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2AgreementParams, CancellationToken>((_, __, a, ___) => { sent = a; calls++; })
                .Returns(Task.CompletedTask);
            // Two pickup polls also observe pending-agreement: still only ONE accept call for the order.
            var plugin = new CERTInextCAPlugin(mock.Object, Config(pickupRetries: 2));

            var result = await EnrollAsync(plugin, signerName: SignerNameValue);

            calls.Should().Be(1, "the acceptance is attempted at most once per order per enroll call");
            sent.Should().NotBeNull();
            sent!.SignerName.Should().Be(SignerNameValue, "a template SignerName overrides the requestor default, as on create");
            sent.SignerPlace.Should().Be(SignerPlaceValue);
            sent.Accepted.Should().BeTrue();
            result.CARequestID.Should().Be(OrderId);
            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);

            var all = capture.Entries.Select(e => e.Message).ToList();
            int started = all.FindIndex(m => m.Contains("Subscriber Agreement acceptance attempt started"));
            int accepted = all.FindIndex(m => m.Contains("Subscriber Agreement accepted."));
            started.Should().BeGreaterOrEqualTo(0);
            accepted.Should().BeGreaterThan(started, "the intent is audit-logged before the call");
            all[started].Should().Contain(OrderId).And.Contain("pending-agreement");
            all.Should().NotContain(m => m.Contains(SignerNameValue) || m.Contains(SignerPlaceValue),
                "the signer's name and place are personal data, withheld unless LogSensitiveRequestData is on");
        }

        [Fact]
        public async Task Enroll_PendingAgreement_AcceptFailure_WarnsAndStillReturnsThePendingOrder()
        {
            using var capture = new PluginLogCapture();
            var mock = NewOrderMock(Constants.ApiV2.FamilySsl, "pending-agreement");
            mock.Setup(c => c.AcceptAgreementV2Async(Constants.ApiV2.FamilySsl, OrderId, It.IsAny<V2AgreementParams>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("CERTInext V2 API error during 'V2 accept agreement'. HTTP 500. boom"));
            var plugin = new CERTInextCAPlugin(mock.Object, Config());

            var result = await EnrollAsync(plugin);

            result.CARequestID.Should().Be(OrderId);
            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            capture.Lines(LogLevel.Warning, "Subscriber Agreement acceptance failed").Should().ContainSingle()
                .Which.Should().Contain(OrderId);
        }

        [Theory]
        [InlineData("pending-dcv")]
        [InlineData("pending-approval")]
        [InlineData("issued")]
        public async Task Enroll_OtherStatuses_NeverCallAcceptAgreement(string status)
        {
            var mock = NewOrderMock(Constants.ApiV2.FamilySsl, status);
            if (status == "issued")
                mock.Setup(c => c.DownloadCertificateV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new V2CertificateDownloadResponse { OrderId = OrderId, CertificatePem = MockCertificateData.FakePemCertificate });
            var plugin = new CERTInextCAPlugin(mock.Object, Config());

            await EnrollAsync(plugin);

            mock.Verify(c => c.AcceptAgreementV2Async(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<V2AgreementParams>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Enroll_PrivatePki_PendingAgreement_NeverCallsAcceptAgreement()
        {
            var mock = NewOrderMock(Constants.ApiV2.FamilyPrivatePki, "pending-agreement");
            var plugin = new CERTInextCAPlugin(mock.Object, Config());

            await EnrollAsync(plugin, Constants.ApiV2.FamilyPrivatePki);

            mock.Verify(c => c.AcceptAgreementV2Async(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<V2AgreementParams>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        // ---------------------------------------------------------------------------
        // Synchronize
        // ---------------------------------------------------------------------------

        private static async IAsyncEnumerable<OrderReportEntryV2> Rows(params OrderReportEntryV2[] rows)
        {
            foreach (var r in rows) yield return r;
            await Task.CompletedTask;
        }

        private static OrderReportEntryV2 PendingRow(string id, string domain = "example.com") => new OrderReportEntryV2
        {
            OrderNumber       = id,
            OrderStatus       = "Order Accepted",
            CertificateStatus = "Pending for Approver",
            DomainName        = domain,
            OrderDate         = DateTime.UtcNow.AddHours(-1).ToString("o")
        };

        [Fact]
        public async Task Synchronize_PendingAgreementOrder_AcceptedOncePerPass_WithConnectorSignerValues()
        {
            using var capture = new PluginLogCapture();
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            // The same order listed twice in one pass: still a single acceptance.
            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(Rows(PendingRow(OrderId), PendingRow(OrderId)));
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse { OrderId = OrderId, Status = "pending-agreement" }));
            V2AgreementParams sent = null;
            mock.Setup(c => c.AcceptAgreementV2Async(Constants.ApiV2.FamilySsl, OrderId, It.IsAny<V2AgreementParams>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2AgreementParams, CancellationToken>((_, __, a, ___) => sent = a)
                .Returns(Task.CompletedTask);
            var plugin = new CERTInextCAPlugin(mock.Object, Config());
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            mock.Verify(c => c.AcceptAgreementV2Async(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<V2AgreementParams>(), It.IsAny<CancellationToken>()), Times.Once);
            sent.Should().NotBeNull();
            sent!.SignerName.Should().Be("Connector Requestor");
            sent.SignerPlace.Should().Be(SignerPlaceValue);
            capture.Lines(LogLevel.Information, "acceptance attempt started").Should().ContainSingle();
            buffer.Count.Should().Be(2, "the rows are still emitted as pending; acceptance only nudges the CA");
        }

        [Fact]
        public async Task Synchronize_AcceptFailure_DoesNotFailTheSync()
        {
            using var capture = new PluginLogCapture();
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(Rows(PendingRow(OrderId)));
            mock.Setup(c => c.ResolveAndTrackOrderV2WithFamilyAsync(OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync((Constants.ApiV2.FamilySsl, new V2OrderStatusResponse { OrderId = OrderId, Status = "pending-agreement" }));
            mock.Setup(c => c.AcceptAgreementV2Async(Constants.ApiV2.FamilySsl, OrderId, It.IsAny<V2AgreementParams>(), It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("HTTP 500"));
            var plugin = new CERTInextCAPlugin(mock.Object, Config());
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            Func<Task> act = () => plugin.Synchronize(buffer, null, true, CancellationToken.None);

            await act.Should().NotThrowAsync();
            buffer.Should().ContainSingle().Which.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            capture.Lines(LogLevel.Warning, "Subscriber Agreement acceptance failed").Should().ContainSingle();
        }

        [Fact]
        public async Task Synchronize_NoSignerConfigured_MakesNoExtraCalls()
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(Rows(PendingRow(OrderId)));
            var plugin = new CERTInextCAPlugin(mock.Object, Config(signerPlace: ""));
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            buffer.Count.Should().Be(1);
            mock.Verify(c => c.ResolveAndTrackOrderV2WithFamilyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Synchronize_PendingRowWithoutDomain_NonSslFamily_IsNotTracked()
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            mock.Setup(c => c.ListOrdersV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(Rows(PendingRow(OrderId, domain: "")));
            var plugin = new CERTInextCAPlugin(mock.Object, Config());
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);

            await plugin.Synchronize(buffer, null, true, CancellationToken.None);

            buffer.Count.Should().Be(1);
            mock.Verify(c => c.ResolveAndTrackOrderV2WithFamilyAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }
    }
}
