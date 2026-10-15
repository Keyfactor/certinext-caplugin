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
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// End-to-end (real <see cref="CERTInextClient"/> against WireMock) guards for the V2
    /// single-call enrollment: the CSR goes inline on <c>POST /{family}</c>, the product is pinned
    /// with <c>X-Product-Code</c>, and SSL/TLS never sends <c>PUT .../csr</c> when <c>V2InlineCsr=true</c>
    /// (Private PKI ignores the flag and keeps create + Submit CSR; the default is the two-call flow).
    /// </summary>
    public class V2SingleCallCreateTests : IDisposable
    {
        private const string OrderId = "ord_single_001";
        private const string SslPath = "/api/certinext/v2/ssl-certificates";
        private const string PkiPath = "/api/certinext/v2/private-pki-certificates";

        private readonly WireMockServer _server = WireMockServer.Start();

        public void Dispose() => _server.Stop();

        private CERTInextConfig Config() => new CERTInextConfig
        {
            ApiUrl            = _server.Urls[0],
            UseV2Api          = true,
            OAuthClientId     = "my-v2-client",
            OAuthClientSecret = "my-v2-secret",
            RequestorName     = "Test User",
            RequestorEmail    = "test@example.com",
            SignerIp          = "1.2.3.4",
            SignerPlace       = "New York",
            PickupRetries     = 0,
            // Every test in this class exercises the opt-in single-call flow unless it says otherwise.
            V2InlineCsr       = true
        };

        private CERTInextCAPlugin BuildPlugin(CERTInextConfig config = null)
        {
            config ??= Config();
            return new CERTInextCAPlugin(new CERTInextClient(config), config);
        }

        private void StubToken() =>
            _server.Given(Request.Create().WithPath("/oauth/token").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2TokenResponseJson()));

        private void StubCatalog() =>
            _server.Given(Request.Create().WithPath("/api/certinext/v2/catalog/products").UsingGet())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody("[{\"productCode\":\"842\",\"productTypeID\":\"13\",\"productName\":\"DV SSL\",\"active\":true}]"));

        private void StubCreate(string path, int status, string body) =>
            _server.Given(Request.Create().WithPath(path).UsingPost())
                .RespondWith(Response.Create().WithStatusCode(status)
                    .WithHeader("Content-Type", "application/json").WithBody(body));

        private void StubTrack(string path, string json) =>
            _server.Given(Request.Create().WithPath($"{path}/{OrderId}").UsingGet())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json").WithBody(json));

        private static EnrollmentProductInfo SslProductInfo(string productCode = "842") => new EnrollmentProductInfo
        {
            ProductID = "DV SSL",
            ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ProductCode"]    = productCode,
                ["ProductFamily"]  = "ssl",
                ["ProductVariant"] = "dv",
                ["DomainName"]     = "example.com"
            }
        };

        private static EnrollmentProductInfo PkiProductInfo() => new EnrollmentProductInfo
        {
            ProductID = "DV SSL",
            ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ProductCode"]    = "149",
                ["ProductFamily"]  = "private-pki",
                ["ProductVariant"] = "intranet-ssl",
                ["DomainName"]     = "intranet.example.com"
            }
        };

        private static Task<EnrollmentResult> Enroll(
            CERTInextCAPlugin plugin, EnrollmentProductInfo info, string csr = null,
            EnrollmentType type = EnrollmentType.New, string subject = "CN=example.com") =>
            plugin.Enroll(csr ?? MockCertificateData.FakeCsrPem, subject, new Dictionary<string, string[]>(),
                info, RequestFormat.PKCS10, type);

        private List<WireMock.Logging.ILogEntry> Requests(string method) =>
            _server.LogEntries.Where(e => e.RequestMessage.Method.Equals(method, StringComparison.OrdinalIgnoreCase)).ToList();

        private void AssertNoPutAndNoCsrPath()
        {
            Requests("PUT").Should().BeEmpty("the CSR goes inline on create — Submit CSR no longer exists");
            _server.LogEntries.Should().NotContain(e => e.RequestMessage.Path.EndsWith("/csr", StringComparison.OrdinalIgnoreCase));
        }

        [Theory]
        [InlineData(EnrollmentType.New)]
        [InlineData(EnrollmentType.Reissue)]
        [InlineData(EnrollmentType.RenewOrReissue)]
        public async Task Ssl_CreateReturnsIssued_DownloadsInSameCall_CsrInlineAndProductPinned_NoPut(EnrollmentType type)
        {
            StubToken();
            StubCatalog();
            StubCreate(SslPath, 201, MockCertificateData.V2CreateOrderIssuedJson(OrderId));
            StubTrack(SslPath, MockCertificateData.V2TrackOrderIssuedJson(OrderId));
            _server.Given(Request.Create().WithPath($"{SslPath}/{OrderId}/certificate").UsingGet())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2CertificateDownloadJson(OrderId)));

            var result = await Enroll(BuildPlugin(), SslProductInfo(), type: type);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            result.CARequestID.Should().Be(OrderId);
            result.Certificate.Should().NotBeNullOrWhiteSpace();

            var creates = Requests("POST").Where(e => e.RequestMessage.Path == SslPath).ToList();
            creates.Should().HaveCount(1, "order creation is never retried");
            creates[0].RequestMessage.Headers.Should().ContainKey("X-Product-Code")
                .WhoseValue.Should().Contain("842");
            using var body = JsonDocument.Parse(creates[0].RequestMessage.Body ?? string.Empty);
            body.RootElement.GetProperty("csr").GetString().Should().Be(MockCertificateData.FakeCsrPem,
                "the CSR is sent unchanged, PEM as received");
            AssertNoPutAndNoCsrPath();
        }

        [Fact]
        public async Task Ssl_CreateReturnsPendingApproval_ReturnsPendingWithOrderId_NoPut()
        {
            StubToken();
            StubCatalog();
            StubCreate(SslPath, 201,
                $"{{\"orderId\":\"{OrderId}\",\"requestId\":\"r1\",\"status\":\"pending-approval\"}}");
            StubTrack(SslPath,
                $"{{\"orderId\":\"{OrderId}\",\"requestId\":\"r1\",\"status\":\"pending-approval\",\"productVariant\":\"dv\",\"domain\":\"example.com\"}}");

            var result = await Enroll(BuildPlugin(), SslProductInfo());

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            result.CARequestID.Should().Be(OrderId);
            result.Certificate.Should().BeNull();
            AssertNoPutAndNoCsrPath();
        }

        [Fact]
        public async Task Ssl_IssuedButCertificateNotYetDownloadable_Ems1165_ReturnsPendingNotAnError()
        {
            // Finding 10: right after 'issued' the download can still return 422 EMS-1165. The
            // order exists and carries its CSR, so the enrollment must come back pending with the
            // order id (sync imports the certificate), not throw.
            StubToken();
            StubCatalog();
            StubCreate(SslPath, 201, MockCertificateData.V2CreateOrderIssuedJson(OrderId));
            StubTrack(SslPath, MockCertificateData.V2TrackOrderIssuedJson(OrderId));
            _server.Given(Request.Create().WithPath($"{SslPath}/{OrderId}/certificate").UsingGet())
                .RespondWith(Response.Create().WithStatusCode(422)
                    .WithHeader("Content-Type", "application/problem+json")
                    .WithBody("{\"type\":\"EMS-1165\",\"title\":\"Unprocessable\",\"status\":422,\"detail\":\"certificate not available\"}"));

            var result = await Enroll(BuildPlugin(), SslProductInfo());

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            result.CARequestID.Should().Be(OrderId);
            AssertNoPutAndNoCsrPath();
        }

        [Fact]
        public async Task PrivatePki_FlagOn_IgnoresIt_TwoCall_CreateWithoutCsr_ThenExactlyOnePutCsr_ProductPinned()
        {
            // Private PKI keeps create + Submit CSR (the sandbox rejects an inline csr there with 422);
            // this is the ONLY path in the plugin that sends PUT .../csr.
            StubToken();
            StubCreate(PkiPath, 201,
                $"{{\"orderId\":\"{OrderId}\",\"requestId\":\"r1\",\"status\":\"pending-csr\",\"variant\":\"intranet-ssl\"}}");
            _server.Given(Request.Create().WithPath($"{PkiPath}/{OrderId}/csr").UsingPut())
                .RespondWith(Response.Create().WithStatusCode(204));
            StubTrack(PkiPath,
                $"{{\"orderId\":\"{OrderId}\",\"requestId\":\"r1\",\"status\":\"pending-approval\",\"variant\":\"intranet-ssl\"}}");

            var result = await Enroll(BuildPlugin(), PkiProductInfo(), subject: "CN=intranet.example.com");

            result.CARequestID.Should().Be(OrderId);
            var creates = Requests("POST").Where(e => e.RequestMessage.Path == PkiPath).ToList();
            creates.Should().HaveCount(1);
            creates[0].RequestMessage.Headers.Should().ContainKey("X-Product-Code").WhoseValue.Should().Contain("149");
            using var body = JsonDocument.Parse(creates[0].RequestMessage.Body ?? string.Empty);
            body.RootElement.TryGetProperty("csr", out _).Should().BeFalse("Private PKI create carries no inline csr");

            var puts = Requests("PUT");
            puts.Should().HaveCount(1, "Private PKI submits the CSR exactly once, never retried");
            puts[0].RequestMessage.Path.Should().Be($"{PkiPath}/{OrderId}/csr");
            using var putBody = JsonDocument.Parse(puts[0].RequestMessage.Body ?? string.Empty);
            putBody.RootElement.GetProperty("csr").GetString().Should().Be(MockCertificateData.FakeCsrPem);
        }

        [Fact]
        public async Task Ssl_DefaultConfig_TwoCall_CreateWithoutCsr_ThenExactlyOnePutCsr()
        {
            // V2InlineCsr defaults to false: SSL/TLS behaves as before — create without csr, then PUT .../csr.
            StubToken();
            StubCatalog();
            StubCreate(SslPath, 201,
                $"{{\"orderId\":\"{OrderId}\",\"requestId\":\"r1\",\"status\":\"pending-csr\"}}");
            _server.Given(Request.Create().WithPath($"{SslPath}/{OrderId}/csr").UsingPut())
                .RespondWith(Response.Create().WithStatusCode(204));
            StubTrack(SslPath,
                $"{{\"orderId\":\"{OrderId}\",\"requestId\":\"r1\",\"status\":\"pending-approval\",\"productVariant\":\"dv\",\"domain\":\"example.com\"}}");
            var config = Config();
            config.V2InlineCsr = false;

            var result = await Enroll(BuildPlugin(config), SslProductInfo());

            result.CARequestID.Should().Be(OrderId);
            var creates = Requests("POST").Where(e => e.RequestMessage.Path == SslPath).ToList();
            creates.Should().HaveCount(1);
            creates[0].RequestMessage.Headers.Should().ContainKey("X-Product-Code").WhoseValue.Should().Contain("842");
            using var body = JsonDocument.Parse(creates[0].RequestMessage.Body ?? string.Empty);
            body.RootElement.TryGetProperty("csr", out _).Should().BeFalse("the default create carries no inline csr");
            var puts = Requests("PUT");
            puts.Should().HaveCount(1);
            puts[0].RequestMessage.Path.Should().Be($"{SslPath}/{OrderId}/csr");
        }

        [Fact]
        public async Task Ssl_DefaultConfig_CsrRejected_CancelsOrphanedOrderOnce()
        {
            StubToken();
            StubCatalog();
            StubCreate(SslPath, 201,
                $"{{\"orderId\":\"{OrderId}\",\"requestId\":\"r1\",\"status\":\"pending-csr\"}}");
            _server.Given(Request.Create().WithPath($"{SslPath}/{OrderId}/csr").UsingPut())
                .RespondWith(Response.Create().WithStatusCode(400)
                    .WithHeader("Content-Type", "application/problem+json")
                    .WithBody("{\"title\":\"Bad Request\",\"status\":400,\"detail\":\"bad csr\"}"));
            _server.Given(Request.Create().WithPath($"{SslPath}/{OrderId}/cancel").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(204));
            var config = Config();
            config.V2InlineCsr = false;

            var result = await Enroll(BuildPlugin(config), SslProductInfo());

            result.Status.Should().Be((int)EndEntityStatus.FAILED);
            result.CARequestID.Should().Be(OrderId);
            Requests("PUT").Should().HaveCount(1, "Submit CSR is never retried");
            Requests("POST").Count(e => e.RequestMessage.Path == $"{SslPath}/{OrderId}/cancel").Should().Be(1);
        }

        [Fact]
        public async Task Ssl_Create5xx_ThrowsDoNotResubmitMessage_NoRetry_NoTrack_NoPut()
        {
            StubToken();
            StubCatalog();
            StubCreate(SslPath, 500, "{\"title\":\"Internal Server Error\",\"status\":500}");

            Func<Task> act = () => Enroll(BuildPlugin(), SslProductInfo());

            (await act.Should().ThrowAsync<Exception>())
                .WithMessage("*next synchronization*do not resubmit*");
            Requests("POST").Count(e => e.RequestMessage.Path == SslPath).Should().Be(1, "create is non-idempotent: never retried");
            Requests("GET").Should().NotContain(e => e.RequestMessage.Path.StartsWith(SslPath + "/"),
                "no order id was returned, so there is nothing to track");
            AssertNoPutAndNoCsrPath();
        }

        [Fact]
        public async Task Ssl_Create2xxWithEmptyBody_ThrowsDoNotResubmitMessage_NoRetry()
        {
            // The CA accepted the create but we cannot read the order id: the order exists with its
            // inline CSR, so the message must steer the operator away from resubmitting.
            StubToken();
            StubCatalog();
            _server.Given(Request.Create().WithPath(SslPath).UsingPost())
                .RespondWith(Response.Create().WithFault(FaultType.EMPTY_RESPONSE));

            Func<Task> act = () => Enroll(BuildPlugin(), SslProductInfo());

            (await act.Should().ThrowAsync<Exception>())
                .WithMessage("*next synchronization*do not resubmit*");
            Requests("POST").Count(e => e.RequestMessage.Path == SslPath).Should().Be(1);
            AssertNoPutAndNoCsrPath();
        }

        [Fact]
        public async Task Client_CreateWithNoHttpStatus_TransportFailure_ThrowsDoNotResubmitMessage()
        {
            // No HTTP status at all (timeout / refused / dropped connection) is the same "created but we
            // never heard back" case as a 5xx. Prime the token cache, then take the server away.
            StubToken();
            _server.Given(Request.Create().WithPath("/api/certinext/v2/auth/me").UsingGet())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json").WithBody(MockCertificateData.V2AuthMeJson()));
            using var client = new CERTInextClient(Config());
            await client.GetAuthMeV2Async();
            _server.Stop();

            Func<Task> act = () => client.PlaceOrderV2Async(
                Constants.ApiV2.FamilySsl, "842",
                new API.V2.V2CreateSslOrderRequest
                {
                    Requestor    = new API.V2.V2Requestor { Name = "T", Email = "t@t.com" },
                    Certificate  = new API.V2.V2CertificateParams { Domain = "example.com" },
                    Subscription = new API.V2.V2SubscriptionParams(),
                    Csr          = MockCertificateData.FakeCsrPem
                });

            (await act.Should().ThrowAsync<Exception>())
                .WithMessage("*next synchronization*do not resubmit*");
        }

        [Fact]
        public async Task Ssl_Create4xx_KeepsDefiniteRejectionMessage_NotTheDoNotResubmitWording()
        {
            StubToken();
            StubCatalog();
            StubCreate(SslPath, 422,
                "{\"type\":\"EMS-1\",\"title\":\"Unprocessable\",\"status\":422,\"detail\":\"bad csr\"}");

            Func<Task> act = () => Enroll(BuildPlugin(), SslProductInfo());

            var ex = await act.Should().ThrowAsync<Exception>();
            ex.Which.Message.Should().Contain("HTTP 422").And.NotContain("do not resubmit");
            AssertNoPutAndNoCsrPath();
        }

        [Fact]
        public async Task Ssl_DefaultConfig_Create5xx_DoesNotUseDoNotResubmitMessage_NoRetry_NoPut()
        {
            // Two-call mode: an order created behind a lost response has no CSR and never issues, so the
            // inline-only "do not resubmit; the next sync imports it" message would be wrong (af036ae behaviour).
            StubToken();
            StubCatalog();
            StubCreate(SslPath, 500, "{\"title\":\"Internal Server Error\",\"status\":500}");
            var config = Config();
            config.V2InlineCsr = false;

            Func<Task> act = () => Enroll(BuildPlugin(config), SslProductInfo());

            var ex = await act.Should().ThrowAsync<Exception>();
            ex.Which.Message.Should().NotContain("do not resubmit").And.NotContain("next synchronization");
            Requests("POST").Count(e => e.RequestMessage.Path == SslPath).Should().Be(1, "create is non-idempotent: never retried");
            Requests("PUT").Should().BeEmpty("no order id came back, so there is no CSR to submit");
        }

        [Fact]
        public async Task Ssl_DefaultConfig_Create2xxUnreadableBody_DoesNotUseDoNotResubmitMessage()
        {
            StubToken();
            StubCatalog();
            StubCreate(SslPath, 201, "this is not json");
            var config = Config();
            config.V2InlineCsr = false;

            Func<Task> act = () => Enroll(BuildPlugin(config), SslProductInfo());

            var ex = await act.Should().ThrowAsync<Exception>();
            ex.Which.Message.Should().NotContain("do not resubmit").And.NotContain("next synchronization");
            Requests("POST").Count(e => e.RequestMessage.Path == SslPath).Should().Be(1);
            Requests("PUT").Should().BeEmpty();
        }

        [Fact]
        public async Task Ssl_InlineMode_Create2xxUnreadableBody_ThrowsDoNotResubmitMessage()
        {
            StubToken();
            StubCatalog();
            StubCreate(SslPath, 201, "this is not json");

            Func<Task> act = () => Enroll(BuildPlugin(), SslProductInfo());

            (await act.Should().ThrowAsync<Exception>())
                .WithMessage("*most likely created*next synchronization*do not resubmit*");
            Requests("POST").Count(e => e.RequestMessage.Path == SslPath).Should().Be(1);
            AssertNoPutAndNoCsrPath();
        }

        [Fact]
        public async Task PrivatePki_FlagOn_Create5xx_DoesNotUseDoNotResubmitMessage()
        {
            // The flag is ignored for Private PKI (always two-call), so the inline-only wording must not appear.
            StubToken();
            StubCreate(PkiPath, 500, "{\"title\":\"Internal Server Error\",\"status\":500}");

            Func<Task> act = () => Enroll(BuildPlugin(), PkiProductInfo(), subject: "CN=intranet.example.com");

            var ex = await act.Should().ThrowAsync<Exception>();
            ex.Which.Message.Should().NotContain("do not resubmit").And.NotContain("next synchronization");
            Requests("POST").Count(e => e.RequestMessage.Path == PkiPath).Should().Be(1, "create is never retried");
            Requests("PUT").Should().BeEmpty("no order id came back, so there is no CSR to submit");
        }

        [Fact]
        public async Task PrivatePki_FlagOn_Create2xxUnreadableBody_DoesNotUseDoNotResubmitMessage()
        {
            StubToken();
            StubCreate(PkiPath, 201, "this is not json");

            Func<Task> act = () => Enroll(BuildPlugin(), PkiProductInfo(), subject: "CN=intranet.example.com");

            var ex = await act.Should().ThrowAsync<Exception>();
            ex.Which.Message.Should().NotContain("do not resubmit").And.NotContain("next synchronization");
            Requests("PUT").Should().BeEmpty();
        }

        [Fact]
        public async Task Client_DefaultConfig_CreateWithNoHttpStatus_DoesNotUseDoNotResubmitMessage()
        {
            // Same transport failure as Client_CreateWithNoHttpStatus_TransportFailure_..., but in two-call mode.
            StubToken();
            _server.Given(Request.Create().WithPath("/api/certinext/v2/auth/me").UsingGet())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json").WithBody(MockCertificateData.V2AuthMeJson()));
            var config = Config();
            config.V2InlineCsr = false;
            using var client = new CERTInextClient(config);
            await client.GetAuthMeV2Async();
            _server.Stop();

            Func<Task> act = () => client.PlaceOrderV2Async(
                Constants.ApiV2.FamilySsl, "842",
                new API.V2.V2CreateSslOrderRequest
                {
                    Requestor    = new API.V2.V2Requestor { Name = "T", Email = "t@t.com" },
                    Certificate  = new API.V2.V2CertificateParams { Domain = "example.com" },
                    Subscription = new API.V2.V2SubscriptionParams()
                });

            var ex = await act.Should().ThrowAsync<Exception>();
            ex.Which.Message.Should().NotContain("do not resubmit").And.NotContain("next synchronization");
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public async Task Ssl_BlankCsr_FailsBeforeAnyRequest(string csr)
        {
            var result = await plugin_Enroll(csr);

            result.Status.Should().Be((int)EndEntityStatus.FAILED);
            result.StatusMessage.Should().Contain("no CSR").And.Contain("No order was placed");
            _server.LogEntries.Should().BeEmpty("a blank CSR must be rejected before any CA call");

            Task<EnrollmentResult> plugin_Enroll(string c) =>
                BuildPlugin().Enroll(c, "CN=example.com", new Dictionary<string, string[]>(), SslProductInfo(),
                    RequestFormat.PKCS10, EnrollmentType.New);
        }

        [Fact]
        public async Task Ssl_WhitespaceProductCode_ResolvesFromCatalog_CreateStillPinned()
        {
            // A whitespace ProductCode is treated as unset and resolved from the live catalog; the
            // create must still carry X-Product-Code (never the unpinned 917 auto-resolution).
            StubToken();
            StubCatalog();
            StubCreate(SslPath, 201,
                $"{{\"orderId\":\"{OrderId}\",\"requestId\":\"r1\",\"status\":\"pending-approval\"}}");
            StubTrack(SslPath,
                $"{{\"orderId\":\"{OrderId}\",\"requestId\":\"r1\",\"status\":\"pending-approval\",\"productVariant\":\"dv\",\"domain\":\"example.com\"}}");

            await Enroll(BuildPlugin(), SslProductInfo(productCode: "   "));

            var create = Requests("POST").Single(e => e.RequestMessage.Path == SslPath);
            create.RequestMessage.Headers.Should().ContainKey("X-Product-Code").WhoseValue.Should().Contain("842");
        }
    }
}
