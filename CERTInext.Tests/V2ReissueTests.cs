// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using Moq;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// V2 SSL/TLS reissue through <c>POST /ssl-certificates/{orderId}/reissue</c>, end to end with a real
    /// <see cref="CERTInextClient"/> against WireMock: the <c>rekey</c> body, <c>V2ReissueRevokePrevious</c>,
    /// the derived (non-numeric) order id through Track, Download, GetSingleRecord and Sync, the 404/422
    /// fallback to a new order, no fallback on 5xx, and the paths that never reissue.
    /// </summary>
    public class V2ReissueTests : IDisposable
    {
        private const string PriorOrderId = "1984857369";
        private const string DerivedOrderId = "1984857369R001";
        private const string NewOrderId = "5550001111";
        private const string PriorSerial = "0A1B2C3D";
        private const string SslPath = "/api/certinext/v2/ssl-certificates";
        private const string ReissuePath = SslPath + "/" + PriorOrderId + "/reissue";

        private readonly WireMockServer _server = WireMockServer.Start();

        public V2ReissueTests()
        {
            _server.Given(Request.Create().WithPath("/oauth/token").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2TokenResponseJson()));
            _server.Given(Request.Create().WithPath("/api/certinext/v2/catalog/products").UsingGet())
                .RespondWith(Json(200, "[{\"productCode\":\"842\",\"productTypeID\":\"13\",\"productName\":\"DV SSL\",\"active\":true}]"));
            foreach (var id in new[] { DerivedOrderId, NewOrderId })
            {
                _server.Given(Request.Create().WithPath($"{SslPath}/{id}").UsingGet())
                    .RespondWith(Json(200, MockCertificateData.V2TrackOrderIssuedJson(id)));
                _server.Given(Request.Create().WithPath($"{SslPath}/{id}/certificate").UsingGet())
                    .RespondWith(Json(200, MockCertificateData.V2CertificateDownloadJson(id)));
            }
            _server.Given(Request.Create().WithPath(SslPath).UsingPost())
                .RespondWith(Json(201, MockCertificateData.V2CreateOrderIssuedJson(NewOrderId)));
        }

        public void Dispose() => _server.Stop();

        private static IResponseBuilder Json(int status, string body) =>
            Response.Create().WithStatusCode(status).WithHeader("Content-Type", "application/json").WithBody(body);

        private CERTInextConfig Config(bool revokePrevious = false) => new CERTInextConfig
        {
            ApiUrl                  = _server.Urls[0],
            UseV2Api                = true,
            OAuthClientId           = "my-v2-client",
            OAuthClientSecret       = "my-v2-secret",
            RequestorName           = "Test User",
            RequestorEmail          = "test@example.com",
            SignerPlace             = "New York",
            PickupRetries           = 0,
            DcvEnabled              = false,
            V2ReissueRevokePrevious = revokePrevious
        };

        /// <summary>Reader that maps <see cref="PriorSerial"/> to <see cref="PriorOrderId"/> expiring in <paramref name="expiresInDays"/>.</summary>
        private static Mock<ICertificateDataReader> Reader(int expiresInDays = 200)
        {
            var reader = new Mock<ICertificateDataReader>();
            reader.Setup(r => r.GetRequestIDBySerialNumber(PriorSerial)).ReturnsAsync(PriorOrderId);
            reader.Setup(r => r.GetExpirationDateByRequestId(PriorOrderId)).Returns(DateTime.UtcNow.AddDays(expiresInDays));
            return reader;
        }

        private CERTInextCAPlugin Plugin(Mock<ICertificateDataReader> reader, CERTInextConfig config = null)
        {
            config ??= Config();
            return new CERTInextCAPlugin(new CERTInextClient(config), reader.Object, config);
        }

        private static EnrollmentProductInfo Info(string family = "ssl", string priorSn = PriorSerial, string code = "842")
        {
            var p = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ProductCode"]   = code,
                ["ProductFamily"] = family,
                ["DomainName"]    = family == "private-pki" ? "intranet.example.com" : "example.com",
                ["RenewalWindowDays"] = "30"
            };
            if (family == "private-pki") p["ProductVariant"] = "intranet-ssl";
            if (priorSn != null) p["PriorCertSN"] = priorSn;
            return new EnrollmentProductInfo { ProductID = "DV SSL", ProductParameters = p };
        }

        private static Task<EnrollmentResult> Enroll(CERTInextCAPlugin plugin, EnrollmentType type,
            EnrollmentProductInfo info = null, Dictionary<string, string[]> san = null) =>
            plugin.Enroll(MockCertificateData.FakeCsrPem, "CN=example.com", san ?? new Dictionary<string, string[]>(),
                info ?? Info(), RequestFormat.PKCS10, type);

        private void StubReissue(int status, string body) =>
            _server.Given(Request.Create().WithPath(ReissuePath).UsingPost()).RespondWith(Json(status, body));

        private List<WireMock.Logging.ILogEntry> Posts(string path) =>
            _server.LogEntries.Where(e => e.RequestMessage.Path == path
                && e.RequestMessage.Method.Equals("POST", StringComparison.OrdinalIgnoreCase)).ToList();

        private JsonElement ReissueBody() =>
            JsonDocument.Parse(Posts(ReissuePath).Single().RequestMessage.Body!).RootElement;

        [Fact]
        public async Task Reissue_SendsRekeyGoldenBody_ReturnsDerivedOrderAndCertificate()
        {
            StubReissue(201, $"{{\"orderId\":\"{DerivedOrderId}\",\"status\":\"issued\"}}");

            var result = await Enroll(Plugin(Reader()), EnrollmentType.Reissue);

            result.CARequestID.Should().Be(DerivedOrderId);
            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            result.Certificate.Should().StartWith("-----BEGIN CERTIFICATE-----");
            result.StatusMessage.Should().Contain($"Reissued from CERTInext order {PriorOrderId}");
            Posts(SslPath).Should().BeEmpty("a successful reissue places no new order");

            var expected = JsonSerializer.Serialize(new Dictionary<string, object>
            {
                ["mode"] = "rekey",
                ["reason"] = "Reissued via Keyfactor Command AnyCA REST Gateway.",
                ["csr"] = MockCertificateData.FakeCsrPem,
                ["revokePrevious"] = false
            });
            Posts(ReissuePath).Single().RequestMessage.Body.Should().Be(expected,
                "rekey with the new CSR, no additionalDomains for a single-domain order, and no revokeReason when not revoking");
        }

        [Fact]
        public async Task Reissue_RevokePreviousOn_SendsSuperseded()
        {
            StubReissue(201, $"{{\"orderId\":\"{DerivedOrderId}\",\"status\":\"issued\"}}");

            var result = await Enroll(Plugin(Reader(), Config(revokePrevious: true)), EnrollmentType.Reissue);

            result.CARequestID.Should().Be(DerivedOrderId);
            var body = ReissueBody();
            body.GetProperty("revokePrevious").GetBoolean().Should().BeTrue();
            body.GetProperty("revokeReason").GetString().Should().Be("superseded");
            result.StatusMessage.Should().Contain("revocation of the previous certificate (superseded) was requested");
        }

        [Fact]
        public async Task Reissue_UccOrder_SendsAdditionalDomains()
        {
            StubReissue(201, $"{{\"orderId\":\"{DerivedOrderId}\",\"status\":\"issued\"}}");
            // No ProductCode: extra DNS SANs make the order UCC, the same rule as create.
            var info = Info(code: null);
            info.ProductParameters.Remove("ProductCode");
            var san = new Dictionary<string, string[]> { ["dns"] = new[] { "example.com", "a.example.com", "b.example.com" } };

            await Enroll(Plugin(Reader()), EnrollmentType.Reissue, info, san);

            ReissueBody().GetProperty("additionalDomains").EnumerateArray().Select(e => e.GetString())
                .Should().Equal("a.example.com", "b.example.com");
        }

        [Theory]
        [InlineData(404, "Order not found under this account.")]
        [InlineData(422, "Order is not in issued state.")]
        public async Task Reissue_404Or422_FallsBackToNewOrder_AndSaysSo(int status, string detail)
        {
            StubReissue(status, MockCertificateData.V2ProblemDetailsJson(status, "Rejected", detail, "about:blank"));

            var result = await Enroll(Plugin(Reader()), EnrollmentType.Reissue);

            result.CARequestID.Should().Be(NewOrderId);
            Posts(SslPath).Should().ContainSingle("the fallback places exactly one new order");
            result.StatusMessage.Should().Contain($"CERTInext rejected the reissue of order {PriorOrderId}")
                .And.Contain($"HTTP {status}").And.Contain("a new order was placed");
        }

        [Theory]
        [InlineData(500)]
        [InlineData(503)]
        public async Task Reissue_5xx_DoesNotFallBackOrRetry_SaysDoNotResubmit(int status)
        {
            StubReissue(status, "{}");

            Func<Task> act = () => Enroll(Plugin(Reader()), EnrollmentType.Reissue);

            (await act.Should().ThrowAsync<Exception>()).Which.Message.Should().Contain("do not resubmit");
            Posts(ReissuePath).Should().ContainSingle("a reissue is never retried");
            Posts(SslPath).Should().BeEmpty("the derived order may exist, so no new order is placed");
        }

        [Fact]
        public async Task Reissue_201WithoutOrderId_Throws_DoNotResubmit()
        {
            StubReissue(201, "{\"status\":\"issued\"}");
            Func<Task> act = () => Enroll(Plugin(Reader()), EnrollmentType.Reissue);
            (await act.Should().ThrowAsync<Exception>()).Which.Message.Should().Contain("do not resubmit");
            Posts(SslPath).Should().BeEmpty();
        }

        [Fact]
        public async Task Reissue_NoPriorCertSn_PlacesNewOrder_AndSaysSo()
        {
            var result = await Enroll(Plugin(Reader()), EnrollmentType.Reissue, Info(priorSn: null));

            result.CARequestID.Should().Be(NewOrderId);
            Posts(ReissuePath).Should().BeEmpty();
            result.StatusMessage.Should().Contain("No prior certificate serial number was supplied");
        }

        [Fact]
        public async Task Reissue_PriorOrderNotFoundInGateway_PlacesNewOrder()
        {
            var reader = new Mock<ICertificateDataReader>();
            reader.Setup(r => r.GetRequestIDBySerialNumber(PriorSerial)).ReturnsAsync((string)null);

            var result = await Enroll(Plugin(reader), EnrollmentType.Reissue);

            result.CARequestID.Should().Be(NewOrderId);
            Posts(ReissuePath).Should().BeEmpty();
            result.StatusMessage.Should().Contain("could not be found");
        }

        [Theory]
        [InlineData(200, true)]   // outside the 30-day window: V1's reissue branch
        [InlineData(10, false)]   // inside the window: a renewal, placed as a new order
        [InlineData(-5, false)]   // expired: a new order
        public async Task RenewOrReissue_ReissuesOnlyOutsideRenewalWindow(int expiresInDays, bool expectReissue)
        {
            StubReissue(201, $"{{\"orderId\":\"{DerivedOrderId}\",\"status\":\"issued\"}}");

            var result = await Enroll(Plugin(Reader(expiresInDays)), EnrollmentType.RenewOrReissue);

            result.CARequestID.Should().Be(expectReissue ? DerivedOrderId : NewOrderId);
            Posts(ReissuePath).Should().HaveCount(expectReissue ? 1 : 0);
        }

        [Theory]
        [InlineData(EnrollmentType.New)]
        [InlineData(EnrollmentType.Renew)]
        public async Task NewAndRenew_NeverReissue(EnrollmentType type)
        {
            var result = await Enroll(Plugin(Reader()), type);
            result.CARequestID.Should().Be(NewOrderId);
            Posts(ReissuePath).Should().BeEmpty();
        }

        [Fact]
        public async Task PrivatePki_Reissue_KeepsNewOrderBehaviour()
        {
            const string pkiPath = "/api/certinext/v2/private-pki-certificates";
            _server.Given(Request.Create().WithPath(pkiPath).UsingPost())
                .RespondWith(Json(201, MockCertificateData.V2CreateOrderPendingJson("pki_001")));
            _server.Given(Request.Create().WithPath(pkiPath + "/pki_001/csr").UsingPut())
                .RespondWith(Response.Create().WithStatusCode(200));
            _server.Given(Request.Create().WithPath(pkiPath + "/pki_001").UsingGet())
                .RespondWith(Json(200, MockCertificateData.V2TrackOrderPendingJson("pki_001")));

            var result = await Enroll(Plugin(Reader()), EnrollmentType.Reissue, Info(family: "private-pki", code: "149"));

            result.CARequestID.Should().Be("pki_001");
            _server.LogEntries.Should().NotContain(e => e.RequestMessage.Path.EndsWith("/reissue"),
                "the spec has no Private PKI reissue endpoint");
        }

        [Fact]
        public async Task DerivedOrderId_RoundTripsThroughGetSingleRecordAndSync()
        {
            _server.Given(Request.Create().WithPath("/api/certinext/v2/reports/orders").UsingGet())
                .RespondWith(Json(200, MockCertificateData.V2OrdersReportJson(1, 1, new[] { DerivedOrderId },
                    orderStatus: "Order Fulfilled", certificateStatus: "Certificate Downloaded")));
            var plugin = Plugin(Reader());

            var single = await plugin.GetSingleRecord(DerivedOrderId);
            single.CARequestID.Should().Be(DerivedOrderId);
            single.Status.Should().Be((int)EndEntityStatus.GENERATED);

            var buffer = new BlockingCollection<AnyCAPluginCertificate>(100);
            await plugin.Synchronize(buffer, null, true, CancellationToken.None);
            var synced = buffer.ToArray().Should().ContainSingle().Subject;
            synced.CARequestID.Should().Be(DerivedOrderId);
            synced.Status.Should().Be((int)EndEntityStatus.GENERATED);
            synced.Certificate.Should().StartWith("-----BEGIN CERTIFICATE-----");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_RejectsNonBooleanReissueRevokePrevious()
        {
            var plugin = new CERTInextCAPlugin();
            var info = new Dictionary<string, object>
            {
                ["ApiUrl"] = "https://ca.example.com", ["UseV2Api"] = true,
                ["OAuthClientId"] = "id", ["OAuthClientSecret"] = "secret", ["SignerPlace"] = "NY",
                ["V2ReissueRevokePrevious"] = "sometimes"
            };
            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);
            await act.Should().ThrowAsync<Exception>().WithMessage("*V2ReissueRevokePrevious*must be true or false*");
        }

        [Fact]
        public void Config_ReissueRevokePrevious_DefaultsFalse_AnnotatedAsBoolean()
        {
            new CERTInextConfig().V2ReissueRevokePrevious.Should().BeFalse();
            var a = new CERTInextCAPlugin().GetCAConnectorAnnotations()[Constants.Config.V2ReissueRevokePrevious];
            a.Type.Should().Be("Boolean");
            a.DefaultValue.Should().Be(false);
        }
    }
}
