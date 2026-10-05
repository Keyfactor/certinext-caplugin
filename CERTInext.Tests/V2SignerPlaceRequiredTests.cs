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
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
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
    /// Regression tests for issue 0039 (signerPlace): the V2 spec marks SSL create
    /// <c>agreement.signerPlace</c> "Conditional - required if `agreement` sent", and the plugin
    /// always sends <c>agreement</c> on V2 SSL orders but used to drop a blank signerPlace.
    /// V2 connectors now require <c>SignerPlace</c> in <see cref="CERTInextCAPlugin.ValidateCAConnectionInfo"/>
    /// (before any network call), and <c>EnrollV2Async</c> fails fast for an SSL order whose
    /// resolved signer place is blank. V1 and V2 Private PKI (no agreement) are unaffected.
    /// </summary>
    public class V2SignerPlaceRequiredTests
    {
        private static Mock<ICERTInextClient> NewMock() =>
            new Mock<ICERTInextClient>(MockBehavior.Strict);

        private static Dictionary<string, object> V2ConnectionInfo(string apiUrl, object signerPlace)
        {
            var info = new Dictionary<string, object>
            {
                ["UseV2Api"]          = true,
                ["ApiUrl"]            = apiUrl,
                ["OAuthClientId"]     = "my-client",
                ["OAuthClientSecret"] = "my-secret"
            };
            if (signerPlace != null) info["SignerPlace"] = signerPlace;
            return info;
        }

        private static CERTInextConfig V2Config(string signerPlace) => new CERTInextConfig
        {
            UseV2Api          = true,
            ApiUrl            = "https://v2.certinext.io",
            OAuthClientId     = "my-client",
            OAuthClientSecret = "my-secret",
            RequestorName     = "Test User",
            RequestorEmail    = "test@example.com",
            SignerIp          = "1.2.3.4",
            SignerPlace       = signerPlace,
            PickupRetries     = 0
        };

        private static EnrollmentProductInfo SslProductInfo(string templateSignerPlace = null)
        {
            var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ProductCode"]    = "842",
                ["ProductFamily"]  = "ssl",
                ["ProductVariant"] = "dv",
                ["DomainName"]     = "example.com"
            };
            if (templateSignerPlace != null) parameters["SignerPlace"] = templateSignerPlace;
            return new EnrollmentProductInfo { ProductID = Constants.Products.DvSsl, ProductParameters = parameters };
        }

        // ---------------------------------------------------------------------------
        // ValidateCAConnectionInfo
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData(null)]   // key absent
        [InlineData("")]
        [InlineData("   ")]
        public async Task ValidateCAConnectionInfo_V2_BlankSignerPlace_RejectedWithoutAnyHttpCall(string signerPlace)
        {
            // ApiUrl points at a live WireMock server with no stubs: if validation reached the
            // connectivity test, the server would record the token request.
            using var server = WireMockServer.Start();
            var plugin = new CERTInextCAPlugin(NewMock().Object, V2Config("New York"));

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(V2ConnectionInfo(server.Urls[0], signerPlace));

            var ex = await act.Should().ThrowAsync<AnyCAValidationException>();
            ex.Which.Message.Should().Contain("'SignerPlace' is required when UseV2Api is true")
                .And.Contain("Subscriber Agreement");
            server.LogEntries.Should().BeEmpty("the SignerPlace check must run before any network call");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_V2_SignerPlaceSet_Passes()
        {
            using var server = WireMockServer.Start();
            server
                .Given(Request.Create().WithPath("/oauth/token").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2TokenResponseJson()));
            server
                .Given(Request.Create().WithPath("/api/certinext/v2/auth/me").UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2AuthMeJson()));

            var plugin = new CERTInextCAPlugin(NewMock().Object, V2Config("New York"));

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(V2ConnectionInfo(server.Urls[0], "San Francisco, CA"));

            await act.Should().NotThrowAsync();
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_V1_BlankSignerPlace_NotReportedAsError()
        {
            // V1 config that fails for an unrelated reason (no AccountNumber) with SignerPlace
            // blank: the aggregated error list must not name SignerPlace — V1 is unchanged.
            var plugin = new CERTInextCAPlugin(NewMock().Object, V2Config("New York"));
            var info = new Dictionary<string, object>
            {
                ["ApiUrl"]      = "https://v1.certinext.io/emSignHub-API/",
                ["UseV2Api"]    = false,
                ["SignerPlace"] = ""
            };

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            var ex = await act.Should().ThrowAsync<AnyCAValidationException>();
            ex.Which.Message.Should().Contain("AccountNumber").And.NotContain("SignerPlace");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_V1_BlankSignerPlace_Passes()
        {
            using var server = WireMockServer.Start();
            server
                .Given(Request.Create().WithPath("/ValidateCredentials").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody("{\"meta\":{\"status\":\"1\"}}"));

            var plugin = new CERTInextCAPlugin(NewMock().Object, V2Config("New York"));
            var info = new Dictionary<string, object>
            {
                ["ApiUrl"]        = server.Urls[0] + "/",
                ["UseV2Api"]      = false,
                ["AccountNumber"] = "12345",
                ["AuthMode"]      = "AccessKey",
                ["ApiKey"]        = "v1-key",
                ["SignerPlace"]   = ""
            };

            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            await act.Should().NotThrowAsync("V1 does not require SignerPlace");
        }

        // ---------------------------------------------------------------------------
        // EnrollV2Async defence in depth
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        public async Task Enroll_V2Ssl_BlankResolvedSignerPlace_FailsFastWithNoCaCall(string connectorSignerPlace)
        {
            // Strict mock with no setups: any client call (catalog, PlaceOrder, ...) throws.
            var mock = NewMock();
            var plugin = new CERTInextCAPlugin(mock.Object, V2Config(connectorSignerPlace));

            var result = await plugin.Enroll(
                MockCertificateData.FakeCsrPem, "CN=example.com", new Dictionary<string, string[]>(),
                SslProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            result.Status.Should().Be((int)EndEntityStatus.FAILED);
            result.CARequestID.Should().BeEmpty();
            result.StatusMessage.Should().Contain("requires a signer place")
                .And.Contain("No order was placed");
            mock.Verify(c => c.PlaceOrderV2Async(
                It.IsAny<string>(), It.IsAny<string>(), It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()),
                Times.Never);
            mock.VerifyNoOtherCalls();
        }

        [Fact]
        public async Task Enroll_V2Ssl_TemplateSignerPlaceOverridesBlankConnector_SendsTemplateValue()
        {
            var mock = NewMock();
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail>
                {
                    new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true }
                });
            V2CreateSslOrderRequest captured = null;
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(), It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback<string, string, V2CreateSslOrderRequest, CancellationToken>((_, __, req, ___) => captured = req)
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = "ord_sp_001", Status = "pending-csr" });
            mock.Setup(c => c.SubmitCsrV2Async(It.IsAny<string>(), "ord_sp_001", It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), "ord_sp_001", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = "ord_sp_001", Status = "pending-approval" });

            var plugin = new CERTInextCAPlugin(mock.Object, V2Config(""));

            var result = await plugin.Enroll(
                MockCertificateData.FakeCsrPem, "CN=example.com", new Dictionary<string, string[]>(),
                SslProductInfo(templateSignerPlace: "Austin, TX"), RequestFormat.PKCS10, EnrollmentType.New);

            result.Status.Should().NotBe((int)EndEntityStatus.FAILED);
            captured.Should().NotBeNull();
            captured!.Agreement.SignerPlace.Should().Be("Austin, TX");
        }

        [Fact]
        public async Task Enroll_V2PrivatePki_BlankSignerPlace_StillPlacesOrder()
        {
            // Private PKI has no Subscriber Agreement, so a blank SignerPlace must not block it.
            var mock = NewMock();
            mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<V2CreatePrivatePkiOrderRequest>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = "ord_pki_sp", Status = "pending-csr" });
            mock.Setup(c => c.SubmitCsrV2Async(
                    Constants.ApiV2.FamilyPrivatePki, "ord_pki_sp", It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            mock.Setup(c => c.TrackOrderV2Async(Constants.ApiV2.FamilyPrivatePki, "ord_pki_sp", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = "ord_pki_sp", Status = "pending-approval" });

            var plugin = new CERTInextCAPlugin(mock.Object, V2Config(""));
            var productInfo = new EnrollmentProductInfo
            {
                ProductID = Constants.Products.DvSsl,
                ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["ProductFamily"]  = "private-pki",
                    ["ProductVariant"] = "intranet-ssl",
                    ["ProductCode"]    = "149",
                    ["DomainName"]     = "intranet.acme.local"
                }
            };

            var result = await plugin.Enroll(
                MockCertificateData.FakeCsrPem, "CN=intranet.acme.local", new Dictionary<string, string[]>(),
                productInfo, RequestFormat.PKCS10, EnrollmentType.New);

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            result.CARequestID.Should().Be("ord_pki_sp");
            mock.Verify(c => c.PlaceOrderV2Async(
                It.IsAny<string>(), It.IsAny<V2CreatePrivatePkiOrderRequest>(), It.IsAny<CancellationToken>()), Times.Once);
        }
    }
}
