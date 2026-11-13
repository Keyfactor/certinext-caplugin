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
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// V2 problem+json <c>title</c>/<c>detail</c>/<c>errors[]</c> can echo a submitted value such as an
    /// email address, and ExtractV2ErrorMessage folds that text into the exception message Command
    /// stores. With <c>LogSensitiveRequestData</c> off, email-shaped tokens are masked (via
    /// <c>MaskEmail</c>) and the rest of the text is preserved; with the flag on the text is verbatim.
    /// Mirrors the V1 coverage in <see cref="CaErrorTextMaskingTests"/>. All data is synthetic.
    /// </summary>
    public class V2ErrorTextMaskingTests : IDisposable
    {
        private const string Email = "jane.doe@example.com";
        private const string MaskedEmail = "j***@example.com";
        private const string OrderId = "ord_mask_001";

        private readonly WireMockServer _server = WireMockServer.Start();

        public V2ErrorTextMaskingTests()
        {
            _server
                .Given(Request.Create().WithPath("/oauth/token").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2TokenResponseJson(3600)));
        }

        public void Dispose() => _server.Stop();

        private CERTInextClient BuildClient(bool logSensitiveRequestData) => new CERTInextClient(new CERTInextConfig
        {
            ApiUrl                 = _server.Urls[0],
            AuthMode               = "AccessKey",
            ApiKey                 = "test-v1-key",
            AccountNumber          = "12345",
            UseV2Api               = true,
            OAuthClientId          = "my-v2-client",
            OAuthClientSecret      = "my-v2-secret",
            RequestorName          = "Test User",
            RequestorEmail         = "test@example.com",
            PageSize               = 100,
            GroupNumber            = string.Empty,
            LogSensitiveRequestData = logSensitiveRequestData
        });

        private void StubRevoke(int status, string body) =>
            _server
                .Given(Request.Create()
                    .WithPath($"/api/certinext/v2/ssl-certificates/{OrderId}/revoke").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(status)
                    .WithHeader("Content-Type", "application/problem+json")
                    .WithBody(body));

        private static Task RevokeAsync(CERTInextClient client) =>
            client.RevokeOrderV2Async(Constants.ApiV2.FamilySsl, OrderId, new V2RevokeRequest { Reason = "superseded" });

        [Fact]
        public async Task V2Revoke422_Detail_FlagOff_MasksEmailKeepsRestOfText()
        {
            StubRevoke(422, MockCertificateData.V2ProblemDetailsJson(
                422, "Unprocessable Entity", $"Contact {Email} is not allowed for this order"));

            using var client = BuildClient(logSensitiveRequestData: false);
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => RevokeAsync(client));

            ex.Message.Should().Contain(MaskedEmail)
                .And.Contain("is not allowed for this order")
                .And.NotContain(Email);
        }

        [Fact]
        public async Task V2Revoke422_Detail_FlagOn_IsVerbatim()
        {
            StubRevoke(422, MockCertificateData.V2ProblemDetailsJson(
                422, "Unprocessable Entity", $"Contact {Email} is not allowed for this order"));

            using var client = BuildClient(logSensitiveRequestData: true);
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => RevokeAsync(client));

            ex.Message.Should().Contain(Email);
        }

        [Fact]
        public async Task V2Failure_PerFieldErrors_FlagOff_MasksEmailInFieldMessage()
        {
            string body = "{\"type\":\"EMS-400\",\"title\":\"Bad Request\",\"status\":400,\"detail\":\"Validation failed\","
                + $"\"errors\":[{{\"field\":\"requestor.email\",\"message\":\"{Email} is not a registered user\"}}]}}";
            StubRevoke(400, body);

            using var client = BuildClient(logSensitiveRequestData: false);
            var ex = await Assert.ThrowsAsync<Exception>(() => RevokeAsync(client));

            ex.Message.Should().Contain("requestor.email")
                .And.Contain(MaskedEmail)
                .And.Contain("is not a registered user")
                .And.NotContain(Email);
        }

        [Fact]
        public async Task V2Failure_Forbidden_FlagOff_MasksEmailInHint()
        {
            StubRevoke(403, MockCertificateData.V2ProblemDetailsJson(
                403, "Forbidden", $"User {Email} cannot revoke"));

            using var client = BuildClient(logSensitiveRequestData: false);
            var ex = await Assert.ThrowsAsync<Exception>(() => RevokeAsync(client));

            ex.Message.Should().Contain("HTTP 403")
                .And.Contain(MaskedEmail)
                .And.NotContain(Email);
        }
    }
}
