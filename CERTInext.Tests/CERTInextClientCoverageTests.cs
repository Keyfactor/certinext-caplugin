// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Group B WireMock tests: auth-failure branches and OAuth2 error conditions in
    /// <see cref="CERTInextClient"/>.
    ///
    /// All CERTInext API endpoints use HTTP POST with the endpoint name appended
    /// directly to the base URL. Responses use a "meta" block with status "1"/"0".
    /// </summary>
    public class CERTInextClientCoverageTests : IDisposable
    {
        private readonly WireMockServer _server;
        private readonly string _baseUrl;

        public CERTInextClientCoverageTests()
        {
            _server = WireMockServer.Start();
            _baseUrl = _server.Urls[0];
        }

        public void Dispose()
        {
            _server.Stop();
        }

        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

        private CERTInextClient BuildClient(string authMode = "AccessKey", string apiKey = "test-key") =>
            new CERTInextClient(new CERTInextConfig
            {
                ApiUrl = _baseUrl,
                AuthMode = authMode,
                ApiKey = apiKey,
                AccountNumber = "12345",
                RequestorName = "Test User",
                RequestorEmail = "test@example.com",
                PageSize = 100
            });

        private CERTInextClient BuildOAuthClient(string tokenUrl) =>
            new CERTInextClient(new CERTInextConfig
            {
                ApiUrl = _baseUrl,
                AuthMode = "OAuth",
                OAuthTokenUrl = tokenUrl,
                OAuthClientId = "my-client",
                OAuthClientSecret = "my-secret",
                AccountNumber = "12345",
                RequestorName = "Test User",
                RequestorEmail = "test@example.com",
                PageSize = 100
            });

        // ---------------------------------------------------------------------------
        // B1a: PingAsync throws on 401 (POST /ValidateCredentials)
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task PingAsync_Throws_On401()
        {
            _server
                .Given(Request.Create().WithPath("/ValidateCredentials").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(401)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.UnauthorizedJson()));

            var client = BuildClient(apiKey: "bad-key");

            Func<Task> act = () => client.PingAsync();

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("*health check failed*");
        }

        // ---------------------------------------------------------------------------
        // B1b: PingAsync throws on 403
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task PingAsync_Throws_On403()
        {
            _server
                .Given(Request.Create().WithPath("/ValidateCredentials").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(403)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(@"{""error"":""FORBIDDEN"",""message"":""Access denied.""}"));

            var client = BuildClient(apiKey: "restricted-key");

            Func<Task> act = () => client.PingAsync();

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("*health check failed*");
        }

        // ---------------------------------------------------------------------------
        // B2a: GetCertificateAsync throws on 401 during TrackOrder
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task GetCertificateAsync_Throws_On401()
        {
            _server
                .Given(Request.Create().WithPath("/TrackOrder").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(401)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.UnauthorizedJson()));

            var client = BuildClient(apiKey: "bad-key");

            Func<Task> act = () => client.GetCertificateAsync(MockCertificateData.OrderNumber1);

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("*Authentication failure*");
        }

        // ---------------------------------------------------------------------------
        // B3a: RevokeCertificateAsync throws on 401 during RevokeOrder
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task RevokeCertificateAsync_Throws_On401()
        {
            _server
                .Given(Request.Create().WithPath("/RevokeOrder").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(401)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.UnauthorizedJson()));

            var client = BuildClient(apiKey: "bad-key");
            var revokeReq = new RevokeCertificateRequest { Reason = "unspecified" };

            Func<Task> act = () => client.RevokeCertificateAsync(MockCertificateData.OrderNumber1, revokeReq);

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("*authentication failure*");
        }

        // ---------------------------------------------------------------------------
        // B4a: RenewCertificateAsync throws on 401 during TrackOrder of prior order
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task RenewCertificateAsync_Throws_On401()
        {
            _server
                .Given(Request.Create().WithPath("/TrackOrder").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(401)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.UnauthorizedJson()));

            var client = BuildClient(apiKey: "bad-key");
            var renewReq = new RenewCertificateRequest { Csr = MockCertificateData.FakeCsrPem };

            Func<Task> act = () => client.RenewCertificateAsync(MockCertificateData.OrderNumber1, renewReq);

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("*Authentication failure*");
        }

        // ---------------------------------------------------------------------------
        // B5a: ListCertificatesAsync throws on 401 during GetOrderReport
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task ListCertificatesAsync_Throws_On401()
        {
            _server
                .Given(Request.Create().WithPath("/GetOrderReport").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(401)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.UnauthorizedJson()));

            var client = BuildClient(apiKey: "bad-key");

            Func<Task> act = async () =>
            {
                await foreach (var _ in client.ListCertificatesAsync())
                {
                    // consume the stream; exception should propagate
                }
            };

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("*Authentication failure*");
        }

        // ---------------------------------------------------------------------------
        // B6a: GetProfilesAsync throws on 401 during GetProductDetails
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task GetProfilesAsync_Throws_On401()
        {
            _server
                .Given(Request.Create().WithPath("/GetProductDetails").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(401)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.UnauthorizedJson()));

            var client = BuildClient(apiKey: "bad-key");

            Func<Task> act = () => client.GetProfilesAsync();

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("*Authentication failure*");
        }

        // ---------------------------------------------------------------------------
        // B7a: EnrollCertificateAsync throws when GenerateOrderSSL returns empty body
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task EnrollCertificateAsync_Throws_OnEmptyResponseBody()
        {
            _server
                .Given(Request.Create().WithPath("/GenerateOrderSSL").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(string.Empty));

            var client = BuildClient();
            var req = new EnrollCertificateRequest
            {
                ProfileId = MockCertificateData.ProfileIdTls,
                Csr = MockCertificateData.FakeCsrPem
            };

            Func<Task> act = () => client.EnrollCertificateAsync(req);

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("*empty body*");
        }

        // ---------------------------------------------------------------------------
        // B8a: RevokeCertificateAsync uses safe generic message when body is plain text
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task RevokeCertificateAsync_ThrowsWithSafeMessage_WhenBodyIsPlainText()
        {
            _server
                .Given(Request.Create().WithPath("/RevokeOrder").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(500)
                    .WithHeader("Content-Type", "text/plain")
                    .WithBody("Internal server error — please contact support."));

            var client = BuildClient();
            var revokeReq = new RevokeCertificateRequest { Reason = "unspecified" };

            Func<Task> act = () => client.RevokeCertificateAsync(MockCertificateData.OrderNumber1, revokeReq);

            // Message should NOT contain raw body content; should reference the operation name
            var ex = await act.Should().ThrowAsync<Exception>();
            ex.Which.Message.Should().Contain("revoke");
            ex.Which.Message.Should().NotContain("Internal server error — please contact support.",
                "raw response bodies must not appear in exception messages");
        }

        // ---------------------------------------------------------------------------
        // B9a: OAuth2 token fetch fails when endpoint returns 500
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task OAuth2_Throws_WhenTokenEndpointReturns500()
        {
            _server
                .Given(Request.Create().WithPath("/oauth/token").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(500)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.ServerErrorJson()));

            string tokenUrl = $"{_baseUrl}/oauth/token";
            var client = BuildOAuthClient(tokenUrl);

            Func<Task> act = () => client.PingAsync();

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("*OAuth2 token*");
        }

        // ---------------------------------------------------------------------------
        // B9b: OAuth2 token fetch fails when response has no access_token field
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task OAuth2_Throws_WhenTokenResponseLacksAccessToken()
        {
            // Return 200 but with a body that doesn't have access_token
            _server
                .Given(Request.Create().WithPath("/oauth/token").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(@"{""token_type"":""Bearer"",""expires_in"":3600}"));

            string tokenUrl = $"{_baseUrl}/oauth/token";
            var client = BuildOAuthClient(tokenUrl);

            Func<Task> act = () => client.PingAsync();

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("*access_token*");
        }
    }
}
