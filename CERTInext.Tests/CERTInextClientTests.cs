// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
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
    /// Integration tests for <see cref="CERTInextClient"/> using WireMock.Net.
    /// A real WireMockServer is started on a random port; RestSharp makes real HTTP
    /// calls against it so the serialisation/routing code is fully exercised.
    ///
    /// The real CERTInext API uses HTTP POST for ALL endpoints.
    /// No path prefix — endpoint names are appended directly to the base URL.
    /// All responses include a "meta" wrapper with status "1" (success) or "0" (failure).
    /// </summary>
    public class CERTInextClientTests : IDisposable
    {
        private readonly WireMockServer _server;
        private readonly string _baseUrl;

        public CERTInextClientTests()
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

        /// <summary>
        /// Builds a client using AccessKey auth mode. "AccountNumber" is used in every
        /// meta block; "ApiKey" is used to compute authKey (SHA256 hash).
        /// </summary>
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
        // PingAsync — calls POST /ValidateCredentials
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task PingAsync_ReturnsHealthy_WhenServerRespondsOk()
        {
            _server
                .Given(Request.Create().WithPath("/ValidateCredentials").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.ValidateCredentialsSuccessJson()));

            var client = BuildClient();

            // Should not throw
            await client.PingAsync();

            _server.LogEntries.Should().Contain(e =>
                e.RequestMessage.Path == "/ValidateCredentials");
        }

        [Fact]
        public async Task PingAsync_Throws_When500Returned()
        {
            _server
                .Given(Request.Create().WithPath("/ValidateCredentials").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(500)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.ServerErrorJson()));

            var client = BuildClient();

            Func<Task> act = () => client.PingAsync();

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("*health check failed*");
        }

        [Fact]
        public async Task PingAsync_Throws_WhenMetaStatusIsFailure()
        {
            _server
                .Given(Request.Create().WithPath("/ValidateCredentials").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.ValidateCredentialsFailureJson("EMS-001", "Invalid credentials")));

            var client = BuildClient();

            Func<Task> act = () => client.PingAsync();

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("*credential validation failed*");
        }

        // ---------------------------------------------------------------------------
        // OAuth2 token fetch
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task OAuth2_FetchesToken_BeforeFirstApiCall()
        {
            // Arrange token endpoint
            _server
                .Given(Request.Create().WithPath("/oauth/token").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.OAuth2TokenJson(3600)));

            _server
                .Given(Request.Create().WithPath("/ValidateCredentials").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.ValidateCredentialsSuccessJson()));

            string tokenUrl = $"{_baseUrl}/oauth/token";
            var client = BuildOAuthClient(tokenUrl);

            await client.PingAsync();

            // Both the token endpoint and ValidateCredentials endpoint were called
            _server.LogEntries.Select(e => e.RequestMessage.Path)
                .Should().Contain("/oauth/token")
                .And.Contain("/ValidateCredentials");
        }

        [Fact]
        public async Task OAuth2_TokenIsCached_SecondCallDoesNotRefetch()
        {
            _server
                .Given(Request.Create().WithPath("/oauth/token").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.OAuth2TokenJson(3600)));

            _server
                .Given(Request.Create().WithPath("/ValidateCredentials").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.ValidateCredentialsSuccessJson()));

            string tokenUrl = $"{_baseUrl}/oauth/token";
            var client = BuildOAuthClient(tokenUrl);

            await client.PingAsync();
            await client.PingAsync();

            // Token endpoint called exactly once; ValidateCredentials called twice
            int tokenRequests = _server.LogEntries.Count(e => e.RequestMessage.Path == "/oauth/token");
            tokenRequests.Should().Be(1, "token should be cached for the second call");

            int pingRequests = _server.LogEntries.Count(e => e.RequestMessage.Path == "/ValidateCredentials");
            pingRequests.Should().Be(2);
        }

        // ---------------------------------------------------------------------------
        // EnrollCertificateAsync (legacy) — calls POST /GenerateOrderSSL, /TrackOrder,
        // and optionally /GetCertificate
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task EnrollCertificateAsync_ReturnsCertificate_WhenServerIssues()
        {
            // GenerateOrderSSL → returns an orderNumber
            _server
                .Given(Request.Create().WithPath("/GenerateOrderSSL").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.GenerateOrderSuccessJson(MockCertificateData.OrderNumber1)));

            // TrackOrder → certificate is generated (statusId=9)
            _server
                .Given(Request.Create().WithPath("/TrackOrder").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.TrackOrderIssuedJson(MockCertificateData.OrderNumber1)));

            // GetCertificate → returns PEM
            _server
                .Given(Request.Create().WithPath("/GetCertificate").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.GetCertificateSuccessJson()));

            var client = BuildClient();
            var req = new EnrollCertificateRequest
            {
                ProfileId = MockCertificateData.ProfileIdTls,
                Csr = MockCertificateData.FakeCsrPem,
                Subject = "CN=test.example.com",
                Comment = "Unit test"
            };

            var result = await client.EnrollCertificateAsync(req);

            result.Should().NotBeNull();
            result.Id.Should().Be(MockCertificateData.OrderNumber1);
            result.Status.Should().Be("issued");
            result.Certificate.Should().Contain("BEGIN CERTIFICATE");
        }

        [Fact]
        public async Task EnrollCertificateAsync_ReturnsPending_WhenServerReturnsPendingApproval()
        {
            // GenerateOrderSSL
            _server
                .Given(Request.Create().WithPath("/GenerateOrderSSL").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.GenerateOrderSuccessJson(MockCertificateData.OrderNumber2)));

            // TrackOrder → pending (statusId=1 = SetupPending, not downloadable)
            _server
                .Given(Request.Create().WithPath("/TrackOrder").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.TrackOrderPendingJson(MockCertificateData.OrderNumber2)));

            var client = BuildClient();
            var req = new EnrollCertificateRequest
            {
                ProfileId = MockCertificateData.ProfileIdTls,
                Csr = MockCertificateData.FakeCsrPem
            };

            var result = await client.EnrollCertificateAsync(req);

            result.Status.Should().Be("pending_approval");
            result.Certificate.Should().BeNull();
        }

        [Fact]
        public async Task EnrollCertificateAsync_Throws_WhenGenerateOrderFails()
        {
            _server
                .Given(Request.Create().WithPath("/GenerateOrderSSL").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.ApiFailureJson("EMS-100", "Invalid CSR.")));

            var client = BuildClient();
            var req = new EnrollCertificateRequest { ProfileId = MockCertificateData.ProfileIdTls, Csr = "bad-csr" };

            Func<Task> act = () => client.EnrollCertificateAsync(req);

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("*Invalid CSR*");
        }

        [Fact]
        public async Task EnrollCertificateAsync_Throws_When5xxReturned()
        {
            _server
                .Given(Request.Create().WithPath("/GenerateOrderSSL").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(500)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.ServerErrorJson()));

            var client = BuildClient();
            var req = new EnrollCertificateRequest { ProfileId = MockCertificateData.ProfileIdTls, Csr = MockCertificateData.FakeCsrPem };

            Func<Task> act = () => client.EnrollCertificateAsync(req);

            await act.Should().ThrowAsync<Exception>();
        }

        // ---------------------------------------------------------------------------
        // GetCertificateAsync (legacy) — calls POST /TrackOrder then POST /GetCertificate
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task GetCertificateAsync_ReturnsCertificate_WhenFound()
        {
            _server
                .Given(Request.Create().WithPath("/TrackOrder").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.TrackOrderIssuedJson(MockCertificateData.OrderNumber1)));

            _server
                .Given(Request.Create().WithPath("/GetCertificate").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.GetCertificateSuccessJson()));

            var client = BuildClient();
            var result = await client.GetCertificateAsync(MockCertificateData.OrderNumber1);

            result.Should().NotBeNull();
            result.Id.Should().Be(MockCertificateData.OrderNumber1);
            result.Status.Should().Be("issued");
            result.Certificate.Should().Contain("BEGIN CERTIFICATE");
        }

        [Fact]
        public async Task GetCertificateAsync_ThrowsKeyNotFound_WhenOrderNotFound()
        {
            _server
                .Given(Request.Create().WithPath("/TrackOrder").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.ApiFailureJson("EMS-913", "Order not found.")));

            var client = BuildClient();

            Func<Task> act = () => client.GetCertificateAsync("nonexistent-order");

            await act.Should().ThrowAsync<KeyNotFoundException>();
        }

        // ---------------------------------------------------------------------------
        // RevokeCertificateAsync (legacy) — calls POST /RevokeOrder
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task RevokeCertificateAsync_Succeeds_When200Returned()
        {
            _server
                .Given(Request.Create().WithPath("/RevokeOrder").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.RevokeSuccessJson()));

            var client = BuildClient();
            var revokeReq = new RevokeCertificateRequest { Reason = "keyCompromise", Comment = "Test revocation" };

            // Should not throw
            await client.RevokeCertificateAsync(MockCertificateData.OrderNumber1, revokeReq);

            _server.LogEntries.Should().Contain(e => e.RequestMessage.Path == "/RevokeOrder");
        }

        [Fact]
        public async Task RevokeCertificateAsync_Throws_WhenServerReturnsFailure()
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

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("*revoke*");
        }

        // ---------------------------------------------------------------------------
        // RenewCertificateAsync (legacy) — calls TrackOrder (for prior order), then
        // GenerateOrderSSL + TrackOrder + GetCertificate (for new order)
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task RenewCertificateAsync_ReturnsNewCertificate_OnSuccess()
        {
            // First TrackOrder call: retrieve prior order info
            _server
                .Given(Request.Create().WithPath("/TrackOrder").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.TrackOrderIssuedJson(MockCertificateData.OrderNumber1)));

            // GenerateOrderSSL: new order
            _server
                .Given(Request.Create().WithPath("/GenerateOrderSSL").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.GenerateOrderSuccessJson(MockCertificateData.OrderNumber2)));

            // GetCertificate for new order
            _server
                .Given(Request.Create().WithPath("/GetCertificate").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.GetCertificateSuccessJson()));

            var client = BuildClient();
            var renewReq = new RenewCertificateRequest
            {
                Csr = MockCertificateData.FakeCsrPem,
                ValidityDays = 365,
                Comment = "Renewal test"
            };

            var result = await client.RenewCertificateAsync(MockCertificateData.OrderNumber1, renewReq);

            result.Id.Should().Be(MockCertificateData.OrderNumber2);
            result.Status.Should().Be("issued");
            result.Certificate.Should().Contain("BEGIN CERTIFICATE");
        }

        // ---------------------------------------------------------------------------
        // ListCertificatesAsync (legacy) — calls POST /GetOrderReport with pagination
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task ListCertificatesAsync_ReturnsSinglePage_WhenOnlyOnePage()
        {
            _server
                .Given(Request.Create().WithPath("/GetOrderReport").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.OrderReportSinglePageJson()));

            var client = BuildClient();
            var results = new List<LegacyGetCertificateResponse>();

            await foreach (var cert in client.ListCertificatesAsync(issuedAfter: null, pageSize: 100))
            {
                results.Add(cert);
            }

            results.Should().HaveCount(1);
            results[0].Id.Should().Be(MockCertificateData.OrderNumber1);
        }

        [Fact]
        public async Task ListCertificatesAsync_IteratesMultiplePages()
        {
            // The client sends pageNumber in the POST body JSON.
            // We match on body content to serve different pages.
            // Page 1: body contains "pageNumber":"1"
            _server
                .Given(Request.Create()
                    .WithPath("/GetOrderReport")
                    .UsingPost()
                    .WithBody(new WireMock.Matchers.JsonPartialMatcher(@"{""searchCriteria"":{""pageNumber"":""1""}}")))
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.OrderReportPageJson(
                        new[] { MockCertificateData.OrderNumber1 }, "2")));

            // Page 2: body contains "pageNumber":"2" → empty response to stop
            _server
                .Given(Request.Create()
                    .WithPath("/GetOrderReport")
                    .UsingPost()
                    .WithBody(new WireMock.Matchers.JsonPartialMatcher(@"{""searchCriteria"":{""pageNumber"":""2""}}")))
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.OrderReportEmptyJson()));

            // Use pageSize=1 so that a single-entry response triggers a next-page fetch
            var client = new CERTInextClient(new CERTInextConfig
            {
                ApiUrl = _baseUrl,
                AuthMode = "AccessKey",
                ApiKey = "test-key",
                AccountNumber = "12345",
                RequestorName = "Test User",
                RequestorEmail = "test@example.com",
                PageSize = 1
            });

            var results = new List<LegacyGetCertificateResponse>();

            await foreach (var cert in client.ListCertificatesAsync(issuedAfter: null, pageSize: 1))
            {
                results.Add(cert);
            }

            results.Should().HaveCount(1);
            results[0].Id.Should().Be(MockCertificateData.OrderNumber1);
        }

        [Fact]
        public async Task ListCertificatesAsync_StopsWhenEmptyPageReturned()
        {
            _server
                .Given(Request.Create().WithPath("/GetOrderReport").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.OrderReportEmptyJson()));

            var client = BuildClient();
            var results = new List<LegacyGetCertificateResponse>();

            await foreach (var cert in client.ListCertificatesAsync())
            {
                results.Add(cert);
            }

            results.Should().BeEmpty();
        }

        [Fact]
        public async Task ListCertificatesAsync_RespectsIssuedAfterFilter()
        {
            var since = new DateTime(2024, 3, 1, 0, 0, 0, DateTimeKind.Utc);

            _server
                .Given(Request.Create().WithPath("/GetOrderReport").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.OrderReportSinglePageJson()));

            var client = BuildClient();
            var results = new List<LegacyGetCertificateResponse>();

            await foreach (var cert in client.ListCertificatesAsync(issuedAfter: since, pageSize: 100))
            {
                results.Add(cert);
            }

            results.Should().HaveCount(1);

            // Verify the GetOrderReport was called (issuedAfter date is in the POST body, not a query param)
            _server.LogEntries.Should().Contain(e => e.RequestMessage.Path == "/GetOrderReport");
        }

        // ---------------------------------------------------------------------------
        // GetProfilesAsync (legacy) — calls POST /GetProductDetails
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task GetProfilesAsync_ReturnsProfiles_WhenServerResponds()
        {
            _server
                .Given(Request.Create().WithPath("/GetProductDetails").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.GetProductDetailsJson()));

            var client = BuildClient();
            var profiles = await client.GetProfilesAsync();

            profiles.Should().HaveCount(2);
            profiles.Should().Contain(p => p.Id == MockCertificateData.ProfileIdTls);
            profiles.Should().Contain(p => p.Id == MockCertificateData.ProfileIdClient);
            profiles.All(p => p.Active).Should().BeTrue();
        }

        [Fact]
        public async Task GetProfilesAsync_ReturnsEmptyList_WhenNoProductsReturned()
        {
            _server
                .Given(Request.Create().WithPath("/GetProductDetails").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.GetProductDetailsEmptyJson()));

            var client = BuildClient();
            var profiles = await client.GetProfilesAsync();

            profiles.Should().BeEmpty();
        }

        // ---------------------------------------------------------------------------
        // Error handling — 401 Unauthorized
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task EnrollCertificateAsync_Throws_When401Returned()
        {
            _server
                .Given(Request.Create().WithPath("/GenerateOrderSSL").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(401)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.UnauthorizedJson()));

            var client = BuildClient(apiKey: "wrong-key");
            var req = new EnrollCertificateRequest
            {
                ProfileId = MockCertificateData.ProfileIdTls,
                Csr = MockCertificateData.FakeCsrPem
            };

            Func<Task> act = () => client.EnrollCertificateAsync(req);

            await act.Should().ThrowAsync<Exception>();
        }
    }
}
