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
using System.Reflection;
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
    /// WireMock-based tests for V2 REST API methods on <see cref="CERTInextClient"/>.
    /// A real WireMockServer handles the V2 token endpoint and all V2 REST paths so
    /// serialisation, routing, and token caching are fully exercised.
    /// </summary>
    public class CERTInextClientV2Tests : IDisposable
    {
        private readonly WireMockServer _server;
        private readonly string _baseUrl;

        public CERTInextClientV2Tests()
        {
            _server = WireMockServer.Start();
            _baseUrl = _server.Urls[0];
        }

        public void Dispose() => _server.Stop();

        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

        private CERTInextClient BuildV2Client() =>
            new CERTInextClient(new CERTInextConfig
            {
                // V1 fields still required (Synchronize uses V1)
                ApiUrl        = _baseUrl,
                AuthMode      = "AccessKey",
                ApiKey        = "test-v1-key",
                AccountNumber = "12345",
                // V2 fields
                UseV2Api      = true,
                ApiUrlV2      = _baseUrl,
                ClientId      = "my-v2-client",
                ClientSecret  = "my-v2-secret",
                RequestorName  = "Test User",
                RequestorEmail = "test@example.com",
                PageSize       = 100
            });

        private void StubV2Token(int expiresIn = 3600)
        {
            _server
                .Given(Request.Create()
                    .WithPath("/oauth/token")
                    .UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2TokenResponseJson(expiresIn)));
        }

        // ---------------------------------------------------------------------------
        // Token fetch
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task PingV2Async_FetchesTokenAndCallsAuthMe()
        {
            StubV2Token();
            _server
                .Given(Request.Create()
                    .WithPath("/api/certinext/v2/auth/me")
                    .UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2AuthMeJson()));

            using var client = BuildV2Client();
            await client.PingV2Async();

            // Verify both token and auth/me endpoints were called
            _server.LogEntries.Should().Contain(e => e.RequestMessage.Path == "/oauth/token");
            _server.LogEntries.Should().Contain(e => e.RequestMessage.Path == "/api/certinext/v2/auth/me");
        }

        [Fact]
        public async Task GetAuthMeV2Async_ReturnsAccountNumber()
        {
            StubV2Token();
            _server
                .Given(Request.Create()
                    .WithPath("/api/certinext/v2/auth/me")
                    .UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2AuthMeJson("99887766")));

            using var client = BuildV2Client();
            var result = await client.GetAuthMeV2Async();

            result.AccountNumber.Should().Be("99887766");
            result.AuthType.Should().Be("oauth2");
        }

        [Fact]
        public async Task PingV2Async_TokenCached_OnlyOneFetch()
        {
            StubV2Token();
            _server
                .Given(Request.Create()
                    .WithPath("/api/certinext/v2/auth/me")
                    .UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2AuthMeJson()));

            using var client = BuildV2Client();
            await client.PingV2Async();
            await client.PingV2Async(); // second call — should reuse cached token

            var tokenCalls = 0;
            foreach (var entry in _server.LogEntries)
                if (entry.RequestMessage.Path == "/oauth/token") tokenCalls++;

            tokenCalls.Should().Be(1, "token should be cached after the first fetch");
        }

        // ---------------------------------------------------------------------------
        // PlaceOrderV2Async
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task PlaceOrderV2Async_ReturnsPendingOrder()
        {
            StubV2Token();
            _server
                .Given(Request.Create()
                    .WithPath("/api/certinext/v2/ssl-certificates")
                    .UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(201)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2CreateOrderPendingJson(MockCertificateData.V2OrderId1)));

            using var client = BuildV2Client();
            var result = await client.PlaceOrderV2Async(
                Constants.ApiV2.FamilySsl,
                "842",
                new V2CreateSslOrderRequest
                {
                    ProductVariant = "dv",
                    Requestor      = new V2Requestor { Name = "Test", Email = "t@t.com", Phone = "555", Designation = "IT" },
                    Certificate    = new V2CertificateParams { Domain = "example.com" },
                    Subscription   = new V2SubscriptionParams { ValidityYears = 1 },
                    Agreement      = new V2AgreementParams { SignerName = "Test", SignerIp = "1.2.3.4", SignerPlace = "NY", Accepted = true }
                });

            result.OrderId.Should().Be(MockCertificateData.V2OrderId1);
            result.Status.Should().Be("pending-dcv");
        }

        [Fact]
        public async Task PlaceOrderV2Async_SetsProductCodeHeader()
        {
            StubV2Token();
            _server
                .Given(Request.Create()
                    .WithPath("/api/certinext/v2/ssl-certificates")
                    .UsingPost()
                    .WithHeader("X-Product-Code", "842"))
                .RespondWith(Response.Create()
                    .WithStatusCode(201)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2CreateOrderPendingJson()));

            using var client = BuildV2Client();
            var result = await client.PlaceOrderV2Async(
                Constants.ApiV2.FamilySsl, "842",
                new V2CreateSslOrderRequest
                {
                    Requestor    = new V2Requestor { Name = "T", Email = "t@t.com", Phone = "1", Designation = "IT" },
                    Certificate  = new V2CertificateParams { Domain = "example.com" },
                    Subscription = new V2SubscriptionParams(),
                    Agreement    = new V2AgreementParams { SignerName = "T", SignerIp = "1.1.1.1", SignerPlace = "NY", Accepted = true }
                });

            result.Should().NotBeNull();
        }

        // ---------------------------------------------------------------------------
        // TrackOrderV2Async
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task TrackOrderV2Async_Issued_ReturnsIssuedStatus()
        {
            StubV2Token();
            _server
                .Given(Request.Create()
                    .WithPath($"/api/certinext/v2/ssl-certificates/{MockCertificateData.V2OrderId1}")
                    .UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2TrackOrderIssuedJson(MockCertificateData.V2OrderId1)));

            using var client = BuildV2Client();
            var result = await client.TrackOrderV2Async(Constants.ApiV2.FamilySsl, MockCertificateData.V2OrderId1);

            result.Status.Should().Be("issued");
            result.OrderId.Should().Be(MockCertificateData.V2OrderId1);
        }

        [Fact]
        public async Task TrackOrderV2Async_NotFound_ThrowsKeyNotFoundException()
        {
            StubV2Token();
            _server
                .Given(Request.Create()
                    .WithPath($"/api/certinext/v2/ssl-certificates/nonexistent")
                    .UsingGet())
                .RespondWith(Response.Create().WithStatusCode(404));

            using var client = BuildV2Client();
            await Assert.ThrowsAsync<KeyNotFoundException>(
                () => client.TrackOrderV2Async(Constants.ApiV2.FamilySsl, "nonexistent"));
        }

        // ---------------------------------------------------------------------------
        // DownloadCertificateV2Async
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task DownloadCertificateV2Async_ReturnsPem()
        {
            StubV2Token();
            _server
                .Given(Request.Create()
                    .WithPath($"/api/certinext/v2/ssl-certificates/{MockCertificateData.V2OrderId1}/certificate")
                    .UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2CertificateDownloadJson(MockCertificateData.V2OrderId1)));

            using var client = BuildV2Client();
            var result = await client.DownloadCertificateV2Async(Constants.ApiV2.FamilySsl, MockCertificateData.V2OrderId1);

            result.CertificatePem.Should().StartWith("-----BEGIN CERTIFICATE-----");
            result.SerialNumber.Should().Be("0A1B2C3D4E5F");
            result.OrderId.Should().Be(MockCertificateData.V2OrderId1);
        }

        // ---------------------------------------------------------------------------
        // RevokeOrderV2Async
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task RevokeOrderV2Async_SuccessfulRevoke()
        {
            StubV2Token();
            _server
                .Given(Request.Create()
                    .WithPath($"/api/certinext/v2/ssl-certificates/{MockCertificateData.V2OrderId1}/revoke")
                    .UsingPost())
                .RespondWith(Response.Create().WithStatusCode(204));

            using var client = BuildV2Client();
            // Should not throw
            await client.RevokeOrderV2Async(
                Constants.ApiV2.FamilySsl,
                MockCertificateData.V2OrderId1,
                new V2RevokeRequest { Reason = "superseded", Note = "Replaced." });
        }

        [Fact]
        public async Task RevokeOrderV2Async_422_ThrowsInvalidOperationException()
        {
            StubV2Token();
            _server
                .Given(Request.Create()
                    .WithPath($"/api/certinext/v2/ssl-certificates/{MockCertificateData.V2OrderId1}/revoke")
                    .UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(422)
                    .WithHeader("Content-Type", "application/problem+json")
                    .WithBody(MockCertificateData.V2ProblemDetailsJson(422, "Unprocessable Entity", "Order not in issued state", "EMS-931")));

            using var client = BuildV2Client();
            await Assert.ThrowsAsync<InvalidOperationException>(
                () => client.RevokeOrderV2Async(
                    Constants.ApiV2.FamilySsl,
                    MockCertificateData.V2OrderId1,
                    new V2RevokeRequest { Reason = "superseded" }));
        }

        // ---------------------------------------------------------------------------
        // Product-family resolution
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task ResolveAndTrackOrderV2Async_FindsOrderInSslFamily()
        {
            StubV2Token();
            // SSL family returns 404 → should try private-pki... wait, we want to find it in SSL
            _server
                .Given(Request.Create()
                    .WithPath($"/api/certinext/v2/ssl-certificates/{MockCertificateData.V2OrderId1}")
                    .UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2TrackOrderIssuedJson(MockCertificateData.V2OrderId1)));

            using var client = BuildV2Client();
            var result = await client.ResolveAndTrackOrderV2Async(MockCertificateData.V2OrderId1);

            result.OrderId.Should().Be(MockCertificateData.V2OrderId1);
            result.Status.Should().Be("issued");
        }

        [Fact]
        public async Task ResolveAndTrackOrderV2Async_FindsOrderInPrivatePkiFamily()
        {
            StubV2Token();
            // SSL → 404, private-pki → 200
            _server
                .Given(Request.Create()
                    .WithPath($"/api/certinext/v2/ssl-certificates/{MockCertificateData.V2OrderId2}")
                    .UsingGet())
                .RespondWith(Response.Create().WithStatusCode(404));

            _server
                .Given(Request.Create()
                    .WithPath($"/api/certinext/v2/private-pki-certificates/{MockCertificateData.V2OrderId2}")
                    .UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2TrackOrderIssuedJson(MockCertificateData.V2OrderId2)));

            using var client = BuildV2Client();
            var result = await client.ResolveAndTrackOrderV2Async(MockCertificateData.V2OrderId2);

            result.OrderId.Should().Be(MockCertificateData.V2OrderId2);
        }

        [Fact]
        public async Task ResolveAndTrackOrderV2Async_NotInAnyFamily_ThrowsKeyNotFoundException()
        {
            StubV2Token();
            foreach (var family in new[] { "ssl-certificates", "private-pki-certificates", "signature-certificates" })
            {
                _server
                    .Given(Request.Create()
                        .WithPath($"/api/certinext/v2/{family}/ord_missing")
                        .UsingGet())
                    .RespondWith(Response.Create().WithStatusCode(404));
            }

            using var client = BuildV2Client();
            await Assert.ThrowsAsync<KeyNotFoundException>(
                () => client.ResolveAndTrackOrderV2Async("ord_missing"));
        }

        // ---------------------------------------------------------------------------
        // GetDcvV2Async
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task GetDcvV2Async_ReturnsChallengeWithToken()
        {
            StubV2Token();
            _server
                .Given(Request.Create()
                    .WithPath($"/api/certinext/v2/ssl-certificates/{MockCertificateData.V2OrderId1}/dcv")
                    .UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2DcvChallengeJson(MockCertificateData.V2OrderId1, "example.com", "my-dcv-token")));

            using var client = BuildV2Client();
            var result = await client.GetDcvV2Async(MockCertificateData.V2OrderId1, Constants.ApiV2.FamilySsl);

            result.OrderNumber.Should().Be(MockCertificateData.V2OrderId1);
            result.DomainName.Should().Be("example.com");
            result.DcvMethod.Should().Be("2");
            result.FileNameContent.Should().Be("my-dcv-token");
        }

        [Fact]
        public async Task GetDcvV2Async_NonSuccess_Throws()
        {
            StubV2Token();
            _server
                .Given(Request.Create()
                    .WithPath($"/api/certinext/v2/ssl-certificates/{MockCertificateData.V2OrderId1}/dcv")
                    .UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(400)
                    .WithHeader("Content-Type", "application/problem+json")
                    .WithBody(MockCertificateData.V2ProblemDetailsJson(400, "Bad Request", "Order not found")));

            using var client = BuildV2Client();
            await Assert.ThrowsAsync<Exception>(
                () => client.GetDcvV2Async(MockCertificateData.V2OrderId1, Constants.ApiV2.FamilySsl));
        }

        // ---------------------------------------------------------------------------
        // VerifyDcvV2Async
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task VerifyDcvV2Async_200Ok_ReturnsVerified()
        {
            StubV2Token();
            _server
                .Given(Request.Create()
                    .WithPath($"/api/certinext/v2/ssl-certificates/{MockCertificateData.V2OrderId1}/dcv/verify")
                    .UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2DcvVerifySuccessJson()));

            using var client = BuildV2Client();
            var result = await client.VerifyDcvV2Async(MockCertificateData.V2OrderId1, "example.com", Constants.ApiV2.FamilySsl);

            result.OverallStatus.Should().Be("VERIFIED");
        }

        [Fact]
        public async Task VerifyDcvV2Async_204NoContent_ReturnsVerified()
        {
            StubV2Token();
            _server
                .Given(Request.Create()
                    .WithPath($"/api/certinext/v2/ssl-certificates/{MockCertificateData.V2OrderId1}/dcv/verify")
                    .UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(204));

            using var client = BuildV2Client();
            var result = await client.VerifyDcvV2Async(MockCertificateData.V2OrderId1, "example.com", Constants.ApiV2.FamilySsl);

            result.OverallStatus.Should().Be("VERIFIED");
        }

        [Fact]
        public async Task VerifyDcvV2Async_422_ThrowsInvalidOperationException()
        {
            StubV2Token();
            _server
                .Given(Request.Create()
                    .WithPath($"/api/certinext/v2/ssl-certificates/{MockCertificateData.V2OrderId1}/dcv/verify")
                    .UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(422)
                    .WithHeader("Content-Type", "application/problem+json")
                    .WithBody(MockCertificateData.V2ProblemDetailsJson(422, "Unprocessable Entity", "DNS record not found")));

            using var client = BuildV2Client();
            var ex = await Assert.ThrowsAsync<InvalidOperationException>(
                () => client.VerifyDcvV2Async(MockCertificateData.V2OrderId1, "example.com", Constants.ApiV2.FamilySsl));

            ex.Message.Should().Contain("DCV verification failed");
        }

        [Fact]
        public async Task VerifyDcvV2Async_SendsDnsTxtMethod()
        {
            StubV2Token();
            _server
                .Given(Request.Create()
                    .WithPath($"/api/certinext/v2/ssl-certificates/{MockCertificateData.V2OrderId1}/dcv/verify")
                    .UsingPost()
                    .WithBody(b => b != null && b.Contains("\"dns-txt\"")))
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2DcvVerifySuccessJson()));

            using var client = BuildV2Client();
            var result = await client.VerifyDcvV2Async(MockCertificateData.V2OrderId1, "example.com", Constants.ApiV2.FamilySsl);

            result.OverallStatus.Should().Be("VERIFIED");
        }

        // ---------------------------------------------------------------------------
        // DownloadCertificateV2Async — chain PEM assembly
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task DownloadCertificateV2Async_WithChainPem_DeserializesChain()
        {
            StubV2Token();
            _server
                .Given(Request.Create()
                    .WithPath($"/api/certinext/v2/ssl-certificates/{MockCertificateData.V2OrderId1}/certificate")
                    .UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2CertificateDownloadWithChainJson(MockCertificateData.V2OrderId1)));

            using var client = BuildV2Client();
            var result = await client.DownloadCertificateV2Async(Constants.ApiV2.FamilySsl, MockCertificateData.V2OrderId1);

            result.CertificatePem.Should().StartWith("-----BEGIN CERTIFICATE-----");
            result.ChainPem.Should().NotBeNullOrEmpty("API returned a chainPem array");
            result.ChainPem.Should().HaveCount(1);
            result.ChainPem[0].Should().Contain("INTERMEDIATE");
        }

        [Fact]
        public async Task DownloadCertificateV2Async_WithoutChainPem_ChainIsNull()
        {
            StubV2Token();
            _server
                .Given(Request.Create()
                    .WithPath($"/api/certinext/v2/ssl-certificates/{MockCertificateData.V2OrderId1}/certificate")
                    .UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2CertificateDownloadJson(MockCertificateData.V2OrderId1)));

            using var client = BuildV2Client();
            var result = await client.DownloadCertificateV2Async(Constants.ApiV2.FamilySsl, MockCertificateData.V2OrderId1);

            result.CertificatePem.Should().StartWith("-----BEGIN CERTIFICATE-----");
            result.ChainPem.Should().BeNullOrEmpty("API did not return chainPem");
        }

        // ---------------------------------------------------------------------------
        // Token refresh when expired
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task Token_CachedAndReused_WhenNotNearExpiry()
        {
            // Restates PingV2Async_TokenCached_OnlyOneFetch's proof via GetAuthMeV2Async — kept
            // as its own case (G11) so cache-reuse and expiry-refetch (below) are each one
            // single-purpose test rather than folded into one.
            StubV2Token();
            _server
                .Given(Request.Create()
                    .WithPath("/api/certinext/v2/auth/me")
                    .UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2AuthMeJson()));

            using var client = BuildV2Client();
            await client.GetAuthMeV2Async();
            await client.GetAuthMeV2Async();

            TokenFetchCount(_server).Should().Be(1, "a non-expired cached token must be reused");
        }

        /// <summary>
        /// G11: a cached token past its early-expiry window must be re-fetched via a fresh
        /// <c>client_credentials</c> call — never via <c>refresh_token</c>. Per the V2 spec,
        /// refresh tokens are single-use and refreshing invalidates the current access token, so
        /// this locks in the client's current (safe) behaviour of only ever using
        /// client_credentials.
        ///
        /// The real cache TTL floors at 30 seconds (<c>Math.Max(expires_in - 60, 30)</c> in
        /// <c>GetOrRefreshV2TokenAsync</c>), which is too slow to wait out in a unit test — so this
        /// reaches into the private <c>_v2TokenExpiry</c> field via reflection to simulate the
        /// passage of time instead of actually waiting.
        /// </summary>
        [Fact]
        public async Task Token_RefetchedViaClientCredentials_WhenPastEarlyExpiryWindow()
        {
            StubV2Token();
            _server
                .Given(Request.Create()
                    .WithPath("/api/certinext/v2/auth/me")
                    .UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2AuthMeJson()));

            using var client = BuildV2Client();
            await client.GetAuthMeV2Async();
            TokenFetchCount(_server).Should().Be(1);

            // Simulate the cached token having entered/passed its early-expiry window.
            SetV2TokenExpiry(client, DateTime.UtcNow.AddSeconds(-1));

            await client.GetAuthMeV2Async();
            TokenFetchCount(_server).Should().Be(2,
                "a token past its early-expiry window must be re-fetched, not reused");

            // Every /oauth/token call must use client_credentials — never refresh_token, even
            // though the stubbed token response includes a refresh_token field.
            foreach (var entry in _server.LogEntries.Where(e => e.RequestMessage.Path == "/oauth/token"))
            {
                string body = entry.RequestMessage.Body ?? string.Empty;
                body.Should().Contain("grant_type=client_credentials");
                body.Should().NotContain("grant_type=refresh_token",
                    "refresh tokens are single-use per the V2 spec — the client must never send this grant proactively");
            }
        }

        private static int TokenFetchCount(WireMockServer server) =>
            server.LogEntries.Count(e => e.RequestMessage.Path == "/oauth/token");

        private static void SetV2TokenExpiry(CERTInextClient client, DateTime value)
        {
            var field = typeof(CERTInextClient)
                .GetField("_v2TokenExpiry", BindingFlags.NonPublic | BindingFlags.Instance);
            field.Should().NotBeNull("test relies on CERTInextClient's private _v2TokenExpiry field existing");
            field!.SetValue(client, value);
        }

        // ---------------------------------------------------------------------------
        // G2: OAuth2 token failure hints (401 invalid_client vs 403 unauthorized_client)
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task GetOrRefreshV2Token_Throws_DistinctHint_On401InvalidClient()
        {
            _server
                .Given(Request.Create().WithPath("/oauth/token").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(401)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(@"{""error"":""invalid_client"",""error_description"":""Client authentication failed.""}"));

            using var client = BuildV2Client();

            Func<Task> act = () => client.PingV2Async();

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("*401*")
                .Where(ex => ex.Message.Contains("ClientId", StringComparison.OrdinalIgnoreCase)
                          || ex.Message.Contains("ClientSecret", StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public async Task GetOrRefreshV2Token_Throws_DistinctHint_On403UnauthorizedClient()
        {
            _server
                .Given(Request.Create().WithPath("/oauth/token").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(403)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(@"{""error"":""unauthorized_client"",""error_description"":""Key not generated in OAuth mode.""}"));

            using var client = BuildV2Client();

            Func<Task> act = () => client.PingV2Async();

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("*403*")
                .Where(ex => ex.Message.Contains("OAuth mode", StringComparison.OrdinalIgnoreCase));
        }

        [Fact]
        public async Task GetOrRefreshV2Token_401And403_ProduceDifferentMessages()
        {
            // The two hints must actually differ — otherwise the distinction above is cosmetic.
            _server
                .Given(Request.Create().WithPath("/oauth/token").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(401)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(@"{""error"":""invalid_client""}"));
            using var client401 = BuildV2Client();
            Exception ex401 = null;
            try { await client401.PingV2Async(); } catch (Exception ex) { ex401 = ex; }

            _server.Reset();
            _server
                .Given(Request.Create().WithPath("/oauth/token").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(403)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(@"{""error"":""unauthorized_client""}"));
            using var client403 = BuildV2Client();
            Exception ex403 = null;
            try { await client403.PingV2Async(); } catch (Exception ex) { ex403 = ex; }

            ex401.Should().NotBeNull();
            ex403.Should().NotBeNull();
            ex401!.Message.Should().NotBe(ex403!.Message);
        }

        [Fact]
        public async Task GetOrRefreshV2Token_Throws_WhenTokenResponseLacksAccessToken()
        {
            _server
                .Given(Request.Create().WithPath("/oauth/token").UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(@"{""token_type"":""Bearer"",""expires_in"":3600}"));

            using var client = BuildV2Client();

            Func<Task> act = () => client.PingV2Async();

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("*access_token*");
        }

        // ---------------------------------------------------------------------------
        // G12: RFC 7807 field-level errors surfaced in the exception message
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task ThrowOnV2Failure_IncludesFieldLevelErrors_FromProblemJson()
        {
            StubV2Token();
            _server
                .Given(Request.Create()
                    .WithPath($"/api/certinext/v2/ssl-certificates/{MockCertificateData.V2OrderId1}")
                    .UsingGet())
                .RespondWith(Response.Create()
                    .WithStatusCode(400)
                    .WithHeader("Content-Type", "application/problem+json")
                    .WithBody(
                        @"{""type"":""https://api.certinext.io/errors/validation""," +
                        @"""title"":""Bad Request"",""status"":400," +
                        @"""detail"":""Body malformed""," +
                        @"""errors"":[{""field"":""certificate.domain"",""message"":""must not be blank""}]}"));

            using var client = BuildV2Client();

            Func<Task> act = () => client.TrackOrderV2Async(Constants.ApiV2.FamilySsl, MockCertificateData.V2OrderId1);

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("*certificate.domain*must not be blank*");
        }
    }
}
