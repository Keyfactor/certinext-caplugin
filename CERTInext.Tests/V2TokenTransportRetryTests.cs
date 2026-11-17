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
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using WireMock.Settings;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Issue 0095: the V2 OAuth2 token request is retried after a transport failure (no HTTP response)
    /// and the failure's transport detail reaches the log and the exception, without secrets. Any HTTP
    /// answer, 401/403 included, is never retried.
    /// </summary>
    public class V2TokenTransportRetryTests : IDisposable
    {
        private const string TokenPath = "/oauth/token";
        private const string Secret = "s3cr3t-client-value";
        private readonly WireMockServer _server = WireMockServer.Start();
        private FlakyTcpProxy _proxy;

        public V2TokenTransportRetryTests()
        {
            _server.Given(Request.Create().WithPath(TokenPath).UsingPost()).RespondWith(TokenOk());
        }

        public void Dispose()
        {
            _proxy?.Dispose();
            _server.Stop();
        }

        /// <summary>Routes the client through a proxy that resets the connections <paramref name="drop"/> selects.</summary>
        private string Via(Func<int, bool> drop)
        {
            _proxy = new FlakyTcpProxy(_server.Urls[0], drop);
            return _proxy.Url;
        }

        private string _apiUrl;

        private CERTInextConfig Config() => new CERTInextConfig
        {
            ApiUrl            = _apiUrl ?? _server.Urls[0],
            UseV2Api          = true,
            OAuthClientId     = "my-v2-client",
            OAuthClientSecret = Secret,
            RequestorName     = "Test User",
            RequestorEmail    = "test@example.com",
            SignerPlace       = "New York",
            PickupRetries     = 0,
            DcvEnabled        = false
        };

        private CERTInextClient Client(CERTInextConfig config = null) =>
            new CERTInextClient(config ?? Config()) { V2TokenRetryDelays = new[] { TimeSpan.Zero, TimeSpan.Zero } };

        private int TokenCalls => _server.LogEntries.Count(e => e.RequestMessage.Path == TokenPath);

        private static IResponseBuilder TokenOk() => Response.Create().WithStatusCode(200)
            .WithHeader("Content-Type", "application/json").WithBody(MockCertificateData.V2TokenResponseJson());

        /// <summary>
        /// The first connection is the first token request (every call needs a token first, and each
        /// token attempt opens its own connection): reset it, forward the rest.
        /// </summary>
        private void StubTokenDropsOnceThenSucceeds() => _apiUrl = Via(n => n == 1);

        /// <summary>Exactly two token attempts: the reset first one, and the retry that reached the server.</summary>
        private void TokenAttemptsShouldBeTwo() =>
            TokenCalls.Should().Be(1, "the first attempt's connection was reset before reaching the server, " +
                "and exactly one retry got through, so two token attempts in total");

        private void StubJson(string path, string body, bool post = false)
        {
            var req = Request.Create().WithPath(path);
            _server.Given(post ? req.UsingPost() : req.UsingGet()).RespondWith(Response.Create().WithStatusCode(post ? 201 : 200)
                .WithHeader("Content-Type", "application/json").WithBody(body));
        }

        [Fact]
        public async Task Enroll_TokenDropsOnce_RetriesAndSucceeds_WithTwoTokenCalls()
        {
            StubTokenDropsOnceThenSucceeds();
            const string orderId = "ord_tok_001";
            StubJson("/api/certinext/v2/ssl-certificates", MockCertificateData.V2CreateOrderIssuedJson(orderId), post: true);
            StubJson($"/api/certinext/v2/ssl-certificates/{orderId}", MockCertificateData.V2TrackOrderIssuedJson(orderId));
            StubJson($"/api/certinext/v2/ssl-certificates/{orderId}/certificate", MockCertificateData.V2CertificateDownloadJson(orderId));
            var config = Config();
            var plugin = new CERTInextCAPlugin(Client(config), config);

            var result = await plugin.Enroll(MockCertificateData.FakeCsrPem, "CN=example.com",
                new Dictionary<string, string[]>(),
                new EnrollmentProductInfo
                {
                    ProductID = "DV SSL",
                    ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["ProductFamily"] = "ssl", ["ProductVariant"] = "dv", ["DomainName"] = "example.com"
                    }
                },
                RequestFormat.PKCS10, EnrollmentType.New);

            result.Status.Should().Be((int)EndEntityStatus.GENERATED);
            TokenAttemptsShouldBeTwo();
            _server.LogEntries.Count(e => e.RequestMessage.Path == "/api/certinext/v2/ssl-certificates").Should().Be(1,
                "only the token request is retried; the order create is sent once");
        }

        [Fact]
        public async Task Sync_TokenDropsOnce_RetriesAndSucceeds_WithTwoTokenCalls()
        {
            StubTokenDropsOnceThenSucceeds();
            StubJson("/api/certinext/v2/reports/orders", MockCertificateData.V2OrdersReportJson(1, 1, Array.Empty<string>()));
            var config = Config();
            var plugin = new CERTInextCAPlugin(Client(config), config);

            await plugin.Synchronize(new BlockingCollection<AnyCAPluginCertificate>(10), null, true, CancellationToken.None);

            TokenAttemptsShouldBeTwo();
        }

        [Fact]
        public async Task ValidateConnection_TokenDropsOnce_RetriesAndSucceeds_WithTwoTokenCalls()
        {
            StubTokenDropsOnceThenSucceeds();
            StubJson("/api/certinext/v2/auth/me", MockCertificateData.V2AuthMeJson());
            var plugin = new CERTInextCAPlugin();

            // The config-save check builds its own client, so this uses the real 1 s backoff.
            await plugin.ValidateCAConnectionInfo(new Dictionary<string, object>
            {
                ["ApiUrl"] = _apiUrl,
                ["UseV2Api"] = true,
                ["OAuthClientId"] = "my-v2-client",
                ["OAuthClientSecret"] = Secret,
                ["SignerPlace"] = "New York",
                ["RequestorName"] = "Test User",
                ["RequestorEmail"] = "test@example.com"
            });

            TokenAttemptsShouldBeTwo();
        }

        [Fact]
        public async Task TokenDropsEveryTime_TriesThreeTimes_MessageHasTransportDetail_NoSecret()
        {
            _apiUrl = Via(_ => true);
            using var client = Client();

            Func<Task> act = () => client.GetAuthMeV2Async();

            var ex = (await act.Should().ThrowAsync<Exception>()).Which;
            ex.Message.Should().Contain("no HTTP response after 3 attempt(s)")
                .And.Contain("ResponseStatus=").And.NotContain(Secret);
            _proxy.Connections.Should().Be(3, "one attempt plus two retries");
            TokenCalls.Should().Be(0, "no attempt reached the server");
        }

        [Theory]
        [InlineData(400)]
        [InlineData(401)]
        [InlineData(403)]
        public async Task TokenHttpError_IsNeverRetried(int status)
        {
            _server.Reset();
            _server.Given(Request.Create().WithPath(TokenPath).UsingPost())
                .RespondWith(Response.Create().WithStatusCode(status)
                    .WithHeader("Content-Type", "application/json").WithBody("{\"error\":\"invalid_client\"}"));
            using var client = Client();

            Func<Task> act = () => client.GetAuthMeV2Async();

            await act.Should().ThrowAsync<Exception>();
            TokenCalls.Should().Be(1);
        }

        [Fact]
        public async Task ApiCallWithNoResponse_MessageKeepsHttp0First_AndHasTransportDetail()
        {
            // Connection 1 carries the token request; every later connection (the API call) is reset.
            _apiUrl = Via(n => n > 1);
            using var client = Client();

            Func<Task> act = () => client.TrackOrderV2Async(Constants.ApiV2.FamilySsl, "ord_x");

            var ex = (await act.Should().ThrowAsync<Exception>()).Which;
            ex.Message.Should().Contain("HTTP 0. No HTTP response (ResponseStatus=");
            CERTInextCAPlugin.IsTransportLevelCsrFailure(ex).Should().BeTrue();
        }

        [Fact]
        public void DescribeTransportFailure_ScrubsSecretsFromExceptionText()
        {
            using var client = Client();
            var resp = new RestSharp.RestResponse
            {
                ResponseStatus = RestSharp.ResponseStatus.Error,
                ErrorException = new System.Net.Http.HttpRequestException(
                    $"send failed for grant_type=client_credentials&client_secret={Secret}",
                    new System.IO.IOException($"raw {Secret} connection reset by peer"))
            };

            string detail = client.DescribeTransportFailure(resp);

            detail.Should().Contain("ResponseStatus=Error").And.Contain("HttpRequestException")
                .And.Contain("IOException").And.Contain("connection reset by peer").And.NotContain(Secret);
        }
    }
}
