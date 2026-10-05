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
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Issue 0044: a V1 call that gets a non-2xx response whose body is not a CERTInext envelope
    /// must surface the HTTP status in the exception, not just "unrecognised error body".
    ///
    /// The body below is the exact one captured live on 2026-09-29 when the V1 GetOrderReport
    /// call was sent to the V2 base URL (ApiUrl without /emSignHub-API/): the host's default
    /// Spring Boot 404 body, with no <c>meta</c> and no <c>message</c>.
    /// </summary>
    public class V1NonSuccessResponseTests : IDisposable
    {
        internal const string LiveSpringNotFoundBody =
            "{\"timestamp\":\"2026-09-29T16:05:05.736+00:00\",\"status\":404,\"error\":\"Not Found\",\"path\":\"/GetOrderReport\"}";

        private readonly WireMockServer _server;

        public V1NonSuccessResponseTests()
        {
            _server = WireMockServer.Start();
        }

        public void Dispose()
        {
            _server.Stop();
        }

        private CERTInextClient BuildClient() =>
            new CERTInextClient(new CERTInextConfig
            {
                ApiUrl = _server.Urls[0],
                AuthMode = "AccessKey",
                ApiKey = "test-key",
                AccountNumber = "12345",
                RequestorName = "Test User",
                RequestorEmail = "test@example.com",
                PageSize = 100
            });

        private void StubNotFound(string path) =>
            _server
                .Given(Request.Create().WithPath(path).UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(404)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(LiveSpringNotFoundBody));

        [Fact]
        public async Task ListOrdersAsync_SpringNotFoundBody_ThrowsWithHttpStatus()
        {
            StubNotFound("/GetOrderReport");
            var client = BuildClient();

            Func<Task> act = async () =>
            {
                await foreach (var _ in client.ListOrdersAsync(pageSize: 5))
                {
                }
            };

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("CERTInext returned an unrecognised error body (HTTP 404) for operation 'list orders page 1'. See gateway logs for details.");
        }

        [Fact]
        public async Task GetProductDetailsAsync_SpringNotFoundBody_ThrowsWithHttpStatus()
        {
            // Same shared DeserializeOrThrow path, different caller.
            StubNotFound("/GetProductDetails");
            var client = BuildClient();

            Func<Task> act = () => client.GetProductDetailsAsync();

            await act.Should().ThrowAsync<Exception>()
                .WithMessage("*unrecognised error body (HTTP 404) for operation 'get product details'*");
        }
    }
}
