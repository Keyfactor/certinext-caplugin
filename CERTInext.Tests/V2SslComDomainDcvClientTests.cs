// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Linq;
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
    /// Wire shape of the domain-level DCV calls used for SSL.com-validated domains:
    /// <c>GET /domains?search=&amp;exactMatch=true</c>, <c>GET /domains/{id}/dcv</c> and
    /// <c>POST /domains/{id}/dcv/verify</c>.
    /// </summary>
    public class V2SslComDomainDcvClientTests : IDisposable
    {
        private const string DomainsPath = "/api/certinext/v2/domains";
        private readonly WireMockServer _server;

        public V2SslComDomainDcvClientTests()
        {
            _server = WireMockServer.Start();
            _server
                .Given(Request.Create().WithPath("/oauth/token").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2TokenResponseJson()));
        }

        public void Dispose() => _server.Stop();

        private CERTInextClient BuildClient() =>
            new CERTInextClient(new CERTInextConfig
            {
                ApiUrl            = _server.Urls[0],
                AuthMode          = "AccessKey",
                ApiKey            = "test-v1-key",
                AccountNumber     = "12345",
                UseV2Api          = true,
                OAuthClientId     = "my-v2-client",
                OAuthClientSecret = "my-v2-secret",
                RequestorName     = "Test User",
                RequestorEmail    = "test@example.com"
            });

        private void Stub(string path, bool post, int status, string body)
        {
            var req = Request.Create().WithPath(path);
            req = post ? req.UsingPost() : req.UsingGet();
            var resp = Response.Create().WithStatusCode(status);
            if (body != null)
                resp = resp.WithHeader("Content-Type", "application/json").WithBody(body);
            _server.Given(req).RespondWith(resp);
        }

        [Fact]
        public async Task FindDomain_SendsExactMatchSearch_ParsesSslComRow()
        {
            Stub(DomainsPath, false, 200,
                "{\"content\":[{\"domainId\":\"dom_1\",\"domainName\":\"example.com\",\"status\":\"ACTIVE\"," +
                "\"dcvStatus\":\"PENDING\",\"validatedBy\":\"SSLCOM\"}],\"totalElements\":1}");

            using var client = BuildClient();
            var row = await client.FindDomainV2Async("example.com");

            row.Should().NotBeNull();
            row!.DomainId.Should().Be("dom_1");
            row.IsValidatedBySslCom.Should().BeTrue();
            var query = _server.LogEntries.Single(e => e.RequestMessage.Path == DomainsPath).RequestMessage.Query;
            query!["search"].Should().Equal("example.com");
            query["exactMatch"].Should().Equal("true");
        }

        [Fact]
        public async Task FindDomain_IgnoresSubstringMatches_ReadsNumericIdAndMissingValidatedBy()
        {
            Stub(DomainsPath, false, 200,
                "{\"content\":[{\"id\":11,\"domainName\":\"sub.example.com\",\"validatedBy\":\"SSLCOM\"}," +
                "{\"id\":12,\"domainName\":\"Example.com\",\"dcvStatus\":\"VERIFIED\"}]}");

            using var client = BuildClient();
            var row = await client.FindDomainV2Async("example.com");

            row!.DomainId.Should().Be("12");
            row.IsValidatedBySslCom.Should().BeFalse("no validatedBy means emSign");
        }

        [Fact]
        public async Task FindDomain_NoRows_ReturnsNull()
        {
            Stub(DomainsPath, false, 200, "{\"content\":[]}");
            using var client = BuildClient();
            (await client.FindDomainV2Async("example.com")).Should().BeNull();
        }

        [Fact]
        public async Task GetDomainDcv_ParsesSelectedRecordAndOptions()
        {
            Stub(DomainsPath + "/dom_1/dcv", false, 200,
                "{\"method\":\"dns-txt\",\"recordName\":\"_pki-validation.example.com\",\"recordValue\":\"v1\"," +
                "\"optionId\":\"opt-1\",\"validatedBy\":\"SSLCOM\",\"caStatus\":\"PENDING\",\"options\":[" +
                "{\"optionId\":\"opt-1\",\"method\":\"dns-txt\",\"brMethod\":\"3.2.2.4.7\",\"recordName\":\"_pki-validation.example.com\"," +
                "\"recordValue\":\"v1\",\"coversName\":\"example.com\",\"exactName\":true}," +
                "{\"optionId\":\"opt-2\",\"method\":\"dns-cname\",\"recordName\":\"_c.example.com\",\"recordValue\":\"t\"}]}");

            using var client = BuildClient();
            var details = await client.GetDomainDcvV2Async("dom_1");

            details.CaStatus.Should().Be("PENDING");
            details.Options.Should().HaveCount(2);
            var picked = details.SelectDnsTxtOption();
            picked.OptionId.Should().Be("opt-1");
            picked.RecordName.Should().Be("_pki-validation.example.com");
            picked.RecordValue.Should().Be("v1");
        }

        [Fact]
        public async Task GetDomainDcv_502_Throws()
        {
            Stub(DomainsPath + "/dom_1/dcv", false, 502, null);
            using var client = BuildClient();
            var act = () => client.GetDomainDcvV2Async("dom_1");
            (await act.Should().ThrowAsync<Exception>()).Which.Message.Should().Contain("502");
        }

        [Fact]
        public async Task VerifyDomainDcv_200_SendsOptionId_ReturnsVerifiedWithValidTill()
        {
            Stub(DomainsPath + "/dom_1/dcv/verify", true, 200, "{\"dcvStatus\":\"VERIFIED\",\"validTill\":\"2027-11-13\"}");

            using var client = BuildClient();
            var result = await client.VerifyDomainDcvV2Async("dom_1", "opt-1");

            result.Verified.Should().BeTrue();
            result.ValidTill.Should().Be("2027-11-13");
            _server.LogEntries.Single(e => e.RequestMessage.Path == DomainsPath + "/dom_1/dcv/verify")
                .RequestMessage.Body.Should().Be("{\"optionId\":\"opt-1\"}");
        }

        [Fact]
        public async Task VerifyDomainDcv_NoOptionId_SendsEmptyObject()
        {
            Stub(DomainsPath + "/dom_1/dcv/verify", true, 200, "{}");
            using var client = BuildClient();
            await client.VerifyDomainDcvV2Async("dom_1", null);
            _server.LogEntries.Single(e => e.RequestMessage.Path == DomainsPath + "/dom_1/dcv/verify")
                .RequestMessage.Body.Should().Be("{}");
        }

        [Fact]
        public async Task VerifyDomainDcv_422UnderReview_ReturnsNotVerifiedWithDiagnostics_MasksEmail()
        {
            Stub(DomainsPath + "/dom_1/dcv/verify", true, 422,
                "{\"type\":\"about:blank\",\"title\":\"Unprocessable Entity\",\"status\":422," +
                "\"diagnostics\":{\"caStatus\":\"UNDER_REVIEW\",\"caMessage\":\"Reviewer admin@example.com is checking\"}}");

            using var client = BuildClient();
            var result = await client.VerifyDomainDcvV2Async("dom_1", "opt-1");

            result.Verified.Should().BeFalse();
            result.CaStatus.Should().Be("UNDER_REVIEW");
            result.CaMessage.Should().NotContain("admin@example.com");
        }

        [Fact]
        public async Task VerifyDomainDcv_502_Throws()
        {
            Stub(DomainsPath + "/dom_1/dcv/verify", true, 502, null);
            using var client = BuildClient();
            var act = () => client.VerifyDomainDcvV2Async("dom_1", "opt-1");
            (await act.Should().ThrowAsync<Exception>()).Which.Message.Should().Contain("502");
        }

        [Fact]
        public void SelectDnsTxtOption_NoTxt_ReturnsNull_DescribesOffered()
        {
            var details = new V2DomainDcvDetails
            {
                Method = "http-url",
                Options = new System.Collections.Generic.List<V2DcvOption>
                {
                    new V2DcvOption { Method = "dns-cname", RecordName = "a", RecordValue = "b" },
                    new V2DcvOption { Method = "dns-txt", RecordName = "x" } // no value: unusable
                }
            };
            details.SelectDnsTxtOption().Should().BeNull();
            details.DescribeOfferedMethods().Should().Contain("dns-cname").And.Contain("http-url");
        }
    }
}
