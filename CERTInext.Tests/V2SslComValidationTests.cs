// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using Moq;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// SSL.com organization validation for V2 OV/EV SSL orders: the typed model and its defensive
    /// "validated for level" logic, the three client calls, and the plugin pre-check, which is
    /// strictly advisory (every failure or not-validated outcome warns and the order is placed anyway).
    /// All sample values are placeholders (no real names or emails).
    /// </summary>
    [Collection(LoggingStateCollection.Name)]
    public class V2SslComValidationTests : IDisposable
    {
        private const string OrgNumber = "1234567";
        private const string ContactEmail = "contact.person@example.org";
        private const string AdminEmail = "pki-admin@example.com";
        private const string OrderId = "ord_sslcom_001";

        private readonly WireMockServer _server = WireMockServer.Start();
        public void Dispose() => _server.Stop();

        // The shape of a live read-only GET on a never-submitted organization (values replaced).
        private const string LiveNotSubmittedJson = @"{
            ""caName"":""SSL.com"",""lastError"":"""",""organizationNumber"":""1234567"",
            ""readiness"":{""current"":{""contactTitle"":"""",""registrationNumber"":""R-1"",""contactName"":""Placeholder"",
                ""businessCategoryId"":"""",""organizationPhone"":""""},
              ""softMissing"":[""Organization phone number""],""evMissing"":[""Business category"",""Contact designation""],
              ""ready"":true,""evReady"":false,""missing"":[]},
            ""lastSyncedAt"":"""",""enabled"":true,""subscriberAgreementAccepted"":false,""externalOrgId"":"""",
            ""defaultLevels"":[""OV""],
            ""contact"":{""companyNumber"":""R-1"",""name"":""Placeholder"",""title"":"""",""email"":""contact.person@example.org""},
            ""submittedAt"":"""",""ca"":""sslcom"",""validatedAt"":"""",""levels"":[],""status"":""NOT_SUBMITTED"",
            ""someFutureField"":{""x"":1}}";

        private static V2SslComValidation Parse(string json) => JsonSerializer.Deserialize<V2SslComValidation>(json);

        // ---------------------------------------------------------------------------
        // Model
        // ---------------------------------------------------------------------------

        [Fact]
        public void Model_ParsesTheLiveShape_AndKeepsUnknownFields()
        {
            var v = Parse(LiveNotSubmittedJson);

            v.Status.Should().Be("NOT_SUBMITTED");
            v.DefaultLevels.Should().Equal("OV");
            v.SubscriberAgreementAccepted.Should().BeFalse();
            v.Readiness.Ready.Should().BeTrue();
            v.Readiness.EvReady.Should().BeFalse();
            v.Readiness.Missing.Should().BeEmpty();
            v.Readiness.EvMissing.Should().Equal("Business category", "Contact designation");
            v.Readiness.SoftMissing.Should().Equal("Organization phone number");
            v.Contact.Email.Should().Be(ContactEmail);
            v.Levels.ValueKind.Should().Be(JsonValueKind.Array);
            v.ExtensionData.Should().ContainKey("someFutureField");
            v.IsLevelValidated("OV").Should().BeFalse();
            v.IsLevelValidated("EV").Should().BeFalse();
            v.IsLevelListed("OV").Should().BeFalse();
        }

        [Fact]
        public void Model_EmptyObject_ParsesAndIsNotValidated()
        {
            var v = Parse("{}");
            v.IsLevelValidated("OV").Should().BeFalse();
            v.IsLevelListed("OV").Should().BeFalse();
        }

        [Theory]
        // per-level objects
        [InlineData(@"{""levels"":[{""level"":""OV"",""status"":""VALIDATED"",""validTill"":""2099-01-01T00:00:00Z""}]}", "OV", true)]
        [InlineData(@"{""levels"":[{""level"":""OV"",""status"":""VALIDATED"",""validTill"":""2099-01-01T00:00:00Z""}]}", "EV", false)]
        [InlineData(@"{""levels"":[{""level"":""ov"",""status"":""approved""}]}", "OV", true)]
        [InlineData(@"{""levels"":[{""level"":""EV"",""state"":""ACTIVE""}]}", "EV", true)]
        [InlineData(@"{""levels"":[{""name"":""OV"",""validTill"":""2099-01-01""}]}", "OV", true)]                       // no status, future expiry
        [InlineData(@"{""levels"":[{""level"":""OV"",""validated"":true}]}", "OV", true)]
        [InlineData(@"{""levels"":[{""level"":""OV"",""status"":""VALIDATED"",""validTill"":""2001-01-01T00:00:00Z""}]}", "OV", false)]  // expired
        [InlineData(@"{""levels"":[{""level"":""OV"",""status"":""PENDING""}]}", "OV", false)]
        [InlineData(@"{""levels"":[{""level"":""OV"",""status"":""NOT_SUBMITTED""}]}", "OV", false)]
        [InlineData(@"{""levels"":[{""level"":""OV"",""validTill"":""2001-01-01""}]}", "OV", false)]                      // no status, past expiry
        [InlineData(@"{""levels"":[{""level"":""OV""}]}", "OV", false)]                                                  // listed, no evidence
        // bare level names: only count with an overall validated status
        [InlineData(@"{""status"":""VALIDATED"",""levels"":[""OV""]}", "OV", true)]
        [InlineData(@"{""status"":""NOT_SUBMITTED"",""levels"":[""OV""]}", "OV", false)]
        [InlineData(@"{""status"":""VALIDATED"",""levels"":[""OV""]}", "EV", false)]
        // map keyed by level
        [InlineData(@"{""levels"":{""OV"":{""status"":""VALIDATED""},""EV"":""PENDING""}}", "OV", true)]
        [InlineData(@"{""levels"":{""OV"":{""status"":""VALIDATED""},""EV"":""PENDING""}}", "EV", false)]
        [InlineData(@"{""levels"":{""EV"":""VALIDATED""}}", "EV", true)]
        // a level-named top-level member
        [InlineData(@"{""OV"":{""status"":""VALIDATED""}}", "OV", true)]
        // the overall status or validatedAt alone is never per-level evidence
        [InlineData(@"{""status"":""VALIDATED"",""levels"":[]}", "OV", false)]
        [InlineData(@"{""validatedAt"":""2026-01-01T00:00:00Z"",""defaultLevels"":[""OV""]}", "OV", false)]
        // unrecognizable shapes are "not validated"
        [InlineData(@"{""levels"":""weird""}", "OV", false)]
        [InlineData(@"{""levels"":[1,2,3]}", "OV", false)]
        [InlineData(@"{""levels"":null}", "OV", false)]
        public void IsLevelValidated_DefensiveAcrossPlausibleShapes(string json, string level, bool expected)
        {
            Parse(json).IsLevelValidated(level).Should().Be(expected);
        }

        [Theory]
        [InlineData(@"{""levels"":[{""level"":""OV"",""status"":""PENDING""}]}", "OV", true)]
        [InlineData(@"{""levels"":[""OV""]}", "OV", true)]
        [InlineData(@"{""levels"":{""EV"":""PENDING""}}", "EV", true)]
        [InlineData(@"{""levels"":[{""level"":""OV"",""status"":""PENDING""}]}", "EV", false)]
        [InlineData(@"{""levels"":[]}", "OV", false)]
        public void IsLevelListed_FindsARequestedLevelInAnyState(string json, string level, bool expected)
        {
            Parse(json).IsLevelListed(level).Should().Be(expected);
        }

        [Theory]
        [InlineData(true, true, 0, "OV", true)]
        [InlineData(true, true, 1, "OV", false)]     // something still missing
        [InlineData(false, true, 0, "OV", false)]
        [InlineData(true, false, 0, "EV", false)]    // OV ready but EV not
        [InlineData(true, true, 0, "EV", true)]
        public void SslComReadyFor_UsesTheMatchingFlagAndMissingList(bool ready, bool evReady, int missingCount, string level, bool expected)
        {
            var missing = Enumerable.Repeat("x", missingCount).ToList();
            var r = new V2SslComReadiness
            {
                Ready = ready, EvReady = evReady,
                Missing = level == "OV" ? missing : new List<string>(),
                EvMissing = level == "EV" ? missing : new List<string>()
            };
            CERTInextCAPlugin.SslComReadyFor(r, level).Should().Be(expected);
        }

        [Fact]
        public void SslComReadyFor_NoReadinessBlock_IsNotReady()
        {
            CERTInextCAPlugin.SslComReadyFor(null, "OV").Should().BeFalse();
            CERTInextCAPlugin.SslComReadyFor(new V2SslComReadiness(), "OV").Should().BeFalse();
        }

        // ---------------------------------------------------------------------------
        // Client (WireMock)
        // ---------------------------------------------------------------------------

        private CERTInextClient BuildClient() => new CERTInextClient(new CERTInextConfig
        {
            ApiUrl            = _server.Urls[0],
            UseV2Api          = true,
            OAuthClientId     = "my-v2-client",
            OAuthClientSecret = "my-v2-secret",
            RequestorName     = "Test User",
            RequestorEmail    = "test@example.com",
            PageSize          = 100
        });

        private void StubToken() =>
            _server.Given(Request.Create().WithPath("/oauth/token").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json")
                    .WithBody(MockCertificateData.V2TokenResponseJson(3600)));

        private const string SslComPath = "/api/certinext/v2/organizations/" + OrgNumber + "/ca-validations/sslcom";

        [Fact]
        public async Task Client_Get_ReadsTheStatusFromTheDocumentedPath()
        {
            StubToken();
            _server.Given(Request.Create().WithPath(SslComPath).UsingGet())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json").WithBody(LiveNotSubmittedJson));

            using var client = BuildClient();
            var v = await client.GetSslComValidationAsync(OrgNumber);

            v.Status.Should().Be("NOT_SUBMITTED");
            v.Readiness.Ready.Should().BeTrue();
        }

        [Fact]
        public async Task Client_Sync_PostsWithoutABody_ToTheSyncPath()
        {
            StubToken();
            _server.Given(Request.Create().WithPath(SslComPath + "/sync").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json").WithBody(LiveNotSubmittedJson));

            using var client = BuildClient();
            var v = await client.SyncSslComValidationAsync(OrgNumber);

            v.Status.Should().Be("NOT_SUBMITTED");
            var entry = _server.LogEntries.Single(e => e.RequestMessage.Path.EndsWith("/sync"));
            entry.RequestMessage.Method.Should().Be("POST");
            (entry.RequestMessage.Body ?? string.Empty).Should().BeEmpty();
        }

        [Fact]
        public async Task Client_Submit_PostsLevelsAgreementFlagAndAdminEmail()
        {
            StubToken();
            _server.Given(Request.Create().WithPath(SslComPath).UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json").WithBody(@"{""status"":""SUBMITTED"",""levels"":[""OV""]}"));

            using var client = BuildClient();
            var v = await client.SubmitSslComValidationAsync(OrgNumber, new V2SslComSubmitRequest
            {
                Levels = new List<string> { "OV" }, SubscriberAgreementAccepted = true, AdminEmail = AdminEmail
            });

            v.Status.Should().Be("SUBMITTED");
            var entry = _server.LogEntries.Single(e => e.RequestMessage.Path == SslComPath);
            using var doc = JsonDocument.Parse(entry.RequestMessage.Body!);
            doc.RootElement.GetProperty("levels").EnumerateArray().Select(e => e.GetString()).Should().Equal("OV");
            doc.RootElement.GetProperty("subscriberAgreementAccepted").GetBoolean().Should().BeTrue();
            doc.RootElement.GetProperty("adminEmail").GetString().Should().Be(AdminEmail);
        }

        [Fact]
        public async Task Client_Submit_OmitsAdminEmailWhenUnset_AndToleratesAnEmptyResponseBody()
        {
            StubToken();
            _server.Given(Request.Create().WithPath(SslComPath).UsingPost())
                .RespondWith(Response.Create().WithStatusCode(204));

            using var client = BuildClient();
            var v = await client.SubmitSslComValidationAsync(OrgNumber, new V2SslComSubmitRequest
            {
                Levels = new List<string> { "EV" }, SubscriberAgreementAccepted = true
            });

            v.Should().BeNull();
            var entry = _server.LogEntries.Single(e => e.RequestMessage.Path == SslComPath);
            entry.RequestMessage.Body.Should().NotContain("adminEmail");
        }

        [Fact]
        public async Task Client_Get_EscapesTheOrganizationNumber_AndCaErrorsThrow()
        {
            StubToken();
            _server.Given(Request.Create().WithPath("/api/certinext/v2/organizations/*/ca-validations/sslcom").UsingGet())
                .RespondWith(Response.Create().WithStatusCode(404)
                    .WithHeader("Content-Type", "application/problem+json")
                    .WithBody(@"{""title"":""Not Found"",""status"":404,""detail"":""Organization not found""}"));

            using var client = BuildClient();
            Func<Task> act = () => client.GetSslComValidationAsync("a/b c");

            await act.Should().ThrowAsync<Exception>().WithMessage("*HTTP 404*");
            _server.LogEntries.Last().RequestMessage.Url.Should().Contain("a%2Fb");
        }

        // ---------------------------------------------------------------------------
        // Plugin
        // ---------------------------------------------------------------------------

        private static CERTInextConfig Config(bool submit = false, string adminEmail = null, string organizationNumber = OrgNumber) =>
            new CERTInextConfig
            {
                UseV2Api                 = true,
                ApiUrl                   = "https://v2.certinext.io",
                OAuthClientId            = "my-client",
                OAuthClientSecret        = "my-secret",
                RequestorName            = "Test User",
                RequestorEmail           = "test@example.com",
                SignerPlace              = "New York",
                OrganizationNumber       = organizationNumber,
                SslComSubmitOrganization = submit,
                SslComAdminEmail         = adminEmail,
                PickupRetries            = 0
            };

        private sealed class Harness
        {
            public Mock<ICERTInextClient> Mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            public List<string> Calls = new List<string>();
            public V2SslComSubmitRequest Submitted;
        }

        private static Harness NewHarness(
            Func<V2SslComValidation> get, Func<V2SslComValidation> sync = null, Func<V2SslComValidation> submit = null,
            Exception getError = null, Exception syncError = null, Exception submitError = null)
        {
            var h = new Harness();
            if (getError != null)
                h.Mock.Setup(c => c.GetSslComValidationAsync(OrgNumber, It.IsAny<CancellationToken>()))
                    .Callback(() => h.Calls.Add("get")).ThrowsAsync(getError);
            else if (get != null)
                h.Mock.Setup(c => c.GetSslComValidationAsync(OrgNumber, It.IsAny<CancellationToken>()))
                    .Callback(() => h.Calls.Add("get")).ReturnsAsync(() => get());
            if (syncError != null)
                h.Mock.Setup(c => c.SyncSslComValidationAsync(OrgNumber, It.IsAny<CancellationToken>()))
                    .Callback(() => h.Calls.Add("sync")).ThrowsAsync(syncError);
            else if (sync != null)
                h.Mock.Setup(c => c.SyncSslComValidationAsync(OrgNumber, It.IsAny<CancellationToken>()))
                    .Callback(() => h.Calls.Add("sync")).ReturnsAsync(() => sync());
            if (submitError != null)
                h.Mock.Setup(c => c.SubmitSslComValidationAsync(OrgNumber, It.IsAny<V2SslComSubmitRequest>(), It.IsAny<CancellationToken>()))
                    .Callback<string, V2SslComSubmitRequest, CancellationToken>((_, r, __) => { h.Calls.Add("submit"); h.Submitted = r; })
                    .ThrowsAsync(submitError);
            else if (submit != null)
                h.Mock.Setup(c => c.SubmitSslComValidationAsync(OrgNumber, It.IsAny<V2SslComSubmitRequest>(), It.IsAny<CancellationToken>()))
                    .Callback<string, V2SslComSubmitRequest, CancellationToken>((_, r, __) => { h.Calls.Add("submit"); h.Submitted = r; })
                    .ReturnsAsync(() => submit());

            h.Mock.Setup(c => c.PlaceOrderV2Async(
                    It.IsAny<string>(), It.IsAny<string>(),
                    It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback(() => h.Calls.Add("place"))
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = OrderId, Status = "pending-csr" });
            h.Mock.Setup(c => c.SubmitCsrV2Async(It.IsAny<string>(), OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Returns(Task.CompletedTask);
            h.Mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "pending-approval" });
            return h;
        }

        private static V2SslComValidation NotSubmitted(bool ready = true, bool evReady = true) => Parse(
            @"{""status"":""NOT_SUBMITTED"",""levels"":[],""defaultLevels"":[""OV""],""lastError"":""contact.person@example.org rejected""," +
            @"""readiness"":{""ready"":" + (ready ? "true" : "false") + @",""evReady"":" + (evReady ? "true" : "false") +
            @",""missing"":[],""evMissing"":[],""softMissing"":[""Organization phone number""]}," +
            @"""contact"":{""name"":""Placeholder"",""email"":""" + ContactEmail + @"""}}");

        private static V2SslComValidation Validated(string level) => Parse(
            @"{""status"":""VALIDATED"",""levels"":[{""level"":""" + level + @""",""status"":""VALIDATED"",""validTill"":""2099-01-01T00:00:00Z""}]}");

        private static Task<EnrollmentResult> EnrollAsync(CERTInextCAPlugin plugin, string productId = Constants.Products.OvSsl,
            string family = "ssl")
        {
            var p = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ProductFamily"] = family, ["DomainName"] = "example.com"
            };
            if (family == "private-pki") p["ProductVariant"] = "intranet-ssl";
            return plugin.Enroll(MockCertificateData.FakeCsrPem, "CN=example.com",
                new Dictionary<string, string[]> { ["dnsname"] = new[] { "example.com" } },
                new EnrollmentProductInfo { ProductID = productId, ProductParameters = p },
                RequestFormat.PKCS10, EnrollmentType.New);
        }

        [Fact]
        public async Task Ov_AlreadyValidated_OnlyReadsTheStatus_ThenPlacesTheOrder()
        {
            using var capture = new PluginLogCapture();
            var h = NewHarness(get: () => Validated("OV"));
            var plugin = new CERTInextCAPlugin(h.Mock.Object, Config(submit: true));

            var result = await EnrollAsync(plugin);

            result.CARequestID.Should().Be(OrderId);
            h.Calls.Should().Equal("get", "place");
            capture.Entries.Where(e => e.Level >= LogLevel.Warning).Should().BeEmpty();
        }

        [Fact]
        public async Task Ov_ValidatedAfterTheSyncRefresh_NoSubmit()
        {
            var h = NewHarness(get: () => NotSubmitted(), sync: () => Validated("OV"), submit: () => NotSubmitted());
            var plugin = new CERTInextCAPlugin(h.Mock.Object, Config(submit: true));

            await EnrollAsync(plugin);

            h.Calls.Should().Equal("get", "sync", "place");
        }

        [Fact]
        public async Task Ov_NotValidated_SubmitOff_WarnsOnce_NeverSubmits_AndStillPlacesTheOrder()
        {
            using var capture = new PluginLogCapture();
            var h = NewHarness(get: () => NotSubmitted(), sync: () => NotSubmitted());
            var plugin = new CERTInextCAPlugin(h.Mock.Object, Config(submit: false));

            var result = await EnrollAsync(plugin);

            result.CARequestID.Should().Be(OrderId);
            h.Calls.Should().Equal("get", "sync", "place");
            var warnings = capture.Entries.Where(e => e.Level == LogLevel.Warning).Select(e => e.Message).ToList();
            warnings.Should().ContainSingle();
            warnings[0].Should().Contain("has not validated organization " + OrgNumber)
                .And.Contain("NOT_SUBMITTED")
                .And.Contain("Organization phone number")
                .And.Contain("SslComSubmitOrganization is off")
                .And.Contain("placing the order anyway");
            // personal data: the SSL.com contact email and the email echoed inside lastError are masked
            warnings[0].Should().NotContain(ContactEmail).And.Contain("c***@example.org");
        }

        [Fact]
        public async Task Ov_NotValidated_SubmitOn_SubmitsOnce_AuditsFirst_WithTheSpecBody()
        {
            using var capture = new PluginLogCapture();
            var h = NewHarness(get: () => NotSubmitted(), sync: () => NotSubmitted(),
                submit: () => Parse(@"{""status"":""SUBMITTED"",""levels"":[{""level"":""OV"",""status"":""PENDING""}]}"));
            var plugin = new CERTInextCAPlugin(h.Mock.Object, Config(submit: true, adminEmail: AdminEmail));

            var result = await EnrollAsync(plugin);

            result.CARequestID.Should().Be(OrderId);
            h.Calls.Should().Equal("get", "sync", "submit", "place");
            h.Submitted.Levels.Should().Equal("OV");
            h.Submitted.SubscriberAgreementAccepted.Should().BeTrue();
            h.Submitted.AdminEmail.Should().Be(AdminEmail);

            var all = capture.Entries.Select(e => e.Message).ToList();
            int audit = all.FindIndex(m => m.Contains("submission attempt started"));
            int done = all.FindIndex(m => m.Contains("organization validation submitted"));
            audit.Should().BeGreaterOrEqualTo(0);
            done.Should().BeGreaterThan(audit, "the acceptance is audit-logged before the call");
            all[audit].Should().Contain("subscriber agreement").And.Contain(OrgNumber)
                .And.NotContain(AdminEmail).And.Contain("p***@example.com");
            // submitted but not yet validated: still warns, still places the order
            capture.Lines(LogLevel.Warning, "has not validated organization").Should().ContainSingle()
                .Which.Should().Contain("SubmittedThisCall=True");
        }

        [Fact]
        public async Task Ov_SubmitOn_ButNoAdminEmail_SendsNone()
        {
            var h = NewHarness(get: () => NotSubmitted(), sync: () => NotSubmitted(), submit: () => NotSubmitted());
            var plugin = new CERTInextCAPlugin(h.Mock.Object, Config(submit: true));

            await EnrollAsync(plugin);

            h.Submitted.AdminEmail.Should().BeNull();
        }

        [Fact]
        public async Task Ov_SubmitOn_ButNotReady_DoesNotSubmit_AndSaysWhy()
        {
            using var capture = new PluginLogCapture();
            var h = NewHarness(get: () => NotSubmitted(ready: false), sync: () => NotSubmitted(ready: false));
            var plugin = new CERTInextCAPlugin(h.Mock.Object, Config(submit: true));

            await EnrollAsync(plugin);

            h.Calls.Should().Equal("get", "sync", "place");
            capture.Lines(LogLevel.Warning, "has not validated organization").Should().ContainSingle()
                .Which.Should().Contain("not ready for OV");
        }

        [Fact]
        public async Task Ov_SubmitOn_NoReadinessInformation_IsTreatedAsNotReady()
        {
            var bare = Parse(@"{""status"":""NOT_SUBMITTED"",""levels"":[]}");
            var h = NewHarness(get: () => bare, sync: () => bare);
            var plugin = new CERTInextCAPlugin(h.Mock.Object, Config(submit: true));

            await EnrollAsync(plugin);

            h.Calls.Should().Equal("get", "sync", "place");
        }

        [Fact]
        public async Task Ov_SubmitOn_LevelAlreadyRequested_DoesNotSubmitAgain()
        {
            var pending = Parse(@"{""status"":""SUBMITTED"",""levels"":[{""level"":""OV"",""status"":""PENDING""}],
                ""readiness"":{""ready"":true,""evReady"":true,""missing"":[],""evMissing"":[]}}");
            var h = NewHarness(get: () => pending, sync: () => pending);
            var plugin = new CERTInextCAPlugin(h.Mock.Object, Config(submit: true));

            await EnrollAsync(plugin);

            h.Calls.Should().Equal("get", "sync", "place");
        }

        [Fact]
        public async Task Ev_UsesTheEvReadinessAndSubmitsTheEvLevel()
        {
            var notReadyForEv = NotSubmitted(ready: true, evReady: false);
            var h1 = NewHarness(get: () => notReadyForEv, sync: () => notReadyForEv);
            await EnrollAsync(new CERTInextCAPlugin(h1.Mock.Object, Config(submit: true)), Constants.Products.EvSsl);
            h1.Calls.Should().Equal("get", "sync", "place");

            var readyForEv = NotSubmitted(ready: false, evReady: true);
            var h2 = NewHarness(get: () => readyForEv, sync: () => readyForEv, submit: () => readyForEv);
            await EnrollAsync(new CERTInextCAPlugin(h2.Mock.Object, Config(submit: true)), Constants.Products.EvSsl);
            h2.Calls.Should().Equal("get", "sync", "submit", "place");
            h2.Submitted.Levels.Should().Equal("EV");
        }

        [Fact]
        public async Task StatusReadFails_WarnsAndStillPlacesTheOrder_WithNoFurtherSslComCalls()
        {
            using var capture = new PluginLogCapture();
            var h = NewHarness(get: null, getError: new Exception("CERTInext V2 API error during 'V2 SSL.com validation status'. HTTP 500. boom"));
            var plugin = new CERTInextCAPlugin(h.Mock.Object, Config(submit: true));

            var result = await EnrollAsync(plugin);

            result.CARequestID.Should().Be(OrderId);
            h.Calls.Should().Equal("get", "place");
            capture.Lines(LogLevel.Warning, "could not be read").Should().ContainSingle();
        }

        [Fact]
        public async Task SyncFails_WarnsAndStillEvaluatesTheEarlierStatus()
        {
            using var capture = new PluginLogCapture();
            var h = NewHarness(get: () => NotSubmitted(), syncError: new Exception("HTTP 500"), submit: () => NotSubmitted());
            var plugin = new CERTInextCAPlugin(h.Mock.Object, Config(submit: true));

            await EnrollAsync(plugin);

            h.Calls.Should().Equal("get", "sync", "submit", "place");
            capture.Lines(LogLevel.Warning, "validation refresh").Should().ContainSingle();
        }

        [Fact]
        public async Task SubmitFails_WarnsAndStillPlacesTheOrder()
        {
            using var capture = new PluginLogCapture();
            var h = NewHarness(get: () => NotSubmitted(), sync: () => NotSubmitted(), submitError: new Exception("HTTP 422"));
            var plugin = new CERTInextCAPlugin(h.Mock.Object, Config(submit: true));

            var result = await EnrollAsync(plugin);

            result.CARequestID.Should().Be(OrderId);
            h.Calls.Should().Equal("get", "sync", "submit", "place");
            capture.Lines(LogLevel.Warning, "submission failed").Should().ContainSingle();
        }

        [Theory]
        [InlineData("DV SSL", "ssl")]
        [InlineData("DV SSL", "private-pki")]
        public async Task DvAndPrivatePki_NeverCallSslCom(string productId, string family)
        {
            var h = NewHarness(get: () => NotSubmitted());
            if (family == "private-pki")
                h.Mock.Setup(c => c.PlaceOrderV2Async(
                        It.IsAny<string>(), It.IsAny<V2CreatePrivatePkiOrderRequest>(), It.IsAny<CancellationToken>()))
                    .Callback(() => h.Calls.Add("place"))
                    .ReturnsAsync(new V2CreateOrderResponse { OrderId = OrderId, Status = "pending-csr" });
            if (family == "private-pki")
            {
                h.Mock.Setup(c => c.SubmitCsrV2Async(Constants.ApiV2.FamilyPrivatePki, OrderId, It.IsAny<string>(), It.IsAny<CancellationToken>()))
                    .Returns(Task.CompletedTask);
                h.Mock.Setup(c => c.TrackOrderV2Async(Constants.ApiV2.FamilyPrivatePki, OrderId, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "pending-approval" });
            }
            var plugin = new CERTInextCAPlugin(h.Mock.Object, Config(submit: true));

            await EnrollAsync(plugin, productId, family);

            h.Calls.Should().Equal("place");
        }

        [Fact]
        public async Task Ov_WithoutOrganizationNumber_IsRejectedBeforeAnySslComCall()
        {
            var h = NewHarness(get: () => NotSubmitted());
            var plugin = new CERTInextCAPlugin(h.Mock.Object, Config(submit: true, organizationNumber: null));

            var result = await EnrollAsync(plugin);

            result.Status.Should().Be((int)EndEntityStatus.FAILED);
            h.Calls.Should().BeEmpty();
        }

        // ---------------------------------------------------------------------------
        // Settings
        // ---------------------------------------------------------------------------

        [Fact]
        public void Annotations_SslComSubmitOrganization_IsABooleanDefaultingToFalse_AndWarnsAboutTheAgreement()
        {
            var annotations = CERTInextCAPluginConfig.GetCAConnectorAnnotations();

            annotations.Should().ContainKey("SslComSubmitOrganization");
            var a = annotations["SslComSubmitOrganization"];
            a.Type.Should().Be("Boolean");
            a.DefaultValue.Should().Be(false);
            a.Comments.Should().ContainEquivalentOf("accepts SSL.com's subscriber agreement on the organization's behalf");
            annotations.Should().ContainKey("SslComAdminEmail");
            annotations["SslComAdminEmail"].Type.Should().Be("String");
            new CERTInextConfig().SslComSubmitOrganization.Should().BeFalse();
        }

        [Fact]
        public void Config_DeserializesTheSslComSettings()
        {
            var cfg = JsonSerializer.Deserialize<CERTInextConfig>(
                $"{{\"SslComSubmitOrganization\":true,\"SslComAdminEmail\":\"{AdminEmail}\"}}");
            cfg!.SslComSubmitOrganization.Should().BeTrue();
            cfg.SslComAdminEmail.Should().Be(AdminEmail);
        }

        private static Dictionary<string, object> Info(string key, object value) => new Dictionary<string, object>
        {
            ["UseV2Api"] = true,
            ["ApiUrl"] = "not-a-url",   // invalid on purpose: errors are collected with the one under test
            ["OAuthClientId"] = "id",
            ["OAuthClientSecret"] = "secret",
            ["SignerPlace"] = "NY",
            [key] = value
        };

        [Theory]
        [InlineData("yes")]
        [InlineData("true")]
        [InlineData(1)]
        public async Task ValidateCAConnectionInfo_RejectsNonBooleanSslComSubmitOrganization(object value)
        {
            var plugin = new CERTInextCAPlugin(new Mock<ICERTInextClient>(MockBehavior.Strict).Object);
            Func<Task> act = () => plugin.ValidateCAConnectionInfo(Info("SslComSubmitOrganization", value));
            await act.Should().ThrowAsync<AnyCAValidationException>().WithMessage("*SslComSubmitOrganization*must be true or false*");
        }

        [Theory]
        [InlineData("not-an-email")]
        [InlineData("two@@example.com")]
        [InlineData("a b@example.com")]
        [InlineData("a@nodot")]
        public async Task ValidateCAConnectionInfo_RejectsAMalformedSslComAdminEmail(string value)
        {
            var plugin = new CERTInextCAPlugin(new Mock<ICERTInextClient>(MockBehavior.Strict).Object);
            Func<Task> act = () => plugin.ValidateCAConnectionInfo(Info("SslComAdminEmail", value));
            await act.Should().ThrowAsync<AnyCAValidationException>().WithMessage("*SslComAdminEmail*");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_AcceptsTheSslComSettings()
        {
            var plugin = new CERTInextCAPlugin(new Mock<ICERTInextClient>(MockBehavior.Strict).Object);
            var info = Info("SslComSubmitOrganization", true);
            info["SslComAdminEmail"] = AdminEmail;
            Func<Task> act = () => plugin.ValidateCAConnectionInfo(info);

            var ex = await act.Should().ThrowAsync<AnyCAValidationException>();   // ApiUrl is invalid on purpose
            ex.Which.Message.Should().NotContain("SslComSubmitOrganization").And.NotContain("SslComAdminEmail");
        }
    }
}
