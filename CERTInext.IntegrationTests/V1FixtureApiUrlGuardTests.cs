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
using System.Collections;
using System.IO;
using FluentAssertions;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Pure offline regression tests (no live-API dependency, no process-env mutation, so they
    /// are safe to run in parallel with every other class):
    /// <list type="bullet">
    ///   <item>the V1 fixture's <see cref="IntegrationTestFixture.EnsureV1ApiUrl"/> guard
    ///   rejects a V2 base URL with an actionable message that never echoes secrets;</item>
    ///   <item><see cref="V2EnvHelper.PromotableKeys"/> never promotes a key the V1 side reads,
    ///   nor any of the fixture's opt-in-only flags.</item>
    /// </list>
    /// </summary>
    public class V1FixtureApiUrlGuardTests
    {
        private const string V1Url = "https://sandbox-us-api.certinext.io/emSignHub-API";
        private const string V2Url = "https://sandbox-us-api.certinext.io";

        // -------------------------------------------------------------------------
        // (D) fail-fast guard
        // -------------------------------------------------------------------------

        [Theory]
        [InlineData(V1Url)]
        [InlineData(V1Url + "/")]
        [InlineData("https://api.certinext.io/emsignhub-api/")] // case-insensitive
        [InlineData("")]                                         // unconfigured: nothing to check
        [InlineData(null)]
        public void EnsureV1ApiUrl_V1OrEmptyUrl_DoesNotThrow(string apiUrl)
        {
            Action act = () => IntegrationTestFixture.EnsureV1ApiUrl(apiUrl, fromProcessEnvironment: false);
            act.Should().NotThrow();
        }

        [Theory]
        [InlineData(V2Url, true)]
        [InlineData(V2Url + "/", false)]
        [InlineData("https://sandbox-us-api.certinext.io/v2", true)]
        public void EnsureV1ApiUrl_V2BaseUrl_ThrowsActionableMessage(string apiUrl, bool fromProcessEnv)
        {
            Action act = () => IntegrationTestFixture.EnsureV1ApiUrl(apiUrl, fromProcessEnv);

            var ex = act.Should().Throw<InvalidOperationException>().Which;
            ex.Message.Should().Contain("CERTINEXT_API_URL")
                .And.Contain("/emSignHub-API")
                .And.Contain("V2 base URL")
                .And.Contain("set -a; . ~/.env_certinext; set +a")
                .And.Contain("~/.env_certinext_v2");
            ex.Message.Should().Contain(fromProcessEnv ? "process environment" : "(from ~/.env_certinext)");
        }

        [Fact]
        public void EnsureV1ApiUrl_UrlWithUserInfoAndQuery_NeverEchoesThem()
        {
            Action act = () => IntegrationTestFixture.EnsureV1ApiUrl(
                "https://someuser:not-a-real-secret@sandbox-us-api.certinext.io/?token=not-a-real-token",
                fromProcessEnvironment: true);

            var ex = act.Should().Throw<InvalidOperationException>().Which;
            ex.Message.Should().Contain("sandbox-us-api.certinext.io");
            ex.Message.Should().NotContain("someuser")
                .And.NotContain("not-a-real-secret")
                .And.NotContain("not-a-real-token");
        }

        /// <summary>
        /// End-to-end offline composition of the shell-overlay path: a correct V1 file, a
        /// V2 <c>CERTINEXT_API_URL</c> in the (simulated) process environment. Real env vars keep
        /// precedence (documented behaviour), and the guard then rejects the leaked value — the
        /// same two steps the fixture constructor runs before it builds any client.
        /// </summary>
        [Fact]
        public void LoadEnvFile_ProcessEnvV2UrlOverridesV1File_GuardRejectsIt()
        {
            string path = Path.Combine(Path.GetTempPath(), $"certinext-v1url-{Guid.NewGuid():N}.env");
            try
            {
                File.WriteAllLines(path, new[]
                {
                    $"CERTINEXT_API_URL={V1Url}",
                    "CERTINEXT_ACCESS_KEY=dummy-access-key",
                });
                var processEnv = new Hashtable { ["CERTINEXT_API_URL"] = V2Url };

                var env = IntegrationTestFixture.LoadEnvFile(path, processEnv);

                env["CERTINEXT_API_URL"].Should().Be(V2Url, "real env vars still override the file");
                Action act = () => IntegrationTestFixture.EnsureV1ApiUrl(env["CERTINEXT_API_URL"], true);
                act.Should().Throw<InvalidOperationException>()
                    .Which.Message.Should().NotContain("dummy-access-key");
            }
            finally
            {
                File.Delete(path);
            }
        }

        // -------------------------------------------------------------------------
        // (B) V2EnvHelper no longer promotes V1-shared keys
        // -------------------------------------------------------------------------

        [Fact]
        public void PromotableKeys_ExcludesEveryV1Key_KeepsV2OnlyKeys()
        {
            // Mirrors the key set ~/.env_certinext_v2 defines today (names only).
            string[] v2FileKeys =
            {
                "CERTINEXT_ACCOUNT_NUMBER", "CERTINEXT_API_URL", "CERTINEXT_CF_API_TOKEN",
                "CERTINEXT_CF_ZONE_ID", "CERTINEXT_CLIENT_ID", "CERTINEXT_CLIENT_SECRET",
                "CERTINEXT_DCV_DOMAIN", "CERTINEXT_GROUP_NUMBER", "CERTINEXT_ORG_NUMBER",
                "CERTINEXT_PRODUCT_CODE", "CERTINEXT_REQUESTOR_EMAIL", "CERTINEXT_REQUESTOR_MOBILE",
                "CERTINEXT_REQUESTOR_NAME", "CERTINEXT_SIGNER_IP", "CERTINEXT_USE_V2_API",
                "certinext_api_url", // case-insensitive match
            };

            var promoted = V2EnvHelper.PromotableKeys(v2FileKeys);

            promoted.Should().BeEquivalentTo(
                "CERTINEXT_CLIENT_ID", "CERTINEXT_CLIENT_SECRET", "CERTINEXT_REQUESTOR_MOBILE",
                "CERTINEXT_SIGNER_IP", "CERTINEXT_USE_V2_API");
        }

        /// <summary>
        /// If a developer ever left one of the fixture's opt-in-only flags (e.g.
        /// CERTINEXT_V2_OPS_TESTS, CERTINEXT_PRIVATE_PKI_LIVE) in ~/.env_certinext_v2, it must
        /// NOT come back out of <see cref="V2EnvHelper.PromotableKeys"/> — otherwise the first
        /// test class constructed in a run reads the flag as unset, then promotes it into real
        /// process env, silently arming every later-constructed test class in the same run even
        /// though nothing was ever exported in the shell. Covers every flag in
        /// <see cref="IntegrationTestFixture._optInOnlyFlags"/>, so a future addition to that set
        /// is covered automatically.
        /// </summary>
        [Fact]
        public void PromotableKeys_ExcludesEveryOptInOnlyFlag()
        {
            var promoted = V2EnvHelper.PromotableKeys(IntegrationTestFixture._optInOnlyFlags);

            promoted.Should().BeEmpty(
                "every opt-in-only flag must be excluded from V2-file promotion, or a value left " +
                "in ~/.env_certinext_v2 could silently arm a later test in the same run");
        }

        [Theory]
        [InlineData("CERTINEXT_API_URL")]
        [InlineData("CERTINEXT_ACCESS_KEY")]
        [InlineData("CERTINEXT_ACCOUNT_NUMBER")]
        [InlineData("CERTINEXT_GROUP_NUMBER")]
        [InlineData("CERTINEXT_ORG_NUMBER")]
        [InlineData("CERTINEXT_PRODUCT_CODE")]
        [InlineData("CERTINEXT_REQUESTOR_EMAIL")]
        [InlineData("CERTINEXT_REQUESTOR_NAME")]
        [InlineData("CERTINEXT_CF_API_TOKEN")]
        [InlineData("CERTINEXT_CF_ZONE_ID")]
        [InlineData("CERTINEXT_DCV_DOMAIN")] // read from process env by V1 DcvLifecycleTests
        public void V1EnvKeys_CoversEveryKeyTheV1SideReads(string key)
        {
            IntegrationTestFixture.V1EnvKeys.Should().Contain(key);
        }
    }
}
