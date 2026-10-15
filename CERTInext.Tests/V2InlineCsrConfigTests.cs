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
using System.Text.Json;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// <c>V2InlineCsr</c> is an opt-in CA connector setting (V2 only, default false): when true,
    /// SSL/TLS enrollment sends the CSR inline in the create call instead of create + Submit CSR.
    /// </summary>
    public class V2InlineCsrConfigTests
    {
        [Fact]
        public void CERTInextConfig_DefaultsToFalse_TwoCallIsTheDefault()
        {
            new CERTInextConfig().V2InlineCsr.Should().BeFalse("the single-call create is opt-in");
        }

        [Fact]
        public void Constants_V2InlineCsr_MatchesJsonPropertyName()
        {
            Constants.Config.V2InlineCsr.Should().Be("V2InlineCsr");
        }

        [Theory]
        [InlineData("true", true)]
        [InlineData("false", false)]
        public void CERTInextConfig_Deserializes(string json, bool expected)
        {
            var cfg = JsonSerializer.Deserialize<CERTInextConfig>($"{{\"V2InlineCsr\":{json}}}");
            cfg!.V2InlineCsr.Should().Be(expected);
        }

        [Fact]
        public void GetCAConnectorAnnotations_ContainsV2InlineCsr_BooleanDefaultFalse_WithClearDescription()
        {
            var annotations = CERTInextCAPluginConfig.GetCAConnectorAnnotations();

            annotations.Should().ContainKey(Constants.Config.V2InlineCsr);
            var a = annotations[Constants.Config.V2InlineCsr];
            a.Type.Should().Be("Boolean");
            a.DefaultValue.Should().Be(false);
            a.Hidden.Should().BeFalse();
            a.Comments.Should().ContainAll("V2", "inline", "SSL/TLS", "Private PKI", "two-call", "do not resubmit", "Default: false");
        }

        private static CERTInextCAPlugin NewPlugin() =>
            new CERTInextCAPlugin(new Mock<ICERTInextClient>(MockBehavior.Strict).Object);

        private static Dictionary<string, object> Info(object inlineCsr) => new Dictionary<string, object>
        {
            ["UseV2Api"] = true,
            ["ApiUrl"] = "not-a-url",           // invalid on purpose: collected with the V2InlineCsr error
            ["OAuthClientId"] = "id",
            ["OAuthClientSecret"] = "secret",
            ["SignerPlace"] = "NY",
            ["V2InlineCsr"] = inlineCsr
        };

        [Theory]
        [InlineData("yes")]
        [InlineData("true")]   // a string would fail config deserialization, so it is rejected up front
        [InlineData(1)]
        public async Task ValidateCAConnectionInfo_RejectsNonBooleanV2InlineCsr(object value)
        {
            Func<Task> act = () => NewPlugin().ValidateCAConnectionInfo(Info(value));

            await act.Should().ThrowAsync<AnyCAValidationException>().WithMessage("*V2InlineCsr*must be true or false*");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_AcceptsBooleanV2InlineCsr_ErrorsAreOnlyTheOtherFields()
        {
            Func<Task> act = () => NewPlugin().ValidateCAConnectionInfo(Info(true));

            // ApiUrl is deliberately invalid, so validation still throws, but not about V2InlineCsr.
            var ex = await act.Should().ThrowAsync<AnyCAValidationException>();
            ex.Which.Message.Should().NotContain("V2InlineCsr");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_AcceptsJsonElementBoolean()
        {
            var el = JsonDocument.Parse("false").RootElement;
            Func<Task> act = () => NewPlugin().ValidateCAConnectionInfo(Info(el));

            var ex = await act.Should().ThrowAsync<AnyCAValidationException>();
            ex.Which.Message.Should().NotContain("V2InlineCsr");
        }
    }
}
