// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

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
    /// From 2.0.0 <c>UseV2Api</c> is optional and defaults to true: the V1 API no longer works, so a
    /// connector that doesn't set it runs on V2. Only an explicit false selects V1.
    /// </summary>
    public class UseV2ApiDefaultTests
    {
        [Fact]
        public void CERTInextConfig_DefaultsToV2()
        {
            new CERTInextConfig().UseV2Api.Should().BeTrue();
        }

        [Theory]
        [InlineData("{}", true)]
        [InlineData("{\"UseV2Api\":true}", true)]
        [InlineData("{\"UseV2Api\":false}", false)]
        public void CERTInextConfig_Deserializes_MissingMeansV2(string json, bool expected)
        {
            JsonSerializer.Deserialize<CERTInextConfig>(json)!.UseV2Api.Should().Be(expected);
        }

        [Fact]
        public void GetCAConnectorAnnotations_UseV2Api_IsOptionalBooleanDefaultTrue()
        {
            var a = CERTInextCAPluginConfig.GetCAConnectorAnnotations()[Constants.ConfigV2.UseV2Api];
            a.Type.Should().Be("Boolean");
            a.DefaultValue.Should().Be(true);
            a.Hidden.Should().BeFalse();
            a.Comments.Should().ContainAll("OPTIONAL", "Default: true");
        }

        public static IEnumerable<object[]> ResolveCases() => new[]
        {
            new object[] { null, true },
            new object[] { true, true },
            new object[] { false, false },
            new object[] { JsonDocument.Parse("true").RootElement, true },
            new object[] { JsonDocument.Parse("false").RootElement, false },
        };

        [Theory]
        [MemberData(nameof(ResolveCases))]
        public void ResolveUseV2Api_OnlyExplicitFalseSelectsV1(object value, bool expected)
        {
            var info = new Dictionary<string, object> { ["UseV2Api"] = value };
            CERTInextCAPlugin.ResolveUseV2Api(info).Should().Be(expected);
        }

        [Fact]
        public void ResolveUseV2Api_MissingKeyMeansV2()
        {
            CERTInextCAPlugin.ResolveUseV2Api(new Dictionary<string, object>()).Should().BeTrue();
        }

        private static CERTInextCAPlugin NewPlugin() =>
            new CERTInextCAPlugin(new Mock<ICERTInextClient>(MockBehavior.Strict).Object);

        [Fact]
        public async Task ValidateCAConnectionInfo_UseV2ApiUnset_AppliesV2Requirements()
        {
            var info = new Dictionary<string, object> { ["ApiUrl"] = "https://ca.example.com" };

            Func<Task> act = () => NewPlugin().ValidateCAConnectionInfo(info);

            var ex = (await act.Should().ThrowAsync<AnyCAValidationException>()).Which;
            ex.Message.Should().ContainAll("OAuthClientId", "OAuthClientSecret", "SignerPlace");
            ex.Message.Should().NotContain("AccountNumber");
        }

        [Fact]
        public async Task ValidateCAConnectionInfo_UseV2ApiFalse_AppliesV1Requirements()
        {
            var info = new Dictionary<string, object>
            {
                ["UseV2Api"] = false,
                ["ApiUrl"] = "https://ca.example.com",
            };

            Func<Task> act = () => NewPlugin().ValidateCAConnectionInfo(info);

            var ex = (await act.Should().ThrowAsync<AnyCAValidationException>()).Which;
            ex.Message.Should().Contain("AccountNumber");
            ex.Message.Should().NotContain("OAuthClientId");
        }
    }
}
