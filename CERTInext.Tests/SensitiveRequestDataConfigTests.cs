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

using FluentAssertions;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// <c>LogSensitiveRequestData</c> is an opt-in CA connector setting, off by
    /// default, that gates whether requestor personal data and full CA request/response bodies
    /// are written to gateway logs.
    /// </summary>
    public class SensitiveRequestDataConfigTests
    {
        [Fact]
        public void CERTInextConfig_DefaultsToFalse()
        {
            new CERTInextConfig().LogSensitiveRequestData.Should().BeFalse(
                "sensitive-data logging must be opt-in, not opt-out");
        }

        [Fact]
        public void GetCAConnectorAnnotations_ContainsLogSensitiveRequestData()
        {
            var annotations = CERTInextCAPluginConfig.GetCAConnectorAnnotations();

            annotations.Should().ContainKey(Constants.Config.LogSensitiveRequestData);

            var annotation = annotations[Constants.Config.LogSensitiveRequestData];
            annotation.Type.Should().Be("Boolean");
            annotation.DefaultValue.Should().Be(false);
            annotation.Comments.Should().ContainAll("name", "email", "phone",
                "temporary", "Credentials");
        }

        [Fact]
        public void Constants_LogSensitiveRequestData_MatchesJsonPropertyName()
        {
            // The Dictionary key used by the Command UI/connector config must match the
            // [JsonPropertyName] on CERTInextConfig for the round-trip through
            // JsonSerializer.Serialize(configProvider.CAConnectionData) /
            // JsonSerializer.Deserialize<CERTInextConfig> in Initialize() to work.
            Constants.Config.LogSensitiveRequestData.Should().Be("LogSensitiveRequestData");
        }

        [Fact]
        public void CERTInextConfig_DeserializesLogSensitiveRequestData_WhenTrue()
        {
            string json = "{\"LogSensitiveRequestData\": true}";
            var config = System.Text.Json.JsonSerializer.Deserialize<CERTInextConfig>(json);

            config.Should().NotBeNull();
            config!.LogSensitiveRequestData.Should().BeTrue();
        }

        [Fact]
        public void CERTInextConfig_DeserializesLogSensitiveRequestData_OmittedField_DefaultsFalse()
        {
            string json = "{\"ApiUrl\": \"https://ca.example.com\"}";
            var config = System.Text.Json.JsonSerializer.Deserialize<CERTInextConfig>(json);

            config.Should().NotBeNull();
            config!.LogSensitiveRequestData.Should().BeFalse();
        }
    }
}
