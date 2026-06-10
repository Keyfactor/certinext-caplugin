// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using FluentAssertions;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Pure unit tests (no live-API dependency) for the env-file parser used by
    /// <see cref="IntegrationTestFixture"/>.  See GitHub issue #8 — without quote
    /// stripping, a shell-style quoted line was being parsed with the quote characters
    /// included in the value.
    /// </summary>
    public class IntegrationTestFixtureTests
    {
        [Theory]
        [InlineData("plain", "plain")]
        [InlineData("  plain  ", "plain")]
        [InlineData("\"Keyfactor Plugin Test\"", "Keyfactor Plugin Test")]
        [InlineData("  \"Keyfactor Plugin Test\"  ", "Keyfactor Plugin Test")]
        [InlineData("'single quoted'", "single quoted")]
        [InlineData("\"\"", "")]               // empty quoted string
        [InlineData("''", "")]                 // empty single-quoted
        [InlineData("\"un-paired'", "\"un-paired'")] // mismatched quotes — leave alone
        [InlineData("\"", "\"")]               // single naked quote, length<2 after trim — leave alone
        [InlineData("", "")]
        [InlineData("   ", "")]
        public void ParseEnvValue_HandlesQuotingAndWhitespace(string input, string expected)
        {
            IntegrationTestFixture.ParseEnvValue(input).Should().Be(expected);
        }

        [Fact]
        public void ParseEnvValue_NullInput_ReturnsEmptyString()
        {
            IntegrationTestFixture.ParseEnvValue(null).Should().Be(string.Empty);
        }

        [Fact]
        public void ParseEnvValue_DoesNotStripEmbeddedQuotes()
        {
            // Quotes in the middle of the value must NOT be stripped; only matching
            // outer wrappers count.
            IntegrationTestFixture.ParseEnvValue("foo\"bar\"baz")
                .Should().Be("foo\"bar\"baz");
        }
    }
}
