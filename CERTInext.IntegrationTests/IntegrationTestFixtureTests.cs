// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
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

        [SkippableTheory]
        [InlineData("CERTINEXT_COMPLETE_PENDING")]
        [InlineData("CERTINEXT_RUN_BULK_TEST")]
        [InlineData("CERTINEXT_ALGO_MATRIX")]
        [InlineData("CERTINEXT_ALGO_MATRIX_DCV")]
        [InlineData("CERTINEXT_SAN_PROBE")]
        [InlineData("certinext_complete_pending")] // env-file keys are matched case-insensitively
        public void PromoteToProcessEnvironment_DoesNotPromoteOptInFlags(string flag)
        {
            Skip.If(Environment.GetEnvironmentVariable(flag) != null,
                $"{flag} is already set in the process environment; cannot verify it is not promoted.");

            IntegrationTestFixture.PromoteToProcessEnvironment(
                new Dictionary<string, string> { [flag] = "1" });

            Environment.GetEnvironmentVariable(flag).Should().BeNull(
                "opt-in flags must come from the real environment, never from ~/.env_certinext");
        }

        [Fact]
        public void PromoteToProcessEnvironment_PromotesOrdinaryKeys_WithoutOverridingRealEnv()
        {
            string fresh = "CERTINEXT_FIXTURE_TEST_" + Guid.NewGuid().ToString("N");
            string preset = "CERTINEXT_FIXTURE_TEST_" + Guid.NewGuid().ToString("N");
            try
            {
                Environment.SetEnvironmentVariable(preset, "from-shell");

                IntegrationTestFixture.PromoteToProcessEnvironment(new Dictionary<string, string>
                {
                    [fresh] = "from-file",
                    [preset] = "from-file",
                });

                Environment.GetEnvironmentVariable(fresh).Should().Be("from-file");
                Environment.GetEnvironmentVariable(preset).Should().Be("from-shell");
            }
            finally
            {
                Environment.SetEnvironmentVariable(fresh, null);
                Environment.SetEnvironmentVariable(preset, null);
            }
        }
    }
}
