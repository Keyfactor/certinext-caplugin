// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using FluentAssertions;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Pure unit tests for the rate-limit-retry helpers in <see cref="CERTInextClient"/>.
    /// Behavioral / end-to-end coverage of the retry loop itself lives in the WireMock
    /// tests; here we pin the predicate and the backoff schedule.
    /// </summary>
    public class RateLimitRetryTests
    {
        [Theory]
        [InlineData("Inactive Account User.", true)]                       // exact form from sandbox
        [InlineData("inactive account user.", true)]                       // case-insensitive
        [InlineData("INACTIVE ACCOUNT USER", true)]                        // case + missing period
        [InlineData("Some preamble: Inactive Account User. Tail", true)]   // embedded substring
        [InlineData("Active account user.", false)]                        // wrong polarity
        [InlineData("Account is inactive", false)]                         // similar phrase, wrong wording
        [InlineData("EMS-956 Invalid Request for this API.", false)]       // unrelated error
        [InlineData("", false)]
        [InlineData(null, false)]
        public void IsRateLimitSurface_DetectsDocumentedPhraseOnly(string errorMessage, bool expected)
        {
            CERTInextClient.IsRateLimitSurface(errorMessage).Should().Be(expected);
        }

        [Theory]
        [InlineData(1, 0.75, 1.25)]   // base = 1s, jittered ±25% ⇒ [0.75, 1.25]
        [InlineData(2, 1.5, 2.5)]    // 2s × jitter
        [InlineData(3, 3.0, 5.0)]    // 4s × jitter
        [InlineData(4, 6.0, 10.0)]   // 8s × jitter
        [InlineData(5, 12.0, 20.0)]  // 16s × jitter
        public void ComputeRateLimitBackoffSeconds_ProducesExpectedRange(int attempt, double min, double max)
        {
            // Run several samples so jitter is exercised; every sample must fall inside
            // the documented exponential ± 25% jitter window.
            for (int i = 0; i < 50; i++)
            {
                double waitSeconds = CERTInextClient.ComputeRateLimitBackoffSeconds(attempt);
                waitSeconds.Should().BeInRange(min, max,
                    $"attempt {attempt} sample {i} must fall inside the documented backoff window");
            }
        }

        [Fact]
        public void ComputeRateLimitBackoffSeconds_ClampsAttemptsBelowOneToOne()
        {
            // Defensive: passing 0 or negative shouldn't produce zero / negative delay.
            CERTInextClient.ComputeRateLimitBackoffSeconds(0)
                .Should().BeInRange(0.75, 1.25);
            CERTInextClient.ComputeRateLimitBackoffSeconds(-3)
                .Should().BeInRange(0.75, 1.25);
        }
    }
}
