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
using FluentAssertions;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Pure unit tests (no live API) for <see cref="TestOutputScrub"/>, which keeps CA-echoed
    /// email addresses out of <c>ITestOutputHelper</c> output.
    /// </summary>
    public class TestOutputScrubTests
    {
        [Fact]
        public void Scrub_NullInput_ReturnsNull()
        {
            TestOutputScrub.Scrub(null).Should().BeNull();
        }

        [Theory]
        [InlineData("Requestor jane.doe+test@example.com is invalid", "Requestor <email> is invalid")]
        [InlineData("a@b.io and c_d@e-f.org", "<email> and <email>")]
        [InlineData("no address here", "no address here")]
        public void Scrub_MasksEmailAddresses(string input, string expected)
        {
            TestOutputScrub.Scrub(input).Should().Be(expected);
        }

        [Fact]
        public void Scrub_TruncatesTo500Characters()
        {
            TestOutputScrub.Scrub(new string('x', 800)).Should().HaveLength(500);
        }

        [Fact]
        public void Describe_ScrubsMessageAndInnerExceptionMessages()
        {
            var ex = new InvalidOperationException(
                "CA rejected contact poc@example.com",
                new ArgumentException("inner echoes requestor@example.org"));

            string text = TestOutputScrub.Describe(ex);

            text.Should().NotContain("@example");
            text.Should().Contain("InvalidOperationException: CA rejected contact <email>");
            text.Should().Contain("ArgumentException: inner echoes <email>");
        }

        [Fact]
        public void Describe_NullException_ReturnsNull()
        {
            TestOutputScrub.Describe(null).Should().BeNull();
        }
    }
}
