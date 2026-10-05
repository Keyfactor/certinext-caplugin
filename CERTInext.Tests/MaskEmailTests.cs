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
using Keyfactor.Extensions.CAPlugin.CERTInext.Models;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Issue 0040: <see cref="LogSanitizer.MaskEmail"/> is the shared email-masking helper used
    /// by both <c>CERTInextCAPlugin</c> (the enrollment-attempt Information log line) and
    /// <c>Client.CERTInextClient</c> (<c>RedactPersonalData</c>) when <c>LogSensitiveRequestData</c>
    /// is off.
    /// </summary>
    public class MaskEmailTests
    {
        [Theory]
        [InlineData("jane.doe@example.com", "j***@example.com")]
        [InlineData("a@b.co", "a***@b.co")]
        [InlineData("Jane.Doe@Example.COM", "J***@Example.COM")]
        public void MaskEmail_KeepsFirstCharacterAndDomain(string input, string expected)
        {
            LogSanitizer.MaskEmail(input).Should().Be(expected);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void MaskEmail_HandlesNullAndEmpty(string input)
        {
            LogSanitizer.MaskEmail(input).Should().Be(input);
        }

        [Theory]
        [InlineData("not-an-email")]
        [InlineData("@example.com")]
        public void MaskEmail_NoUsableLocalPart_FallsBackToFullRedaction(string input)
        {
            LogSanitizer.MaskEmail(input).Should().Be("***REDACTED***");
        }
    }
}
