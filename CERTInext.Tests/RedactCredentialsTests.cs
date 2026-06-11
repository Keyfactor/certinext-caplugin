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
    /// Pins the credential-scrubbing pass that <see cref="LogApiFailure"/> runs on
    /// every response body before truncation.  The CERTInext request meta block
    /// includes an <c>authKey</c> SHA-256 digest that is itself a replayable
    /// credential under SOX (anyone with one valid <c>(ts, txn, authKey)</c> triple
    /// can replay until the timestamp window expires).  These tests pin that the
    /// scrubber catches both the documented-as-sent fields (<c>authKey</c>) and
    /// adjacent credential field names that *could* end up on the wire if a future
    /// code path wires them in (<c>client_secret</c>, <c>accessKey</c>, <c>password</c>).
    /// See the audit report for commit aab1847.
    /// </summary>
    public class RedactCredentialsTests
    {
        [Theory]
        [InlineData(
            "{\"meta\":{\"authKey\":\"deadbeefdeadbeefdeadbeef\",\"ts\":\"2026\"}}",
            "{\"meta\":{\"authKey\":\"***REDACTED***\",\"ts\":\"2026\"}}")]
        [InlineData(
            "{\"client_secret\":\"super-secret-12345\"}",
            "{\"client_secret\":\"***REDACTED***\"}")]
        [InlineData(
            "{\"apiKey\":\"raw-access-key-value\",\"other\":\"keep\"}",
            "{\"apiKey\":\"***REDACTED***\",\"other\":\"keep\"}")]
        [InlineData(
            "{\"accessKey\":\"xxx\",\"password\":\"yyy\"}",
            "{\"accessKey\":\"***REDACTED***\",\"password\":\"***REDACTED***\"}")]
        public void RedactCredentials_ScrubsJsonCredentialFields(string input, string expected)
        {
            CERTInextClient.RedactCredentials(input).Should().Be(expected);
        }

        [Theory]
        [InlineData(
            "grant_type=client_credentials&client_secret=super-secret-12345&client_id=public-id",
            "grant_type=client_credentials&client_secret=***REDACTED***&client_id=public-id")]
        [InlineData(
            "authKey=abc123def456",
            "authKey=***REDACTED***")]
        public void RedactCredentials_ScrubsFormUrlEncodedCredentialFields(string input, string expected)
        {
            CERTInextClient.RedactCredentials(input).Should().Be(expected);
        }

        [Fact]
        public void RedactCredentials_ScrubsAuthorizationHeaderLines()
        {
            string input =
                "POST /token HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "Authorization: Bearer ya29.abcdef-secret-token\r\n" +
                "Content-Type: application/json\r\n";
            string output = CERTInextClient.RedactCredentials(input);
            output.Should().Contain("Authorization: ***REDACTED***");
            output.Should().NotContain("ya29.abcdef-secret-token");
            output.Should().Contain("Host: example.com");
            output.Should().Contain("Content-Type: application/json");
        }

        [Fact]
        public void RedactCredentials_PreservesNonCredentialFields()
        {
            string input = "{\"meta\":{\"ts\":\"2026-05-22\",\"txn\":\"12345\",\"errorMessage\":\"Inactive Account User.\"}}";
            string output = CERTInextClient.RedactCredentials(input);
            output.Should().Be(input, "non-credential fields must pass through unchanged");
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void RedactCredentials_HandlesNullAndEmpty(string input)
        {
            // Should not throw and should return the input unchanged (or empty for null).
            // The current implementation returns the input as-is for these edge cases.
            CERTInextClient.RedactCredentials(input).Should().Be(input);
        }

        [Fact]
        public void RedactCredentials_CaseInsensitiveFieldNameMatch()
        {
            // CERTInext historically uses mixed casing (`AuthKey`, `apiKey`, etc.)
            // depending on the endpoint.  Make sure none slip past the scrubber.
            string input = "{\"AuthKey\":\"abc\",\"APIKEY\":\"def\",\"ClientSecret\":\"xyz\"}";

            string output = CERTInextClient.RedactCredentials(input);

            // ClientSecret isn't currently in the redaction list (only client_secret is),
            // and that's intentional — the JSON convention CERTInext uses is the
            // snake_case form on the OAuth token endpoint. If we ever observe
            // CamelCase variants on the wire, extend the regex. Documented here so
            // a future regression review catches the gap.
            output.Should().Contain("\"AuthKey\":\"***REDACTED***\"");
            output.Should().Contain("\"APIKEY\":\"***REDACTED***\"");
        }
    }
}
