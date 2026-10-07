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
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Parser-level coverage for <c>CERTInextClient.ExtractErrorMessage</c>, which
    /// builds the V1 non-success exception message.
    /// </summary>
    public class ExtractErrorMessageTests
    {
        private const string Op = "list orders page 1";

        [Fact]
        public void LiveSpringNotFoundBody_WithStatus_ReturnsGenericMessageWithHttpStatus()
        {
            CERTInextClient.ExtractErrorMessage(V1NonSuccessResponseTests.LiveSpringNotFoundBody, Op, 404)
                .Should().Be("CERTInext returned an unrecognised error body (HTTP 404) for operation 'list orders page 1'. " +
                             "See gateway logs for details.");
        }

        [Fact]
        public void LiveSpringNotFoundBody_WithoutStatus_KeepsPreviousMessage()
        {
            // RevokeOrderAsync still calls the two-argument form; its message must not change.
            CERTInextClient.ExtractErrorMessage(V1NonSuccessResponseTests.LiveSpringNotFoundBody, Op)
                .Should().Be("CERTInext returned an unrecognised error body for operation 'list orders page 1'. " +
                             "See gateway logs for details.");
        }

        [Theory]
        [InlineData("<html><body>Bad Gateway</body></html>")]
        [InlineData("[]")]
        public void NonEnvelopeBody_WithStatus_ReturnsGenericMessageWithHttpStatus(string body)
        {
            CERTInextClient.ExtractErrorMessage(body, Op, 502)
                .Should().StartWith("CERTInext returned an unrecognised error body (HTTP 502) for operation");
        }

        [Fact]
        public void MetaEnvelope_WithStatus_IncludesStatusAndCaError()
        {
            const string body = "{\"meta\":{\"status\":\"0\",\"errorCode\":\"EMS-913\",\"errorMessage\":\"Invalid Account Number\"}}";

            CERTInextClient.ExtractErrorMessage(body, Op, 500)
                .Should().Be("CERTInext error during 'list orders page 1' (HTTP 500): Invalid Account Number [EMS-913]");
        }

        [Fact]
        public void LegacyMessageBody_WithStatus_IncludesStatusAndMessage()
        {
            CERTInextClient.ExtractErrorMessage("{\"message\":\"Service Unavailable\"}", Op, 503)
                .Should().Be("CERTInext error during 'list orders page 1' (HTTP 503): Service Unavailable");
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void EmptyBody_WithStatus_IncludesStatus(string body)
        {
            CERTInextClient.ExtractErrorMessage(body, Op, 404)
                .Should().Be("CERTInext returned no body (HTTP 404) for operation 'list orders page 1'.");
        }
    }
}
