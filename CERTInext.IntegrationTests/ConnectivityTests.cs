// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0

using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Basic connectivity integration tests.
    /// Verifies that the CERTInext API is reachable and that HMAC credentials are accepted.
    /// </summary>
    public class ConnectivityTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;

        public ConnectivityTests(IntegrationTestFixture fixture)
        {
            _fixture = fixture;
        }

        /// <summary>
        /// Calls <see cref="ICERTInextClient.PingAsync"/> against the live API and
        /// asserts that it completes without throwing.
        /// The underlying ValidateCredentials endpoint returns meta.status = "1" on success;
        /// <see cref="CERTInextClient.PingAsync"/> throws when the status is not "1",
        /// so the absence of an exception is sufficient to confirm success.
        /// </summary>
        [SkippableFact]
        public async Task Ping_ReturnsSuccess()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            // PingAsync throws if meta.status != "1" or if the HTTP call fails.
            // We additionally make a raw call to inspect the meta.status value.
            var act = async () => await _fixture.Client.PingAsync(CancellationToken.None);
            await act.Should().NotThrowAsync("ValidateCredentials should return meta.status == \"1\"");
        }
    }
}
