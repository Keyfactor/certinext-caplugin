// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Helper that skips an xUnit test when integration credentials are absent.
    ///
    /// Usage at the top of every integration test method (which must be decorated
    /// with <c>[SkippableFact]</c> rather than plain <c>[Fact]</c>):
    /// <code>
    ///   IntegrationSkip.IfNotConfigured(_fixture);
    /// </code>
    ///
    /// This calls <see cref="Xunit.Skip.If"/> which throws the internal xUnit exception
    /// recognised by the <c>Xunit.SkippableFact</c> runner extension as a skip rather
    /// than a failure.
    /// </summary>
    public static class IntegrationSkip
    {
        private const string SkipMessage =
            "Integration credentials not configured in ~/.env_certinext " +
            "(CERTINEXT_API_URL and CERTINEXT_ACCESS_KEY are required).";

        /// <summary>
        /// Skips the calling test when <paramref name="fixture"/> is not configured
        /// with live API credentials.
        /// </summary>
        public static void IfNotConfigured(IntegrationTestFixture fixture)
        {
            Xunit.Skip.If(!fixture.IsConfigured, SkipMessage);
        }
    }
}
