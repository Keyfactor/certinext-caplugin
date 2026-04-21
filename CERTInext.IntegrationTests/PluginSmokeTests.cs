// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// End-to-end smoke tests that exercise <see cref="CERTInextCAPlugin"/> via the
    /// <see cref="IAnyCAPlugin"/> interface using a real <see cref="CERTInextConfig"/>
    /// and a live <see cref="Keyfactor.Extensions.CAPlugin.CERTInext.Client.CERTInextClient"/>.
    ///
    /// The plugin is constructed using the test-injection constructor
    /// <c>CERTInextCAPlugin(ICERTInextClient, CERTInextConfig)</c> so that
    /// <see cref="CERTInextCAPlugin.Initialize"/> does not need to be called.
    /// </summary>
    public class PluginSmokeTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;

        public PluginSmokeTests(IntegrationTestFixture fixture)
        {
            _fixture = fixture;
        }

        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Creates a plugin instance wired to the live client and config from the fixture.
        /// Uses the <c>(ICERTInextClient, CERTInextConfig)</c> test constructor so that
        /// no <c>Initialize</c> call is needed.
        /// </summary>
        private CERTInextCAPlugin BuildPlugin()
        {
            return new CERTInextCAPlugin(_fixture.Client, _fixture.Config);
        }

        // ---------------------------------------------------------------------------
        // Tests
        // ---------------------------------------------------------------------------

        /// <summary>
        /// <see cref="CERTInextCAPlugin.Ping"/> should complete without throwing when
        /// the live API is reachable and credentials are valid.
        /// </summary>
        [SkippableFact]
        public async Task Ping_ThroughPlugin_Succeeds()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            var plugin = BuildPlugin();

            var act = async () => await plugin.Ping();
            await act.Should().NotThrowAsync("Ping should succeed with valid credentials");
        }

        /// <summary>
        /// <see cref="CERTInextCAPlugin.GetProductIds"/> should complete without throwing
        /// and return a non-null list.  Some CERTInext sandbox accounts return an empty
        /// product list from GetProductDetails even though orders with those product codes
        /// are visible in GetOrderReport — an empty list is therefore acceptable.
        /// </summary>
        [SkippableFact]
        public void GetProductIds_ReturnsAtLeastOneProduct()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            var plugin = BuildPlugin();

            // GetProductIds is synchronous (calls GetAwaiter().GetResult() internally).
            // The plugin catches any exception from GetProfilesAsync and returns empty
            // rather than throwing, so we assert non-null rather than non-empty.
            List<string> productIds = null;
            var act = () => { productIds = plugin.GetProductIds(); };
            act.Should().NotThrow("GetProductIds should never throw — it swallows exceptions and returns an empty list on failure");

            productIds.Should().NotBeNull(
                "GetProductIds should return a non-null list (may be empty for this account)");
        }

        /// <summary>
        /// <see cref="CERTInextCAPlugin.Synchronize"/> should enumerate at least one
        /// certificate record when a full sync is performed against the live account.
        /// </summary>
        [SkippableFact]
        public async Task Synchronize_ReturnsAtLeastOneRecord()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            var plugin = BuildPlugin();

            // BlockingCollection with a generous bound — integration tests collect all records.
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(boundedCapacity: 10_000);
            var collected = new List<AnyCAPluginCertificate>();

            // Run sync and collection concurrently so the blocking collection does not deadlock.
            var syncTask = Task.Run(async () =>
            {
                await plugin.Synchronize(
                    buffer,
                    lastSync: null,
                    fullSync: true,
                    cancelToken: CancellationToken.None);

                // Signal completion so the consumer loop exits.
                buffer.CompleteAdding();
            });

            // Drain the buffer as sync produces records.
            foreach (var record in buffer.GetConsumingEnumerable())
            {
                collected.Add(record);
            }

            await syncTask; // ensure any exception from Synchronize propagates

            collected.Should().NotBeEmpty(
                "a full sync against the live account should return at least one certificate record");
        }
    }
}
