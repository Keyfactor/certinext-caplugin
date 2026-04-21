// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Tests related to the TrackOrder workflow and order-number semantics.
    ///
    /// Background: TrackOrder requires an <c>orderNumber</c>, which CERTInext assigns
    /// only after an order is submitted and approved.  Draft orders (created with
    /// <c>saveAndHold:"1"</c>) are held in an "On Hold" state and never receive an
    /// <c>orderNumber</c>.  They are identifiable only by their <c>requestNumber</c>.
    ///
    /// These tests confirm that invariant by locating a known draft order in the
    /// GetOrderReport results and asserting its <c>orderNumber</c> is absent.
    /// </summary>
    public class TrackOrderTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;

        // DV SSL draft order confirmed "On Hold" on this account.
        private const string DraftRequestNumber = "4572531551";

        public TrackOrderTests(IntegrationTestFixture fixture)
        {
            _fixture = fixture;
        }

        // ---------------------------------------------------------------------------
        // Helper
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Fetches up to <paramref name="pageSize"/> entries from GetOrderReport (page 1).
        /// </summary>
        private async Task<List<OrderReportEntry>> FetchPageAsync(int pageSize = 20)
        {
            var results = new List<OrderReportEntry>();
            await foreach (var entry in _fixture.Client.ListOrdersAsync(
                orderDateFrom: null,
                pageSize: pageSize,
                ct: CancellationToken.None))
            {
                results.Add(entry);
                if (results.Count >= pageSize)
                    break;
            }
            return results;
        }

        // ---------------------------------------------------------------------------
        // Tests
        // ---------------------------------------------------------------------------

        /// <summary>
        /// A draft order that was created with saveAndHold:"1" and has never been
        /// submitted should have an empty/null orderNumber in GetOrderReport.
        ///
        /// This confirms that the plugin must not attempt to call TrackOrder for orders
        /// that lack an orderNumber — doing so would supply an empty string to the API
        /// and result in an error response.
        /// </summary>
        [SkippableFact]
        public async Task TrackOrder_DraftOrder_HasNoOrderNumber()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            var orders = await FetchPageAsync(20);

            // Locate the known draft order by requestNumber.
            var draft = orders.Find(e => e.RequestNumber == DraftRequestNumber);

            draft.Should().NotBeNull(
                $"draft order with requestNumber \"{DraftRequestNumber}\" must appear in GetOrderReport " +
                "before we can assert its orderNumber field");

            // Explicit null guard so the compiler knows draft is non-null on the next line.
            // The FluentAssertions assertion above will already fail the test if draft is null.
            if (draft == null) return;

            // Draft orders (saveAndHold / On Hold) do not have an orderNumber yet.
            // The field should be null or an empty string.
            (string.IsNullOrEmpty(draft.OrderNumber)).Should().BeTrue(
                $"draft order requestNumber \"{DraftRequestNumber}\" is On Hold and has not been " +
                "submitted, so its orderNumber should be null or empty — TrackOrder cannot be called for it");
        }
    }
}
