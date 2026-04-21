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
    /// Verifies that each draft order created during live API testing appears in the
    /// GetOrderReport response.
    ///
    /// Draft orders are placed with <c>saveAndHold:"1"</c>.  They have a
    /// <c>requestNumber</c> but no <c>orderNumber</c> until they are submitted and
    /// approved.  All five orders below were successfully created against the sandbox
    /// account and should remain visible indefinitely in the order history.
    ///
    /// Product codes confirmed during testing:
    ///   838 — DV SSL        requestNumber 4572531551
    ///   839 — DV Wildcard   requestNumber 9149755266
    ///   840 — DV UCC        requestNumber 1611445122
    ///   842 — OV SSL        requestNumber 5546366498
    ///   846 — EV SSL        requestNumber 3932332114
    /// </summary>
    public class DraftOrderTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;

        public DraftOrderTests(IntegrationTestFixture fixture)
        {
            _fixture = fixture;
        }

        // ---------------------------------------------------------------------------
        // Helper
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Collects all entries from a single GetOrderReport page (page 1, the given
        /// pageSize).  Using a single page of 20 is sufficient for a recently active
        /// account; increase pageSize if the account has more interleaved activity.
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
        /// Draft DV SSL order (product code 838, requestNumber 4572531551) appears in
        /// the order report.
        /// </summary>
        [SkippableFact]
        public async Task DraftOrder_DvSsl_ExistsInOrderReport()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            const string requestNumber = "4572531551";

            var orders = await FetchPageAsync(20);

            orders.Should().Contain(
                e => e.RequestNumber == requestNumber,
                $"draft DV SSL order with requestNumber \"{requestNumber}\" should appear in GetOrderReport");
        }

        /// <summary>
        /// Draft DV SSL Wildcard order (product code 839, requestNumber 9149755266)
        /// appears in the order report.
        /// </summary>
        [SkippableFact]
        public async Task DraftOrder_DvSslWildcard_ExistsInOrderReport()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            const string requestNumber = "9149755266";

            var orders = await FetchPageAsync(20);

            orders.Should().Contain(
                e => e.RequestNumber == requestNumber,
                $"draft DV SSL Wildcard order with requestNumber \"{requestNumber}\" should appear in GetOrderReport");
        }

        /// <summary>
        /// Draft DV SSL UCC order (product code 840, requestNumber 1611445122) appears
        /// in the order report.
        /// </summary>
        [SkippableFact]
        public async Task DraftOrder_DvSslUcc_ExistsInOrderReport()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            const string requestNumber = "1611445122";

            var orders = await FetchPageAsync(20);

            orders.Should().Contain(
                e => e.RequestNumber == requestNumber,
                $"draft DV SSL UCC order with requestNumber \"{requestNumber}\" should appear in GetOrderReport");
        }

        /// <summary>
        /// Draft OV SSL order (product code 842, requestNumber 5546366498) appears in
        /// the order report.
        /// </summary>
        [SkippableFact]
        public async Task DraftOrder_OvSsl_ExistsInOrderReport()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            const string requestNumber = "5546366498";

            var orders = await FetchPageAsync(20);

            orders.Should().Contain(
                e => e.RequestNumber == requestNumber,
                $"draft OV SSL order with requestNumber \"{requestNumber}\" should appear in GetOrderReport");
        }

        /// <summary>
        /// Draft EV SSL order (product code 846, requestNumber 3932332114) appears in
        /// the order report.
        /// </summary>
        [SkippableFact]
        public async Task DraftOrder_EvSsl_ExistsInOrderReport()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            const string requestNumber = "3932332114";

            var orders = await FetchPageAsync(20);

            orders.Should().Contain(
                e => e.RequestNumber == requestNumber,
                $"draft EV SSL order with requestNumber \"{requestNumber}\" should appear in GetOrderReport");
        }
    }
}
