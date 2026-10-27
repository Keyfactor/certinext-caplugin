// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// GetOrderReport / sync integration tests.
    /// Exercises the <see cref="Keyfactor.Extensions.CAPlugin.CERTInext.Client.ICERTInextClient.ListOrdersAsync"/>
    /// path that backs <c>Synchronize</c> in the plugin.
    ///
    /// Tests that require pre-existing orders skip gracefully on a fresh sandbox account
    /// rather than failing — use <c>LifecycleTests</c> to create orders first.
    /// </summary>
    public class OrderReportTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;

        public OrderReportTests(IntegrationTestFixture fixture)
        {
            _fixture = fixture;
        }

        // ---------------------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Collects up to <paramref name="limit"/> entries from a single call to
        /// ListOrdersAsync (page 1, pageSize = limit).  This avoids iterating the
        /// entire order history in test scenarios.
        /// </summary>
        private async Task<List<OrderReportEntry>> FetchFirstPageAsync(int limit = 10)
        {
            var results = new List<OrderReportEntry>();
            await foreach (var entry in _fixture.Client.ListOrdersAsync(
                orderDateFrom: null,
                pageSize: limit,
                ct: CancellationToken.None))
            {
                results.Add(entry);
                if (results.Count >= limit)
                    break;
            }
            return results;
        }

        // ---------------------------------------------------------------------------
        // Tests
        // ---------------------------------------------------------------------------

        /// <summary>
        /// GetOrderReport call completes without throwing.  When the account already has
        /// orders the result is non-empty; on a fresh sandbox account the collection may
        /// be empty and the test skips gracefully rather than failing.
        /// </summary>
        [SkippableFact]
        public async Task GetOrderReport_ReturnsOrders()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            var orders = await FetchFirstPageAsync(10);

            Skip.If(orders.Count == 0, "account has no orders yet — skipping");

            orders.Should().NotBeEmpty(
                "GetOrderReport should return at least one order for the configured account");
        }

        /// <summary>
        /// Every order returned by page 1 of GetOrderReport must have a non-empty
        /// requestNumber, non-empty productCode, and non-empty orderDate.
        /// Skips gracefully when the account has no orders yet.
        /// </summary>
        [SkippableFact]
        public async Task GetOrderReport_AllOrders_HaveRequiredFields()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            var orders = await FetchFirstPageAsync(10);

            Skip.If(orders.Count == 0, "account has no orders yet — skipping");

            foreach (var order in orders)
            {
                // requestNumber is always set (draft or formal order)
                order.RequestNumber.Should().NotBeNullOrWhiteSpace(
                    $"order entry should always have a requestNumber (orderNumber={order.OrderNumber})");

                // productCode identifies the certificate type
                order.ProductCode.Should().NotBeNullOrWhiteSpace(
                    $"order {order.RequestNumber} should have a productCode");

                // orderDate tells us when the order was placed
                order.OrderDate.Should().NotBeNullOrWhiteSpace(
                    $"order {order.RequestNumber} should have an orderDate");
            }
        }
    }
}
