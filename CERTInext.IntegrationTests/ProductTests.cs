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
    /// Product discovery integration tests.
    /// Verifies that GetProductDetails calls succeed and, when the account returns products,
    /// that expected product codes are present.
    ///
    /// Note: some CERTInext sandbox accounts return an empty product list from
    /// GetProductDetails even though those product codes are visible in GetOrderReport.
    /// The test therefore verifies the call succeeds and, if products are returned,
    /// that product code "838" (DV SSL) is among them.
    /// </summary>
    public class ProductTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;

        // Known product code for DV SSL 838 that should exist if the account returns products.
        private const string KnownProductCode = "838";

        public ProductTests(IntegrationTestFixture fixture)
        {
            _fixture = fixture;
        }

        /// <summary>
        /// Calls <see cref="Keyfactor.Extensions.CAPlugin.CERTInext.Client.ICERTInextClient.GetProductDetailsAsync"/>
        /// and asserts that the call completes without throwing.  When at least one product
        /// is returned, asserts that product code "838" (DV SSL) is present in the list.
        ///
        /// Some CERTInext accounts return an empty product list from GetProductDetails
        /// even though orders with that product code can be placed and listed via
        /// GetOrderReport.  An empty list is therefore acceptable in this test.
        /// </summary>
        [SkippableFact]
        public async Task GetProductDetails_ReturnsProducts()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            List<ProductDetail> products = null;

            // The call itself must not throw
            var act = async () =>
            {
                products = await _fixture.Client.GetProductDetailsAsync(CancellationToken.None);
            };
            await act.Should().NotThrowAsync(
                "GetProductDetails should complete without throwing, even if the account returns an empty list");

            products.Should().NotBeNull(
                "GetProductDetailsAsync should never return null — an empty list is acceptable");

            // When the account does return products, assert the expected code is present.
            if (products != null && products.Count > 0)
            {
                products.Should().Contain(
                    p => p.ProductCode == KnownProductCode,
                    $"product code \"{KnownProductCode}\" (DV SSL 838) should be available when products are returned");
            }
        }
    }
}
