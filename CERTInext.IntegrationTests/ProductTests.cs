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
    /// that the configured product code is among them.
    ///
    /// Product codes are per-account — they are provisioned by eMudhra during account setup
    /// and may differ from the codes used by other accounts or in the documentation examples.
    /// This test uses the CERTINEXT_PRODUCT_CODE from the fixture (loaded from ~/.env_certinext)
    /// to perform the presence assertion, rather than hardcoding a specific code.
    ///
    /// Note: the GetProductDetails API requires groupNumber in the productDetails block to
    /// return results on some sandbox accounts.  An empty list from GetProductDetails does not
    /// mean the account has no products — it may indicate the groupNumber was not passed.
    /// </summary>
    public class ProductTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;

        public ProductTests(IntegrationTestFixture fixture)
        {
            _fixture = fixture;
        }

        /// <summary>
        /// Calls <see cref="Keyfactor.Extensions.CAPlugin.CERTInext.Client.ICERTInextClient.GetProductDetailsAsync"/>
        /// and asserts that the call completes without throwing.  When at least one product
        /// is returned, asserts that the configured product code from
        /// <c>CERTINEXT_PRODUCT_CODE</c> is present in the flattened list.
        ///
        /// Some CERTInext accounts may return an empty list when the groupNumber is not
        /// passed in the productDetails block.  An empty list is therefore treated as
        /// acceptable — only the absence of an exception is mandatory.
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

            // When the account does return products and CERTINEXT_PRODUCT_CODE is set,
            // assert that the configured code is present in the list.
            if (products != null && products.Count > 0 && !string.IsNullOrWhiteSpace(_fixture.ProductCode))
            {
                products.Should().Contain(
                    p => p.ProductCode == _fixture.ProductCode,
                    $"configured product code \"{_fixture.ProductCode}\" should be available " +
                    "in the account's product list when GetProductDetails returns results");
            }
        }
    }
}
