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

using System.Collections.Generic;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.Models;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Regression coverage for issue 0036: <see cref="EnrollmentParams.ProductCode"/>'s V1-only
    /// fallback (<see cref="Constants.Products.DefaultProductCodes"/>) must remain exactly as it
    /// was before the fix — only V2 dispatch (<c>EnrollV2Async</c> / <c>ValidateProductInfo</c>)
    /// stopped using it. These tests exercise <see cref="EnrollmentParams"/> directly (it is
    /// <c>internal</c>; this project has <c>InternalsVisibleTo</c> access) so the V1-unaffected
    /// claim is pinned at the unit that both V1 and V2 share, not just re-derived from other
    /// tests continuing to pass.
    /// </summary>
    public class EnrollmentParamsTests
    {
        private static EnrollmentProductInfo MakeProductInfo(string productId, Dictionary<string, string> parameters = null) =>
            new EnrollmentProductInfo
            {
                ProductID = productId,
                ProductParameters = parameters ?? new Dictionary<string, string>()
            };

        [Fact]
        public void ProductCode_NoOverride_FallsBackToV1DefaultProductCodesTable_Unchanged()
        {
            // This is the V1 path's fallback and must be untouched by issue 0036's fix: V1
            // dispatch (EnrollNewAsync/RenewOrReissueAsync) still relies on this exact value.
            var ep = new EnrollmentParams(MakeProductInfo(Constants.Products.OvSsl));

            ep.HasExplicitProductCode.Should().BeFalse();
            ep.ProductCode.Should().Be(Constants.Products.DefaultProductCodes[Constants.Products.OvSsl]);
            ep.ProductCode.Should().Be("842", "the V1-era table value must not change as part of the V2 fix");
            ep.ProfileId.Should().Be(ep.ProductCode, "ProfileId remains a pure alias for ProductCode");
        }

        [Theory]
        [InlineData(Constants.EnrollmentParam.ProductCode)]
        [InlineData(Constants.EnrollmentParam.ProfileId)]
        public void ProductCode_ExplicitOverride_TakesPrecedenceOverDefaultTable(string parameterKey)
        {
            var ep = new EnrollmentParams(MakeProductInfo(
                Constants.Products.OvSsl,
                new Dictionary<string, string> { [parameterKey] = "999" }));

            ep.HasExplicitProductCode.Should().BeTrue();
            ep.ProductCode.Should().Be("999");
        }

        [Fact]
        public void HasExplicitProductCode_False_ForEveryDefaultProductCodesEntry_MatchesV1FallbackBehavior()
        {
            // Sanity sweep across all 10 V1 product names: with no override, every one of them
            // must report HasExplicitProductCode=false and resolve to the exact
            // DefaultProductCodes value — proving the shared getter's V1 behavior is bit-for-bit
            // unchanged by the V2 fix.
            foreach (var kvp in Constants.Products.DefaultProductCodes)
            {
                var ep = new EnrollmentParams(MakeProductInfo(kvp.Key));

                ep.HasExplicitProductCode.Should().BeFalse($"ProductId '{kvp.Key}' has no override configured");
                ep.ProductCode.Should().Be(kvp.Value, $"ProductId '{kvp.Key}' must still resolve via the V1 table");
            }
        }
    }
}
