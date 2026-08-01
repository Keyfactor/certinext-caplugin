// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Text.RegularExpressions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Models
{
    /// <summary>
    /// Validation level of a CERTInext SSL product. Drives whether <c>Enroll()</c> performs a
    /// synchronous pickup poll: DV products issue in seconds once accepted, while OV/EV products
    /// go through a mandatory organization-verification step and issue asynchronously — minutes
    /// to hours, sometimes human-gated (CERTInext support ticket #162763: "there is no setting
    /// on our end that makes this certificate type return instantly in a single call").
    /// </summary>
    internal enum ProductValidationType
    {
        /// <summary>Could not be determined (catalog unavailable and the product name carries no DV/OV/EV token).</summary>
        Unknown = 0,
        Dv = 1,
        Ov = 2,
        Ev = 3
    }

    /// <summary>
    /// Classifies CERTInext products into DV/OV/EV by name. Name-based classification is
    /// deliberate: the numeric product codes differ between CERTInext environments (e.g.
    /// production 842 is OV while sandbox 842 is DV) and the raw <c>productTypeID</c> value
    /// space is undocumented, but product names consistently carry a "DV"/"OV"/"EV" token in
    /// both the account catalog ("OV SSL Certificate 1 Year") and the plugin's template
    /// product list ("OV SSL Wildcard").
    /// </summary>
    internal static class ProductClassifier
    {
        private static readonly Regex DvToken = new Regex(@"\bDV\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex OvToken = new Regex(@"\bOV\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex EvToken = new Regex(@"\bEV\b", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        /// <summary>
        /// Returns the validation type encoded in a product name, or
        /// <see cref="ProductValidationType.Unknown"/> when the name carries no recognizable
        /// token (or carries more than one, which would make any single answer a guess).
        /// </summary>
        internal static ProductValidationType ClassifyName(string productName)
        {
            if (string.IsNullOrWhiteSpace(productName))
                return ProductValidationType.Unknown;

            bool dv = DvToken.IsMatch(productName);
            bool ov = OvToken.IsMatch(productName);
            bool ev = EvToken.IsMatch(productName);

            int matches = (dv ? 1 : 0) + (ov ? 1 : 0) + (ev ? 1 : 0);
            if (matches != 1)
                return ProductValidationType.Unknown;

            return dv ? ProductValidationType.Dv
                 : ov ? ProductValidationType.Ov
                 : ProductValidationType.Ev;
        }
    }
}
