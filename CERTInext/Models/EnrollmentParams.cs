// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using Keyfactor.AnyGateway.Extensions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Models
{
    /// <summary>
    /// Strongly-typed wrapper around <see cref="EnrollmentProductInfo.ProductParameters"/>
    /// that provides safe, defaulted access to all template enrollment parameters.
    /// </summary>
    internal class EnrollmentParams
    {
        private readonly Dictionary<string, string> _parameters;

        public EnrollmentParams(EnrollmentProductInfo productInfo)
        {
            _parameters = productInfo?.ProductParameters ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            ProductId = productInfo?.ProductID ?? string.Empty;
        }

        /// <summary>The certificate profile/product ID from the template.</summary>
        public string ProductId { get; }

        /// <summary>
        /// The CERTInext numeric product code to send to the API.
        /// Resolution order:
        ///   1. ProductCode template parameter (explicit override — use for sandbox or non-standard codes)
        ///   2. ProfileId template parameter (deprecated alias for ProductCode)
        ///   3. V1-ONLY fallback: default production code looked up from the selected product
        ///      name (ProductId) via Constants.Products.DefaultProductCodes.
        /// V2 callers must check <see cref="HasExplicitProductCode"/> before using this value:
        /// when false, this getter's fallback (step 3) is the V1-era table, whose numbering does
        /// not match the live V2 catalog — resolve the V2 code from the live catalog
        /// by ProductTypeId instead (see EnrollV2Async / ValidateProductInfo).
        /// </summary>
        public string ProductCode
        {
            get
            {
                var explicit_ = GetExplicitProductCode();
                if (!string.IsNullOrEmpty(explicit_))
                    return explicit_;

                Constants.Products.DefaultProductCodes.TryGetValue(ProductId ?? string.Empty, out var mapped);
                return mapped ?? string.Empty;
            }
        }

        /// <summary>Alias for ProductCode — kept for backward compat.</summary>
        public string ProfileId => ProductCode;

        /// <summary>
        /// True when an explicit ProductCode or ProfileId override was configured on the
        /// template. False means <see cref="ProductCode"/>'s getter falls back to the V1-only
        /// Constants.Products.DefaultProductCodes table — V2 callers must not use that fallback
        /// value; resolve the code from the live catalog by ProductTypeId instead.
        /// </summary>
        public bool HasExplicitProductCode => !string.IsNullOrEmpty(GetExplicitProductCode());

        private string GetExplicitProductCode()
        {
            return GetString(Constants.EnrollmentParam.ProductCode,
                GetString(Constants.EnrollmentParam.ProfileId, string.Empty));
        }

        /// <summary>Requested subscription validity in years (1, 2, or 3). Takes precedence over ValidityDays.</summary>
        public int ValidityYears => GetInt(Constants.EnrollmentParam.ValidityYears, 0);

        /// <summary>Requested validity in days; 0 means "use profile default".</summary>
        public int ValidityDays => GetInt(Constants.EnrollmentParam.ValidityDays, 0);

        /// <summary>Whether to auto-approve pending-approval certificates.</summary>
        public bool AutoApprove => GetBool(Constants.EnrollmentParam.AutoApprove, false);

        /// <summary>Default requester name to use when not derivable from the subject.</summary>
        public string RequesterName => GetString(Constants.EnrollmentParam.RequesterName, string.Empty);

        /// <summary>Default requester email to use when not derivable from the subject.</summary>
        public string RequesterEmail => GetString(Constants.EnrollmentParam.RequesterEmail, string.Empty);

        /// <summary>
        /// Days before expiry within which a RenewOrReissue is treated as a renewal.
        /// </summary>
        public int RenewalWindowDays => GetInt(Constants.EnrollmentParam.RenewalWindowDays, 90);

        /// <summary>Key algorithm hint (e.g. "RSA2048"). Empty means use profile default.</summary>
        public string KeyType => GetString(Constants.EnrollmentParam.KeyType, string.Empty);

        /// <summary>
        /// Primary domain name for SSL/TLS orders (and the <c>hostname</c> of a V2 private-pki
        /// order). Derived from the CSR CN by the client if omitted here.
        /// </summary>
        public string DomainName => GetString(Constants.EnrollmentParam.DomainName, string.Empty);

        /// <summary>
        /// Per-template subscriber agreement signer name.
        /// Falls back to the connector-level <c>RequestorName</c> if empty.
        /// </summary>
        public string SignerName => GetString(Constants.EnrollmentParam.SignerName, string.Empty);

        /// <summary>
        /// Per-template signer city/location.
        /// Falls back to the connector-level <c>SignerPlace</c> if empty.
        /// </summary>
        public string SignerPlace => GetString(Constants.EnrollmentParam.SignerPlace, string.Empty);

        /// <summary>
        /// Per-template signer IP address.
        /// Falls back to the connector-level <c>SignerIp</c> if empty.
        /// </summary>
        public string SignerIp => GetString(Constants.EnrollmentParam.SignerIp, string.Empty);

        // ------------------------------------------------------------------
        // V2 API parameters
        // ------------------------------------------------------------------

        /// <summary>
        /// V2 product family. Accepted values: "ssl" (default), "private-pki", "signature".
        /// Used to select the correct V2 resource path.
        /// </summary>
        public string ProductFamily => GetString(Constants.EnrollmentParam.ProductFamily, "ssl");

        /// <summary>
        /// V2 product family as the REST path slug used in V2 URL construction.
        /// Maps "ssl" → "ssl-certificates", "private-pki" → "private-pki-certificates",
        /// "signature" → "signature-certificates".
        /// </summary>
        public string ProductFamilySlug => ProductFamily.ToLowerInvariant() switch
        {
            "ssl"         => Constants.ApiV2.FamilySsl,
            "private-pki" => Constants.ApiV2.FamilyPrivatePki,
            "signature"   => Constants.ApiV2.FamilySignature,
            _             => Constants.ApiV2.FamilySsl
        };

        /// <summary>
        /// V2 product variant within the family, sent in the order body. For the SSL family this
        /// is the <c>productVariant</c> field ("dv", "ov", "ev"); for the private-pki family it
        /// is the <c>variant</c> field ("intranet-ssl", "igtf-host").
        /// Default: "dv" (SSL-only; private-pki enrollment rejects it — see
        /// <see cref="HasExplicitProductVariant"/>).
        /// </summary>
        public string ProductVariant => GetString(Constants.EnrollmentParam.ProductVariant, "dv");

        /// <summary>
        /// True when the ProductVariant template parameter is actually set (non-blank), as
        /// opposed to <see cref="ProductVariant"/> falling back to its SSL-only "dv" default.
        /// Used only to word the private-pki validation error accurately.
        /// </summary>
        public bool HasExplicitProductVariant =>
            !string.IsNullOrEmpty(GetString(Constants.EnrollmentParam.ProductVariant, string.Empty));

        // ------------------------------------------------------------------
        // Helpers
        // ------------------------------------------------------------------

        private string GetString(string key, string defaultValue)
        {
            return _parameters.TryGetValue(key, out string v) && !string.IsNullOrWhiteSpace(v)
                ? v.Trim()
                : defaultValue;
        }

        private int GetInt(string key, int defaultValue)
        {
            if (_parameters.TryGetValue(key, out string v) && int.TryParse(v, out int parsed))
                return parsed;
            return defaultValue;
        }

        private bool GetBool(string key, bool defaultValue)
        {
            if (_parameters.TryGetValue(key, out string v) && bool.TryParse(v, out bool parsed))
                return parsed;
            return defaultValue;
        }
    }
}
