// Copyright 2024 Keyfactor
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
        /// The CERTInext numeric product code configured on the template.
        /// Falls back to the deprecated ProfileId parameter for backward compat.
        /// Must be a numeric string (e.g. "838") — the gateway ProductID is a human-readable
        /// name and cannot be passed to the API.
        /// </summary>
        public string ProductCode =>
            GetString(Constants.EnrollmentParam.ProductCode,
                GetString(Constants.EnrollmentParam.ProfileId, string.Empty));

        /// <summary>Alias for ProductCode — kept for backward compat.</summary>
        public string ProfileId => ProductCode;

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
