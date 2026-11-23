// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.API.V2
{
    // ---------------------------------------------------------------------------
    // V2 domain-level DCV (used for domains validated by SSL.com)
    //
    //   GET  /api/certinext/v2/domains?search={fqdn}&exactMatch=true   (find the domain row)
    //   GET  /api/certinext/v2/domains/{domainId}/dcv                  (DcvDetails)
    //   POST /api/certinext/v2/domains/{domainId}/dcv/verify           (DcvVerifyRequest)
    //
    // The spec types DcvDetails and DcvOption; the list row and the verify bodies are untyped
    // `object`, so those members are optional and built from the spec prose.
    // ---------------------------------------------------------------------------

    /// <summary>
    /// One row of <c>GET /domains</c>. The spec leaves the row untyped; the id is read from
    /// <c>domainId</c> (the name <c>DomainCreateResponse</c> uses) or <c>id</c>.
    /// </summary>
    public class V2DomainRecord
    {
        public string DomainId { get; set; }

        public string DomainName { get; set; }

        /// <summary><c>PENDING</c>, <c>VERIFIED</c> or <c>REJECTED</c>.</summary>
        public string DcvStatus { get; set; }

        /// <summary><c>SSLCOM</c> for SSL.com-validated domains; absent means emSign.</summary>
        public string ValidatedBy { get; set; }

        public bool IsValidatedBySslCom =>
            string.Equals(ValidatedBy, Constants.ApiV2.ValidatedBySslCom, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Spec <c>DcvOption</c>: one DCV method SSL.com offers for a domain.</summary>
    public class V2DcvOption
    {
        [JsonPropertyName("optionId")]
        public string OptionId { get; set; }

        /// <summary><c>dns-txt</c>, <c>http-url</c>, <c>dns-cname</c> or <c>dns-persist</c>.</summary>
        [JsonPropertyName("method")]
        public string Method { get; set; }

        [JsonPropertyName("brMethod")]
        public string BrMethod { get; set; }

        /// <summary>Where to publish: the DNS record name, or the full URL of the file.</summary>
        [JsonPropertyName("recordName")]
        public string RecordName { get; set; }

        /// <summary>Value to publish. Never logged.</summary>
        [JsonPropertyName("recordValue")]
        public string RecordValue { get; set; }

        /// <summary>Name this option validates; a parent name also covers its subdomains.</summary>
        [JsonPropertyName("coversName")]
        public string CoversName { get; set; }

        [JsonPropertyName("exactName")]
        public bool? ExactName { get; set; }

        [JsonPropertyName("expiresAt")]
        public string ExpiresAt { get; set; }
    }

    /// <summary>Spec <c>DcvDetails</c>, the body of <c>GET /domains/{domainId}/dcv</c>.</summary>
    public class V2DomainDcvDetails
    {
        [JsonPropertyName("method")]
        public string Method { get; set; }

        [JsonPropertyName("txtToken")]
        public string TxtToken { get; set; }

        [JsonPropertyName("recordName")]
        public string RecordName { get; set; }

        [JsonPropertyName("recordValue")]
        public string RecordValue { get; set; }

        [JsonPropertyName("optionId")]
        public string OptionId { get; set; }

        [JsonPropertyName("options")]
        public List<V2DcvOption> Options { get; set; }

        [JsonPropertyName("validatedBy")]
        public string ValidatedBy { get; set; }

        /// <summary><c>PENDING</c>, <c>UNDER_REVIEW</c>, <c>VALIDATED</c> or <c>EXPIRED</c>.</summary>
        [JsonPropertyName("caStatus")]
        public string CaStatus { get; set; }

        /// <summary>
        /// Picks the option to publish through a DNS provider plugin. Only <c>dns-txt</c> qualifies:
        /// IAnyCAPlugin 3.3's <c>IDomainValidator.StageValidation(key, value)</c> publishes a TXT record
        /// and has no record-type argument, so a <c>dns-cname</c> option can't be staged. Prefers the
        /// selected method when it is <c>dns-txt</c>, then an <c>options[]</c> entry for exactly the
        /// requested name, then any other <c>dns-txt</c> option. Returns null when none has both a
        /// record name and a value.
        /// </summary>
        public V2DcvOption SelectDnsTxtOption()
        {
            if (string.Equals(Method, Constants.ApiV2.DcvMethodDnsTxt, StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(RecordName) && !string.IsNullOrWhiteSpace(RecordValue))
            {
                return new V2DcvOption
                {
                    OptionId = OptionId, Method = Method, RecordName = RecordName, RecordValue = RecordValue
                };
            }

            return (Options ?? new List<V2DcvOption>())
                .Where(o => o != null
                    && string.Equals(o.Method, Constants.ApiV2.DcvMethodDnsTxt, StringComparison.OrdinalIgnoreCase)
                    && !string.IsNullOrWhiteSpace(o.RecordName) && !string.IsNullOrWhiteSpace(o.RecordValue))
                .OrderByDescending(o => o.ExactName == true)
                .FirstOrDefault();
        }

        /// <summary>Methods offered, for the "no usable option" warning.</summary>
        public string DescribeOfferedMethods()
        {
            var methods = (Options ?? new List<V2DcvOption>())
                .Select(o => o?.Method)
                .Append(Method)
                .Where(m => !string.IsNullOrWhiteSpace(m))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            return methods.Count == 0 ? "(none)" : string.Join(", ", methods);
        }
    }

    /// <summary>Spec <c>DcvVerifyRequest</c>, the body of <c>POST /domains/{domainId}/dcv/verify</c>.</summary>
    public class V2DomainDcvVerifyRequest
    {
        /// <summary>SSL.com option to check. Omitted when null, so SSL.com checks the selected option.</summary>
        [JsonPropertyName("optionId")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string OptionId { get; set; }
    }

    /// <summary>
    /// Outcome of <c>POST /domains/{domainId}/dcv/verify</c>. 200 means validated (with
    /// <c>validTill</c>); 422 carries <c>diagnostics.caStatus</c> (<c>PENDING</c>, <c>FAILED</c>,
    /// <c>UNDER_REVIEW</c>, <c>EXPIRED</c>) and <c>diagnostics.caMessage</c>.
    /// </summary>
    public class V2DomainDcvVerifyResult
    {
        public bool Verified { get; set; }

        public string ValidTill { get; set; }

        public string CaStatus { get; set; }

        /// <summary>SSL.com's reason, already passed through <c>LogSanitizer.SanitizeCaText</c>.</summary>
        public string CaMessage { get; set; }
    }
}
