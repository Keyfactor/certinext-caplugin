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

using System;
using System.Text.Json;
using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Read-only helper for querying <c>GET /api/certinext/v2/domains?search=&amp;exactMatch=true</c>
    /// via the existing <see cref="CERTInextClient.ProbeV2GetAsync"/> escape hatch, so DCV-on V2
    /// tests can tell the reuse path (domain already <c>VERIFIED</c>, see issues/0020) apart from
    /// the publish path before asserting what the DNS provider spy should have recorded.
    /// </summary>
    internal static class V2DomainStatusHelper
    {
        /// <summary>
        /// Returns whether <paramref name="domain"/> currently has <c>dcvStatus=VERIFIED</c>, plus
        /// the raw <c>dcvStatus</c> string (null if the domain has no row at all, e.g. never
        /// submitted on any order yet).
        /// </summary>
        public static async Task<(bool IsVerified, string RawStatus)> GetDcvStatusAsync(
            CERTInextClient client, string domain)
        {
            string query = $"/api/certinext/v2/domains?search={Uri.EscapeDataString(domain)}&exactMatch=true";
            var (statusCode, _, content) = await client.ProbeV2GetAsync(query);

            // A failed lookup must not masquerade as "not verified" — that would steer the caller
            // into asserting the publish path for the wrong reason.
            if (statusCode != 200 || string.IsNullOrWhiteSpace(content))
                throw new InvalidOperationException(
                    $"GET /domains lookup for '{domain}' failed: HTTP {statusCode}; cannot tell reuse path from publish path.");

            using var doc = JsonDocument.Parse(content);
            if (!doc.RootElement.TryGetProperty("content", out var arr)
                || arr.ValueKind != JsonValueKind.Array
                || arr.GetArrayLength() == 0)
                return (false, null);

            var row = arr[0];
            string dcvStatus = row.TryGetProperty("dcvStatus", out var v) ? v.GetString() : null;
            return (string.Equals(dcvStatus, "VERIFIED", StringComparison.OrdinalIgnoreCase), dcvStatus);
        }
    }
}
