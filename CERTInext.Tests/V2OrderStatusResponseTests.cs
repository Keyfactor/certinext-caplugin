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
using FluentAssertions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Pure DTO deserialization tests for <see cref="V2OrderStatusResponse"/>'s nested
    /// <c>revocation</c> object (issues/0034). No HTTP layer involved — these assert directly
    /// against <see cref="JsonSerializer"/>, isolated from the client and plugin code that
    /// consumes this type.
    /// </summary>
    public class V2OrderStatusResponseTests
    {
        /// <summary>
        /// Raw Track Order response body captured live against a real revoked SSL order
        /// (order 6758681362, family ssl-certificates, 2026-09-25 — see
        /// issues/0034-v2-revocation-date-reason-dto-mismatch.md's "Live probe findings"
        /// section). Verbatim except for whitespace; unmapped fields (requestor, orderedBy,
        /// subscriberAgreement, subscription, verifications) are expected to be ignored by
        /// System.Text.Json's default unmapped-member handling.
        /// </summary>
        private const string LiveRevokedTrackOrderJson =
            @"{""orderId"":""6758681362"",""requestId"":""1279754567"",""status"":""revoked"",""orderState"":""Order Accepted"",""certificateState"":""Certificate Revoked"",""productVariant"":""dv"",""domain"":""nt2-20260924204408874594000.dcv-test.scrup.org"",""expiresAt"":""2026-12-23T20:44:23Z"",""requestor"":{""name"":""Keyfactor Plugin Test"",""email"":""plugin-test@keyfactor.com"",""phone"":""+0000000000"",""designation"":""Plugin Test""},""orderedBy"":{""name"":""Sean"",""email"":""sbailey@keyfactor.com""},""csrSubmitted"":true,""subscriberAgreement"":{""signed"":true,""signerName"":""Keyfactor Plugin Test"",""signedAt"":""2026-09-25T14:18:14Z"",""signedPlace"":""Gateway Lab""},""subscription"":{""validityYears"":1,""endDate"":""2027-09-24T20:44:27Z"",""status"":""active""},""revocation"":{""status"":""Certificate Revoked"",""reason"":""cessation-of-operation"",""processedAt"":""2026-09-24T20:44:41Z""},""verifications"":{""domain"":{""status"":""VERIFIED"",""domains"":[{""domain"":""nt2-20260924204408874594000.dcv-test.scrup.org"",""domainStatus"":""ACTIVE"",""dcvMethod"":""dns-txt"",""dcvStatus"":""VERIFIED"",""verifiedAt"":""2026-09-24T20:44:13Z"",""caaStatus"":""PASSED""}]},""empty"":false}}";

        [Fact]
        public void Deserialize_LiveRevokedOrderBody_PopulatesNestedRevocationObject()
        {
            var result = JsonSerializer.Deserialize<V2OrderStatusResponse>(LiveRevokedTrackOrderJson);

            result.Should().NotBeNull();
            result!.OrderId.Should().Be("6758681362");
            result.Status.Should().Be("revoked");
            result.ProductVariant.Should().Be("dv");
            result.Domain.Should().Be("nt2-20260924204408874594000.dcv-test.scrup.org");

            // issues/0034: `revocation` is a nested object — status/reason/processedAt — not
            // flat top-level revocationReason/revocationDate properties.
            result.Revocation.Should().NotBeNull();
            result.Revocation!.Status.Should().Be("Certificate Revoked");
            result.Revocation.Reason.Should().Be("cessation-of-operation",
                "the wire reason is RFC 5280-style hyphenated, not V1's camelCase convention");
            result.Revocation.ProcessedAt.Should().Be(
                new DateTime(2026, 9, 24, 20, 44, 41, DateTimeKind.Utc),
                "processedAt is standard ISO 8601 UTC and should bind directly with no custom converter");
        }

        [Fact]
        public void Deserialize_NotRevokedOrderBody_RevocationIsNull()
        {
            // The `revocation` key is absent entirely when an order has never been revoked
            // (confirmed live, issues/0034) — not present-but-null.
            const string issuedJson =
                @"{""orderId"":""ord_abc001"",""requestId"":""req_xyz001"",""status"":""issued"",""productVariant"":""dv"",""domain"":""example.com""}";

            var result = JsonSerializer.Deserialize<V2OrderStatusResponse>(issuedJson);

            result.Should().NotBeNull();
            result!.Status.Should().Be("issued");
            result.Revocation.Should().BeNull();
        }
    }
}
