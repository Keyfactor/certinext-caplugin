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
using Keyfactor.Extensions.CAPlugin.CERTInext.Models;
using Keyfactor.PKI.Enums.EJBCA;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Unit tests for the V2-specific mapping methods on <see cref="StatusMapper"/>.
    /// </summary>
    public class StatusMapperV2Tests
    {
        // ---------------------------------------------------------------------------
        // V2StatusToRequestDisposition
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData("issued",             (int)EndEntityStatus.GENERATED)]
        [InlineData("ISSUED",             (int)EndEntityStatus.GENERATED)]  // case-insensitive
        [InlineData("pending-dcv",        (int)EndEntityStatus.EXTERNALVALIDATION)]
        [InlineData("pending-csr",        (int)EndEntityStatus.EXTERNALVALIDATION)]
        [InlineData("pending-agreement",  (int)EndEntityStatus.EXTERNALVALIDATION)]
        [InlineData("revoked",            (int)EndEntityStatus.REVOKED)]
        [InlineData("cancelled",          (int)EndEntityStatus.FAILED)]
        [InlineData("unknown-future",     (int)EndEntityStatus.FAILED)]
        [InlineData("",                   (int)EndEntityStatus.FAILED)]
        [InlineData(null,                 (int)EndEntityStatus.FAILED)]
        public void V2StatusToRequestDisposition_MapsCorrectly(string v2Status, int expectedDisposition)
        {
            StatusMapper.V2StatusToRequestDisposition(v2Status).Should().Be(expectedDisposition);
        }

        // ---------------------------------------------------------------------------
        // ToV2RevocationReason
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData(0u,  Constants.RevocationReasonV2.Unspecified)]
        [InlineData(1u,  Constants.RevocationReasonV2.KeyCompromise)]
        [InlineData(2u,  Constants.RevocationReasonV2.CACompromise)]
        [InlineData(3u,  Constants.RevocationReasonV2.AffiliationChanged)]
        [InlineData(4u,  Constants.RevocationReasonV2.Superseded)]
        [InlineData(5u,  Constants.RevocationReasonV2.CessationOfOperation)]
        [InlineData(6u,  Constants.RevocationReasonV2.CertificateHold)]
        [InlineData(8u,  Constants.RevocationReasonV2.Unspecified)]      // removeFromCRL: CRL-only, not a valid revoke reason
        [InlineData(9u,  Constants.RevocationReasonV2.PrivilegeWithdrawn)]
        [InlineData(10u, Constants.RevocationReasonV2.AACompromise)]
        [InlineData(99u, Constants.RevocationReasonV2.Unspecified)]      // unknown → unspecified
        public void ToV2RevocationReason_MapsCorrectly(uint crlReason, string expectedV2Reason)
        {
            StatusMapper.ToV2RevocationReason(crlReason).Should().Be(expectedV2Reason);
        }

        // ---------------------------------------------------------------------------
        // Round-trip: ToV2RevocationReason never returns null or empty
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData(0u), InlineData(1u), InlineData(3u), InlineData(4u), InlineData(5u), InlineData(9u)]
        public void ToV2RevocationReason_NeverReturnsNullOrEmpty(uint crlReason)
        {
            StatusMapper.ToV2RevocationReason(crlReason).Should().NotBeNullOrEmpty();
        }

        // ---------------------------------------------------------------------------
        // Regression (issues/0019): every CRL reason code Keyfactor Command can send
        // to IAnyCAPlugin.Revoke must map to a value in the V2 spec's kebab-case
        // `reason` enum (docs/reference/specs/CERTInext API v2.postman_collection.json,
        // "Revoke Certificate"), never to a camelCase string that would get HTTP 400.
        // ---------------------------------------------------------------------------

        /// <summary>
        /// The V2 spec's `reason` enum, hardcoded from the spec text rather than from
        /// <see cref="Constants.RevocationReasonV2"/> so this test still catches a
        /// future accidental edit to that class drifting away from the spec.
        /// </summary>
        private static readonly HashSet<string> SpecRevocationReasonEnum = new()
        {
            "unspecified",
            "key-compromise",
            "ca-compromise",
            "affiliation-changed",
            "superseded",
            "cessation-of-operation",
            "certificate-hold",
            "privilege-withdrawn",
            "aa-compromise",
        };

        // RFC 5280 CRLReason codes that Keyfactor Command can pass through to
        // IAnyCAPlugin.Revoke's revocationReason parameter (0-10, minus the two
        // codes RFC 5280 never assigns: 7 and, for a *request* reason, 8
        // (removeFromCRL is CRL-only) is still exercised here to prove it degrades
        // safely to "unspecified" rather than to an invalid string).
        [Theory]
        [InlineData(0u)]
        [InlineData(1u)]
        [InlineData(2u)]
        [InlineData(3u)]
        [InlineData(4u)]
        [InlineData(5u)]
        [InlineData(6u)]
        [InlineData(8u)]
        [InlineData(9u)]
        [InlineData(10u)]
        public void ToV2RevocationReason_EveryCrlCode_MapsToASpecEnumValue(uint crlReason)
        {
            string v2Reason = StatusMapper.ToV2RevocationReason(crlReason);

            SpecRevocationReasonEnum.Should().Contain(v2Reason,
                $"CRL reason code {crlReason} mapped to '{v2Reason}', which is not one of the V2 spec's " +
                "kebab-case reason values — sending it would get HTTP 400 (issues/0019).");
        }
    }
}
