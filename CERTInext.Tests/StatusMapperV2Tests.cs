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

        // All 11 status values documented by the V2 spec's `/reports/orders` `status`
        // filter (issues/0031) — every one must map explicitly, not fall through the
        // "unmapped" default arm, even where the resulting disposition (FAILED) is the
        // same as the default's. `unknown-future`/empty/null exercise the true default
        // arm below.
        [Theory]
        [InlineData("issued",                             (int)EndEntityStatus.GENERATED)]
        [InlineData("ISSUED",                              (int)EndEntityStatus.GENERATED)]  // case-insensitive
        [InlineData("pending-dcv",                         (int)EndEntityStatus.EXTERNALVALIDATION)]
        [InlineData("pending-csr",                         (int)EndEntityStatus.EXTERNALVALIDATION)]
        [InlineData("pending-agreement",                   (int)EndEntityStatus.EXTERNALVALIDATION)]
        [InlineData("pending-organization-verification",   (int)EndEntityStatus.EXTERNALVALIDATION)]
        [InlineData("pending-documents",                   (int)EndEntityStatus.EXTERNALVALIDATION)]
        [InlineData("pending-approval",                    (int)EndEntityStatus.EXTERNALVALIDATION)]
        [InlineData("revoked",                              (int)EndEntityStatus.REVOKED)]
        [InlineData("cancelled",                             (int)EndEntityStatus.FAILED)]
        [InlineData("rejected",                              (int)EndEntityStatus.FAILED)]
        [InlineData("expired",                               (int)EndEntityStatus.FAILED)]
        public void V2StatusToRequestDisposition_MapsCorrectly(string v2Status, int expectedDisposition)
        {
            StatusMapper.V2StatusToRequestDisposition(v2Status).Should().Be(expectedDisposition);
        }

        // ---------------------------------------------------------------------------
        // Regression (issues/0031): a status string that is NOT one of the 11 spec
        // values must still degrade gracefully to FAILED via the default arm, rather
        // than throwing or being silently treated as "still pending". This is the
        // "truly unrecognized" case, distinct from the deliberate FAILED mappings
        // (cancelled/rejected/expired) tested above.
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData("unknown-future")]
        [InlineData("")]
        [InlineData(null)]
        public void V2StatusToRequestDisposition_UnrecognizedStatus_DefaultsToFailed(string v2Status)
        {
            StatusMapper.V2StatusToRequestDisposition(v2Status).Should().Be((int)EndEntityStatus.FAILED);
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

        // ---------------------------------------------------------------------------
        // V2RevocationReasonToCrlCode (issues/0034) — the inverse of ToV2RevocationReason,
        // used to populate AnyCAPluginCertificate.RevocationReason from a Track Order
        // response's nested revocation.reason string.
        // ---------------------------------------------------------------------------

        [Theory]
        [InlineData(Constants.RevocationReasonV2.Unspecified, 0)]
        [InlineData(Constants.RevocationReasonV2.KeyCompromise, 1)]
        [InlineData(Constants.RevocationReasonV2.CACompromise, 2)]
        [InlineData(Constants.RevocationReasonV2.AffiliationChanged, 3)]
        [InlineData(Constants.RevocationReasonV2.Superseded, 4)]
        [InlineData(Constants.RevocationReasonV2.CessationOfOperation, 5)]
        [InlineData(Constants.RevocationReasonV2.CertificateHold, 6)]
        [InlineData(Constants.RevocationReasonV2.PrivilegeWithdrawn, 9)]
        [InlineData(Constants.RevocationReasonV2.AACompromise, 10)]
        [InlineData("KEY-COMPROMISE", 1)] // case-insensitive
        [InlineData("not-a-real-reason", 0)] // unrecognized → unspecified
        [InlineData(null, 0)] // absent/null → unspecified
        public void V2RevocationReasonToCrlCode_MapsCorrectly(string v2Reason, int expectedCrlCode)
        {
            StatusMapper.V2RevocationReasonToCrlCode(v2Reason).Should().Be(expectedCrlCode);
        }

        // Round-trip: every CRL code ToV2RevocationReason can produce must map back to the
        // same code through V2RevocationReasonToCrlCode (the codes ToV2RevocationReason never
        // emits — 7, and CRL-only 8 — are out of scope, matching ToV2RevocationReason's own
        // documented behavior of mapping "no V2 equivalent" codes to "unspecified").
        [Theory]
        [InlineData(0u)]
        [InlineData(1u)]
        [InlineData(2u)]
        [InlineData(3u)]
        [InlineData(4u)]
        [InlineData(5u)]
        [InlineData(6u)]
        [InlineData(9u)]
        [InlineData(10u)]
        public void V2RevocationReasonToCrlCode_RoundTripsWithToV2RevocationReason(uint crlReason)
        {
            string v2Reason = StatusMapper.ToV2RevocationReason(crlReason);
            StatusMapper.V2RevocationReasonToCrlCode(v2Reason).Should().Be((int)crlReason);
        }
    }
}
