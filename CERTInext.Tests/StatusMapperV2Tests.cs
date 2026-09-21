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
        [InlineData(0u,  Constants.RevocationReason.Unspecified)]
        [InlineData(1u,  Constants.RevocationReason.KeyCompromise)]
        [InlineData(2u,  Constants.RevocationReason.Unspecified)]       // caCompromise has no V2 equivalent
        [InlineData(3u,  Constants.RevocationReason.AffiliationChanged)]
        [InlineData(4u,  Constants.RevocationReason.Superseded)]
        [InlineData(5u,  Constants.RevocationReason.CessationOfOperation)]
        [InlineData(6u,  Constants.RevocationReason.Unspecified)]       // certificateHold → unspecified
        [InlineData(8u,  Constants.RevocationReason.Unspecified)]       // removeFromCRL → unspecified
        [InlineData(9u,  Constants.RevocationReason.PrivilegeWithdrawn)]
        [InlineData(10u, Constants.RevocationReason.Unspecified)]       // aACompromise → unspecified
        [InlineData(99u, Constants.RevocationReason.Unspecified)]       // unknown → unspecified
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
    }
}
