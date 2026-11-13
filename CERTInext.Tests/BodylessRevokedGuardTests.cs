// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Issue 0049 (V1 port): the V1 client never downloads a revoked certificate's body, so a
    /// revoked order always reaches Synchronize/GetSingleRecord with <c>Certificate = null</c>.
    /// Emitted as-is for an order the gateway never stored with a body, that record poisons the
    /// gateway's revoked-certificate search (FromDER on an empty body → 500 on every Command scan).
    /// The guard consults <see cref="ICertificateDataReader.GetExpirationDateByRequestId"/>:
    /// a date → REVOKED unchanged; <c>null</c> → FAILED without revocation data; no row / error /
    /// no reader → Sync skips, GetSingleRecord returns FAILED.
    /// </summary>
    public class BodylessRevokedGuardTests
    {
        private const string Id = MockCertificateData.CertId3;

        /// <summary>A revoked record as the V1 client returns it after the sync refetch: no body.</summary>
        private static LegacyGetCertificateResponse BodylessRevoked() =>
            new LegacyGetCertificateResponse
            {
                Id = Id,
                Status = "revoked",
                Certificate = null,
                ProfileId = MockCertificateData.ProfileIdTls,
                RevokedAt = new DateTime(2026, 10, 20, 0, 0, 0, DateTimeKind.Utc),
                RevocationReason = "keyCompromise"
            };

        private static async IAsyncEnumerable<LegacyGetCertificateResponse> AsyncEnum(
            IEnumerable<LegacyGetCertificateResponse> items)
        {
            foreach (var item in items)
            {
                yield return item;
                await Task.Yield();
            }
        }

        private static Mock<ICERTInextClient> ClientReturning(LegacyGetCertificateResponse refetched)
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Loose);
            mock.Setup(c => c.ListCertificatesAsync(
                    It.IsAny<DateTime?>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnum(new[] { BodylessRevoked() }));
            mock.Setup(c => c.GetCertificateAsync(Id, It.IsAny<CancellationToken>()))
                .ReturnsAsync(refetched);
            return mock;
        }

        private static async Task<List<AnyCAPluginCertificate>> RunSync(
            ICERTInextClient client, ICertificateDataReader reader)
        {
            var plugin = new CERTInextCAPlugin(client, reader, new CERTInextConfig());
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);
            await plugin.Synchronize(buffer, lastSync: null, fullSync: true, cancelToken: CancellationToken.None);
            return buffer.ToList();
        }

        // -------------------------------------------------------------------------------------
        // Synchronize
        // -------------------------------------------------------------------------------------

        [Fact]
        public async Task Sync_GatewayHoldsBody_EmitsBodylessRevokedUnchanged()
        {
            var reader = new Mock<ICertificateDataReader>(MockBehavior.Strict);
            reader.Setup(r => r.GetExpirationDateByRequestId(Id)).Returns(new DateTime(2027, 1, 1));

            var results = await RunSync(ClientReturning(BodylessRevoked()).Object, reader.Object);

            results.Should().ContainSingle();
            results[0].Status.Should().Be((int)EndEntityStatus.REVOKED,
                "an out-of-band CA revoke must still propagate when the gateway already holds the body");
            results[0].Certificate.Should().BeNull();
            results[0].RevocationDate.Should().NotBeNull();
            results[0].RevocationReason.Should().Be(1);
        }

        [Fact]
        public async Task Sync_GatewayRowWithoutBody_EmitsFailedWithoutRevocationData()
        {
            var reader = new Mock<ICertificateDataReader>(MockBehavior.Strict);
            reader.Setup(r => r.GetExpirationDateByRequestId(Id)).Returns((DateTime?)null);

            var results = await RunSync(ClientReturning(BodylessRevoked()).Object, reader.Object);

            results.Should().ContainSingle();
            results[0].Status.Should().Be((int)EndEntityStatus.FAILED);
            results[0].Certificate.Should().BeNull();
            results[0].RevocationDate.Should().BeNull(
                "a RevocationDate on a body-less row is what the gateway's revoked search crashes on");
            results[0].RevocationReason.Should().Be(0);
        }

        [Fact]
        public async Task Sync_NoGatewayRow_SkipsRecord()
        {
            var reader = new Mock<ICertificateDataReader>(MockBehavior.Strict);
            reader.Setup(r => r.GetExpirationDateByRequestId(Id)).Throws(new ArgumentException("no row"));

            var results = await RunSync(ClientReturning(BodylessRevoked()).Object, reader.Object);

            results.Should().BeEmpty("a brand-new body-less REVOKED row could never be un-poisoned");
        }

        [Fact]
        public async Task Sync_ReaderThrowsUnexpected_SkipsRecord()
        {
            var reader = new Mock<ICertificateDataReader>(MockBehavior.Strict);
            reader.Setup(r => r.GetExpirationDateByRequestId(Id)).Throws(new InvalidOperationException("db down"));

            var results = await RunSync(ClientReturning(BodylessRevoked()).Object, reader.Object);

            results.Should().BeEmpty();
        }

        [Fact]
        public async Task Sync_NoReaderInjected_SkipsRecord()
        {
            var results = await RunSync(ClientReturning(BodylessRevoked()).Object, reader: null);

            results.Should().BeEmpty();
        }

        [Fact]
        public async Task Sync_RefetchFails_MetadataOnlyRevokedIsStillGuarded()
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Loose);
            mock.Setup(c => c.ListCertificatesAsync(
                    It.IsAny<DateTime?>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnum(new[] { BodylessRevoked() }));
            mock.Setup(c => c.GetCertificateAsync(Id, It.IsAny<CancellationToken>()))
                .ThrowsAsync(new Exception("TrackOrder 500"));
            var reader = new Mock<ICertificateDataReader>(MockBehavior.Strict);
            reader.Setup(r => r.GetExpirationDateByRequestId(Id)).Returns((DateTime?)null);

            var results = await RunSync(mock.Object, reader.Object);

            results.Should().ContainSingle();
            results[0].Status.Should().Be((int)EndEntityStatus.FAILED);
            results[0].RevocationDate.Should().BeNull();
        }

        [Fact]
        public async Task Sync_RevokedWithBody_DoesNotConsultReader()
        {
            // Strict mock with no setups: any reader call fails the test.
            var reader = new Mock<ICertificateDataReader>(MockBehavior.Strict);

            var results = await RunSync(
                ClientReturning(MockCertificateData.RevokedCertRecord(Id)).Object, reader.Object);

            results.Should().ContainSingle();
            results[0].Status.Should().Be((int)EndEntityStatus.REVOKED);
            results[0].Certificate.Should().NotBeNullOrWhiteSpace();
        }

        // -------------------------------------------------------------------------------------
        // GetSingleRecord
        // -------------------------------------------------------------------------------------

        private static Task<AnyCAPluginCertificate> RunGetSingle(ICertificateDataReader reader)
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Loose);
            mock.Setup(c => c.GetCertificateAsync(Id, It.IsAny<CancellationToken>()))
                .ReturnsAsync(BodylessRevoked());
            var plugin = new CERTInextCAPlugin(mock.Object, reader, new CERTInextConfig());
            return plugin.GetSingleRecord(Id);
        }

        [Fact]
        public async Task GetSingleRecord_GatewayHoldsBody_ReturnsRevoked()
        {
            var reader = new Mock<ICertificateDataReader>(MockBehavior.Strict);
            reader.Setup(r => r.GetExpirationDateByRequestId(Id)).Returns(new DateTime(2027, 1, 1));

            var record = await RunGetSingle(reader.Object);

            record.Status.Should().Be((int)EndEntityStatus.REVOKED);
            record.RevocationDate.Should().NotBeNull();
        }

        [Fact]
        public async Task GetSingleRecord_GatewayRowWithoutBody_ReturnsFailed()
        {
            var reader = new Mock<ICertificateDataReader>(MockBehavior.Strict);
            reader.Setup(r => r.GetExpirationDateByRequestId(Id)).Returns((DateTime?)null);

            var record = await RunGetSingle(reader.Object);

            record.Status.Should().Be((int)EndEntityStatus.FAILED);
            record.RevocationDate.Should().BeNull();
            record.RevocationReason.Should().Be(0);
        }

        [Fact]
        public async Task GetSingleRecord_NoGatewayRow_ReturnsFailed()
        {
            var reader = new Mock<ICertificateDataReader>(MockBehavior.Strict);
            reader.Setup(r => r.GetExpirationDateByRequestId(Id)).Throws(new ArgumentException("no row"));

            var record = await RunGetSingle(reader.Object);

            record.Status.Should().Be((int)EndEntityStatus.FAILED, "GetSingleRecord can't skip");
            record.RevocationDate.Should().BeNull();
        }

        [Fact]
        public async Task GetSingleRecord_NoReaderInjected_ReturnsFailed()
        {
            var record = await RunGetSingle(reader: null);

            record.Status.Should().Be((int)EndEntityStatus.FAILED);
            record.RevocationDate.Should().BeNull();
        }
    }
}
