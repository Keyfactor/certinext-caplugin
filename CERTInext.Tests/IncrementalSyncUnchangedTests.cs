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
    /// Issue 0093: the V1 order listing filters by calendar day, so every incremental pass
    /// re-lists every order placed that day. An issued or revoked order the gateway already holds
    /// with the same status and a stored body must not be refetched (TrackOrder +
    /// DownloadCertificate) or re-emitted on an incremental pass. Anything new, changed, body-less
    /// or unverifiable is processed as before, and full sync is unaffected.
    /// </summary>
    public class IncrementalSyncUnchangedTests
    {
        private const string Id = MockCertificateData.CertId1;
        private static readonly DateTime LastSync = new DateTime(2026, 11, 10, 10, 20, 0, DateTimeKind.Utc);

        /// <summary>An order as the listing returns it: status and metadata, never a body.</summary>
        private static LegacyGetCertificateResponse Listed(string status) =>
            new LegacyGetCertificateResponse
            {
                Id = Id,
                Status = status,
                Certificate = null,
                Subject = "test.example.com",
                ProfileId = MockCertificateData.ProfileIdTls
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

        private static Mock<ICERTInextClient> Client(LegacyGetCertificateResponse listed,
            LegacyGetCertificateResponse refetched)
        {
            var mock = new Mock<ICERTInextClient>(MockBehavior.Loose);
            mock.Setup(c => c.ListCertificatesAsync(
                    It.IsAny<DateTime?>(), It.IsAny<int>(), It.IsAny<CancellationToken>()))
                .Returns(AsyncEnum(new[] { listed }));
            mock.Setup(c => c.GetCertificateAsync(Id, It.IsAny<CancellationToken>()))
                .ReturnsAsync(refetched);
            return mock;
        }

        private static async Task<List<AnyCAPluginCertificate>> RunSync(
            ICERTInextClient client, ICertificateDataReader reader, bool fullSync = false)
        {
            var plugin = new CERTInextCAPlugin(client, reader, new CERTInextConfig());
            var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);
            await plugin.Synchronize(buffer, lastSync: fullSync ? (DateTime?)null : LastSync,
                fullSync: fullSync, cancelToken: CancellationToken.None);
            return buffer.ToList();
        }

        private static Mock<ICertificateDataReader> Reader(int dbStatus, DateTime? storedExpiry)
        {
            var reader = new Mock<ICertificateDataReader>(MockBehavior.Strict);
            reader.Setup(r => r.GetStatusByRequestID(Id)).ReturnsAsync(dbStatus);
            reader.Setup(r => r.GetExpirationDateByRequestId(Id)).Returns(storedExpiry);
            return reader;
        }

        [Fact]
        public async Task Incremental_IssuedAndHeldUnchanged_IsNotRefetchedOrEmitted()
        {
            var client = Client(Listed("issued"), MockCertificateData.IssuedCertRecord(Id));
            var reader = Reader((int)EndEntityStatus.GENERATED, new DateTime(2027, 1, 1));

            var results = await RunSync(client.Object, reader.Object);

            results.Should().BeEmpty("the gateway already holds this certificate as-is");
            client.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Incremental_RevokedAndHeldAsRevoked_IsNotRefetchedOrEmitted()
        {
            var client = Client(Listed("revoked"), MockCertificateData.RevokedCertRecord(Id));
            var reader = Reader((int)EndEntityStatus.REVOKED, new DateTime(2027, 1, 1));

            var results = await RunSync(client.Object, reader.Object);

            results.Should().BeEmpty();
            client.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task Incremental_NewOrder_IsRefetchedAndEmitted()
        {
            var client = Client(Listed("issued"), MockCertificateData.IssuedCertRecord(Id));
            var reader = new Mock<ICertificateDataReader>(MockBehavior.Strict);
            reader.Setup(r => r.GetStatusByRequestID(Id)).ThrowsAsync(new ArgumentException("no row"));

            var results = await RunSync(client.Object, reader.Object);

            results.Should().ContainSingle();
            results[0].Status.Should().Be((int)EndEntityStatus.GENERATED);
            results[0].Certificate.Should().NotBeNullOrWhiteSpace();
        }

        [Fact]
        public async Task Incremental_StatusChangedIssuedToRevoked_IsRefetchedAndEmitted()
        {
            var client = Client(Listed("revoked"), MockCertificateData.RevokedCertRecord(Id));
            var reader = Reader((int)EndEntityStatus.GENERATED, new DateTime(2027, 1, 1));

            var results = await RunSync(client.Object, reader.Object);

            results.Should().ContainSingle("an out-of-band revoke must still propagate");
            results[0].Status.Should().Be((int)EndEntityStatus.REVOKED);
            client.Verify(c => c.GetCertificateAsync(Id, It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task Incremental_StatusChangedPendingToIssued_IsRefetchedAndEmitted()
        {
            var client = Client(Listed("issued"), MockCertificateData.IssuedCertRecord(Id));
            var reader = Reader((int)EndEntityStatus.EXTERNALVALIDATION, null);

            var results = await RunSync(client.Object, reader.Object);

            results.Should().ContainSingle("a DV order that issued after its first pass must be imported");
            results[0].Status.Should().Be((int)EndEntityStatus.GENERATED);
            results[0].Certificate.Should().NotBeNullOrWhiteSpace();
        }

        [Fact]
        public async Task Incremental_HeldWithoutBody_IsRefetchedAndEmitted()
        {
            var client = Client(Listed("issued"), MockCertificateData.IssuedCertRecord(Id));
            var reader = Reader((int)EndEntityStatus.GENERATED, null);

            var results = await RunSync(client.Object, reader.Object);

            results.Should().ContainSingle("a row whose earlier refetch failed must get its body");
            results[0].Certificate.Should().NotBeNullOrWhiteSpace();
        }

        [Fact]
        public async Task Incremental_ReaderFails_IsProcessedAsBefore()
        {
            var client = Client(Listed("issued"), MockCertificateData.IssuedCertRecord(Id));
            var reader = new Mock<ICertificateDataReader>(MockBehavior.Strict);
            reader.Setup(r => r.GetStatusByRequestID(Id)).ThrowsAsync(new InvalidOperationException("db down"));

            var results = await RunSync(client.Object, reader.Object);

            results.Should().ContainSingle();
            results[0].Status.Should().Be((int)EndEntityStatus.GENERATED);
        }

        [Fact]
        public async Task Incremental_NoReaderInjected_IsProcessedAsBefore()
        {
            var client = Client(Listed("issued"), MockCertificateData.IssuedCertRecord(Id));

            var results = await RunSync(client.Object, reader: null);

            results.Should().ContainSingle();
            results[0].Status.Should().Be((int)EndEntityStatus.GENERATED);
        }

        [Fact]
        public async Task Incremental_PendingOrder_DoesNotConsultReader()
        {
            // Strict mock with no setups: any reader call fails the test.
            var client = Client(MockCertificateData.PendingCertRecord(Id), MockCertificateData.PendingCertRecord(Id));
            var reader = new Mock<ICertificateDataReader>(MockBehavior.Strict);

            var results = await RunSync(client.Object, reader.Object);

            results.Should().ContainSingle();
            results[0].Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
        }

        [Fact]
        public async Task FullSync_HeldUnchanged_IsStillRefetchedAndEmitted()
        {
            // Strict mock with no setups: full sync must not consult the reader for issued orders.
            var client = Client(Listed("issued"), MockCertificateData.IssuedCertRecord(Id));
            var reader = new Mock<ICertificateDataReader>(MockBehavior.Strict);

            var results = await RunSync(client.Object, reader.Object, fullSync: true);

            results.Should().ContainSingle();
            results[0].Certificate.Should().NotBeNullOrWhiteSpace();
            client.Verify(c => c.GetCertificateAsync(Id, It.IsAny<CancellationToken>()), Times.Once);
        }
    }
}
