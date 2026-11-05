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
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Read-only probe (issue 0049, V1 port): does the V1 DownloadCertificate endpoint serve the body
    /// of an already-revoked order? The client never asks today (<c>IsCertificateDownloadable</c>
    /// excludes status 22), so a revoked order first seen by sync is always body-less and the plugin
    /// must downgrade it to FAILED. If CERTInext does serve it, sync could backfill the body instead.
    /// This test calls DownloadCertificate directly, bypassing that gate, and reports what came back.
    /// It does not assert either outcome. No orders are created or changed.
    ///
    /// Opt-in: <c>CERTINEXT_PROBE_REVOKED_DOWNLOAD=1</c>. Target: <c>CERTINEXT_REVOKED_ORDER_NUMBER</c>,
    /// or the first revoked order in the account's order report when unset.
    /// </summary>
    public class RevokedDownloadProbeTests : IClassFixture<IntegrationTestFixture>
    {
        private const string OptInFlag = "CERTINEXT_PROBE_REVOKED_DOWNLOAD";
        private const string OrderNumberVar = "CERTINEXT_REVOKED_ORDER_NUMBER";
        private const int MaxScanRows = 2000;

        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;

        public RevokedDownloadProbeTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;
        }

        [SkippableFact]
        public async Task DownloadCertificate_ForRevokedOrder_ReportsWhetherBodyIsServed()
        {
            IntegrationSkip.IfNotConfigured(_fixture);
            Skip.If(Environment.GetEnvironmentVariable(OptInFlag) != "1",
                $"Opt-in read-only probe; set {OptInFlag}=1 to run.");

            string orderNumber = Environment.GetEnvironmentVariable(OrderNumberVar);
            if (string.IsNullOrWhiteSpace(orderNumber))
            {
                int scanned = 0;
                await foreach (var entry in _fixture.Client.ListCertificatesAsync(
                    issuedAfter: null, pageSize: 100, ct: CancellationToken.None))
                {
                    if (++scanned > MaxScanRows) break;
                    if (string.Equals(entry.Status, "revoked", StringComparison.OrdinalIgnoreCase))
                    {
                        orderNumber = entry.Id;
                        break;
                    }
                }
                _output.WriteLine($"scanned={scanned} rows for a revoked order");
            }
            Skip.If(string.IsNullOrWhiteSpace(orderNumber),
                $"No revoked order found; set {OrderNumberVar} to one.");

            var track = await _fixture.Client.TrackOrderAsync(orderNumber, CancellationToken.None);
            string statusId = track.OrderDetails?.CertificateStatusId;
            _output.WriteLine($"order={orderNumber} certificateStatusId={statusId ?? "(null)"} " +
                              $"revokeProcessedDate={(string.IsNullOrWhiteSpace(track.OrderDetails?.RevocationDetails?.RevokeProcessedDate) ? "(none)" : "present")}");
            Skip.If(statusId != Constants.CertificateStatusId.CertificateRevoked.ToString(),
                $"Order {orderNumber} is not revoked (certificateStatusId={statusId}).");

            try
            {
                var resp = await _fixture.Client.DownloadCertificateAsync(orderNumber, CancellationToken.None);
                string pem = resp.CertificateDetails?.EndEntityCertificate;
                _output.WriteLine(string.IsNullOrWhiteSpace(pem)
                    ? "RESULT: DownloadCertificate succeeded but returned NO end-entity body."
                    : $"RESULT: DownloadCertificate SERVED the revoked body ({pem.Length} chars, " +
                      $"startsWithPemHeader={pem.TrimStart().StartsWith("-----BEGIN", StringComparison.Ordinal)}).");
            }
            catch (Exception ex)
            {
                _output.WriteLine($"RESULT: DownloadCertificate REFUSED the revoked order: {TestOutputScrub.Describe(ex)}");
            }
        }
    }
}
