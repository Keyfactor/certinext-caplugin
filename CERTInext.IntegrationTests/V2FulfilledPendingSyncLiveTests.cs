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
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using Org.BouncyCastle.X509;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Plan 0096 item 2, live: a <c>/reports/orders</c> row reading <c>Order Fulfilled | Pending for Approver</c>
    /// must go through Track Order and come out of the V2 sync as issued, with the certificate downloaded.
    /// Runs the real <c>Synchronize</c> code against the live API, with the report listing narrowed to one
    /// order by a forwarding proxy; every other call goes to the real client unchanged. Read-only at
    /// CERTInext (list, track, download), DCV off. Opt-in: <c>CERTINEXT_V2_FULFILLED_PENDING_SYNC=1</c>;
    /// order from <c>CERTINEXT_V2_FULFILLED_PENDING_ORDER</c> (default 1125823297).
    /// </summary>
    public class V2FulfilledPendingSyncLiveTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly ITestOutputHelper _output;
        private readonly Dictionary<string, string> _env;

        public V2FulfilledPendingSyncLiveTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _output = output;
            _env = V2EnvHelper.LoadAndPromote();
        }

        /// <summary>Forwards every call to <see cref="Inner"/>; the report listing yields only <see cref="OrderId"/>.</summary>
        public class OneOrderListingProxy : DispatchProxy
        {
            internal ICERTInextClient Inner;
            internal string OrderId;
            internal readonly ConcurrentQueue<string> Calls = new ConcurrentQueue<string>();
            internal int RowsListed;

            protected override object Invoke(MethodInfo targetMethod, object[] args)
            {
                Calls.Enqueue(targetMethod.Name);
                object result;
                try { result = targetMethod.Invoke(Inner, args); }
                catch (TargetInvocationException tie) when (tie.InnerException != null)
                {
                    ExceptionDispatchInfo.Capture(tie.InnerException).Throw();
                    throw;
                }
                return targetMethod.Name == nameof(ICERTInextClient.ListOrdersV2Async)
                    ? OnlyTarget((IAsyncEnumerable<OrderReportEntryV2>)result)
                    : result;
            }

            private async IAsyncEnumerable<OrderReportEntryV2> OnlyTarget(
                IAsyncEnumerable<OrderReportEntryV2> rows, [EnumeratorCancellation] CancellationToken ct = default)
            {
                await foreach (var row in rows.WithCancellation(ct))
                {
                    RowsListed++;
                    if (string.Equals(row.OrderNumber, OrderId, StringComparison.Ordinal))
                        yield return row;
                }
            }
        }

        [SkippableFact]
        public async Task Sync_OrderFulfilledPendingForApprover_TracksAndDownloads()
        {
            string apiUrl = V2EnvHelper.GetEnv(_env, "CERTINEXT_API_URL");
            string clientId = V2EnvHelper.GetEnv(_env, "CERTINEXT_CLIENT_ID");
            string clientSecret = V2EnvHelper.GetEnv(_env, "CERTINEXT_CLIENT_SECRET");
            Skip.If(string.IsNullOrWhiteSpace(V2EnvHelper.GetEnv(_env, "CERTINEXT_USE_V2_API"))
                    || string.IsNullOrWhiteSpace(apiUrl) || string.IsNullOrWhiteSpace(clientId)
                    || string.IsNullOrWhiteSpace(clientSecret)
                    || V2EnvHelper.GetEnv(_env, "CERTINEXT_V2_FULFILLED_PENDING_SYNC") != "1",
                "Requires CERTINEXT_USE_V2_API + V2 credentials and CERTINEXT_V2_FULFILLED_PENDING_SYNC=1.");
            string orderId = V2EnvHelper.GetEnv(_env, "CERTINEXT_V2_FULFILLED_PENDING_ORDER", "1125823297");

            var config = new CERTInextConfig
            {
                ApiUrl = apiUrl, UseV2Api = true, OAuthClientId = clientId, OAuthClientSecret = clientSecret,
                SignerPlace = "Gateway Lab", PageSize = 100, DcvEnabled = false
            };
            var restoreLogging = TestOutputLogging.RouteTo(_output);
            try
            {
                using var real = new CERTInextClient(config);
                var proxy = DispatchProxy.Create<ICERTInextClient, OneOrderListingProxy>();
                var p = (OneOrderListingProxy)(object)proxy;
                p.Inner = real;
                p.OrderId = orderId;

                using var plugin = new CERTInextCAPlugin(proxy, config);
                var buffer = new BlockingCollection<AnyCAPluginCertificate>(10);
                await plugin.Synchronize(buffer, null, true, CancellationToken.None);

                var calls = p.Calls.ToList();
                _output.WriteLine($"Report rows read: {p.RowsListed}; passed to sync: order {orderId} only.");
                _output.WriteLine("Client calls: " + string.Join(", ", calls.GroupBy(c => c).Select(g => $"{g.Key} x{g.Count()}")));

                var record = buffer.ToArray().Should().ContainSingle(r => r.CARequestID == orderId,
                    "the order must be emitted (it is not recent, failed, or untrackable)").Subject;
                _output.WriteLine($"Emitted: CARequestID={record.CARequestID}, Status={record.Status}, ProductID={record.ProductID}, " +
                                  $"HasCertificate={!string.IsNullOrWhiteSpace(record.Certificate)}");
                if (!string.IsNullOrWhiteSpace(record.Certificate))
                {
                    var cert = new X509CertificateParser().ReadCertificate(System.Text.Encoding.ASCII.GetBytes(record.Certificate));
                    _output.WriteLine($"Certificate: Subject={cert.SubjectDN}, Serial={cert.SerialNumber.ToString(16).ToUpperInvariant()}, " +
                                      $"NotBefore={cert.NotBefore:u}, NotAfter={cert.NotAfter:u}");
                }

                calls.Should().Contain(nameof(ICERTInextClient.ResolveAndTrackOrderV2WithFamilyAsync),
                    "the Fulfilled/Pending-for-Approver pair must defer to Track Order");
                record.Status.Should().Be((int)EndEntityStatus.GENERATED, "Track Order reports the order issued");
                calls.Should().Contain(nameof(ICERTInextClient.ResolveAndDownloadCertificateV2Async),
                    "an issued order's certificate is downloaded");
                // Whether a body comes back is CA state, not plugin behaviour. Live 2026-11-15: 1125823297
                // answered 422 EMS-1165 (never generated; see Finding 35 update), so it was emitted as
                // issued without a body (sync summary IssuedNotGeneratedYet=1) for a later pass.
                if (string.IsNullOrWhiteSpace(record.Certificate))
                    _output.WriteLine("No certificate body: CERTInext reports the order issued but its certificate " +
                                      "isn't generated (see IssuedNotGeneratedYet in the sync summary above).");
            }
            finally
            {
                restoreLogging();
            }
        }
    }
}
