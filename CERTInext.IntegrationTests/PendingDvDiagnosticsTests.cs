// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0
//
// Read-only diagnostic for pending-DV orders that won't advance through sync-DCV.
// For each "orderId|domain" pair in CERTINEXT_DIAG_ORDER_IDS (comma-separated), it
// dumps the TrackOrder DCV state and probes GetDcv to determine whether CERTInext
// has actually exposed a DCV challenge for the order — the question that decides
// whether the plugin's deferred-DCV retry can ever complete it.
//
// Run:
//   export CERTINEXT_DIAG_ORDER_IDS="9937569678|bulk-0b3cbd54.scrup.org,6373633518|bulk-49818a84.scrup.org"
//   dotnet test --filter FullyQualifiedName~PendingDvDiagnostics

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    public class PendingDvDiagnosticsTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _out;

        public PendingDvDiagnosticsTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _out = output;
        }

        [SkippableFact]
        public async Task PendingDvDiagnostics_DumpDcvState()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            string raw = Environment.GetEnvironmentVariable("CERTINEXT_DIAG_ORDER_IDS");
            Skip.If(string.IsNullOrWhiteSpace(raw),
                "Set CERTINEXT_DIAG_ORDER_IDS=\"orderId|domain,orderId|domain,...\" to run the diagnostic.");

            var pairs = raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(p =>
                {
                    var bits = p.Split('|', 2);
                    return (Id: bits[0].Trim(), Domain: bits.Length > 1 ? bits[1].Trim() : null);
                })
                .ToList();

            var ct = CancellationToken.None;
            int challengeReady = 0, challengeNotReady = 0, alreadyValidated = 0, errored = 0;

            foreach (var (id, domain) in pairs)
            {
                _out.WriteLine($"==================== Order {id}  ({domain ?? "?"}) ====================");
                ICERTInextClient client = _fixture.Client;

                try
                {
                    var track = await client.TrackOrderAsync(id, ct);
                    var od = track.OrderDetails;
                    _out.WriteLine($"  OrderStatus:       {od?.OrderStatus} (id={od?.OrderStatusId})");
                    _out.WriteLine($"  CertStatus:        {od?.CertificateStatus} (id={od?.CertificateStatusId})");

                    var dv = od?.DomainVerification;
                    if (dv == null)
                    {
                        _out.WriteLine("  DomainVerification: <null>  (CERTInext has NOT exposed a DCV challenge slot)");
                    }
                    else
                    {
                        _out.WriteLine($"  DomainVerification.status: '{dv.Status}'  (0=Pending,1=Validated,2=Rejected)");
                        var entries = dv.GetDomainEntries();
                        if (entries.Count == 0)
                            _out.WriteLine("  per-domain entries: <none>");
                        foreach (var kv in entries)
                            _out.WriteLine(
                                $"    [{kv.Key}] dcvMethod='{kv.Value.DcvMethod}' dcvStatus='{kv.Value.DcvStatus}' " +
                                $"status='{kv.Value.Status}' caaStatus='{kv.Value.CaaStatus}' verifiedDate='{kv.Value.VerifiedDate}'");

                        if (dv.Status == Constants.Dcv.StatusValidated ||
                            entries.Values.All(e => e.DcvStatus == Constants.Dcv.StatusValidated))
                            alreadyValidated++;
                    }

                    // Probe GetDcv — the decisive test: does CERTInext hand back a challenge token?
                    if (!string.IsNullOrWhiteSpace(domain))
                    {
                        try
                        {
                            var dcv = await client.GetDcvAsync(id, domain, Constants.Dcv.MethodDnsTxt, ct);
                            bool tokenPresent = !string.IsNullOrWhiteSpace(dcv.DcvDetails?.Token);
                            _out.WriteLine($"  GetDcv: tokenPresent={tokenPresent}");
                            if (tokenPresent) challengeReady++;
                        }
                        catch (Exception gex)
                        {
                            _out.WriteLine($"  GetDcv: FAILED -> {gex.Message}");
                            if (gex.Message.Contains("956", StringComparison.OrdinalIgnoreCase) ||
                                gex.Message.Contains("not ready", StringComparison.OrdinalIgnoreCase))
                                challengeNotReady++;
                            else
                                errored++;
                        }
                    }
                }
                catch (Exception ex)
                {
                    _out.WriteLine($"  TrackOrder FAILED: {ex.Message}");
                    errored++;
                }
            }

            _out.WriteLine("");
            _out.WriteLine($"=== SUMMARY over {pairs.Count} orders: " +
                           $"challengeReady={challengeReady}, challengeNotReady={challengeNotReady}, " +
                           $"alreadyValidated={alreadyValidated}, errored={errored} ===");
        }
    }
}
