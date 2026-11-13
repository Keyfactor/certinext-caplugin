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
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Explicit-ID cleanup of V2 SANDBOX orders (fake credits) left behind by experiments.
    /// Opt-in: <c>CERTINEXT_V2_CLEANUP_ORDERS=&lt;comma-separated order ids&gt;</c> as a REAL
    /// environment variable (it is never read from an env file). Credentials come from
    /// ~/.env_certinext_v2.
    ///
    /// Only the listed ids are ever acted on. For each: TrackOrder (record status) -> revoke if
    /// issued, cancel if pending, skip if already revoked / cancelled / rejected / expired ->
    /// TrackOrder again (verify). A narrow read-only order-report window (yesterday..tomorrow) is
    /// read once to report each listed order's creation date and domain; no full sync is run and
    /// nothing is acted on by pattern. Set <c>CERTINEXT_V2_CLEANUP_DRYRUN=1</c> to track and report
    /// details only (no revoke/cancel). Set
    /// <c>CERTINEXT_V2_CLEANUP_FORCE_CANCEL=1</c> (single id only) to make one raw cancel attempt instead of a revoke. Emails are scrubbed from all output.
    /// </summary>
    public class V2OrderCleanupTests : IClassFixture<IntegrationTestFixture>
    {
        private const string OptInFlag = "CERTINEXT_V2_CLEANUP_ORDERS";
        private const int MaxOrders = 25;
        private const string CleanupReason = "Sandbox test order cleanup (issue 0090 lab race repro).";

        private readonly ITestOutputHelper _output;
        private readonly string _apiUrl;
        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly string _groupNumber;
        private readonly bool _v2Enabled;

        private static readonly Regex EmailRx =
            new(@"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", RegexOptions.Compiled);

        public V2OrderCleanupTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _output = output;
            var env = V2EnvHelper.LoadAndPromote();
            _apiUrl = V2EnvHelper.GetEnv(env, "CERTINEXT_API_URL");
            _clientId = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_ID");
            _clientSecret = V2EnvHelper.GetEnv(env, "CERTINEXT_CLIENT_SECRET");
            _groupNumber = V2EnvHelper.GetEnv(env, "CERTINEXT_GROUP_NUMBER", string.Empty);
            _v2Enabled = !string.IsNullOrWhiteSpace(V2EnvHelper.GetEnv(env, "CERTINEXT_USE_V2_API"))
                         && !string.IsNullOrWhiteSpace(_apiUrl)
                         && !string.IsNullOrWhiteSpace(_clientId)
                         && !string.IsNullOrWhiteSpace(_clientSecret);
        }

        private static string Scrub(string s)
        {
            if (string.IsNullOrEmpty(s)) return s ?? string.Empty;
            s = EmailRx.Replace(s, "<email>");
            return s.Length > 500 ? s.Substring(0, 500) + "..." : s;
        }

        private void W(string s) => _output.WriteLine(Scrub(s));

        private static string Describe(Exception ex) => $"{ex.GetType().Name}: {ex.Message}";

        private CERTInextConfig BuildConfig() => new CERTInextConfig
        {
            ApiUrl = _apiUrl,
            UseV2Api = true,
            OAuthClientId = _clientId,
            OAuthClientSecret = _clientSecret,
            RequestorName = "Keyfactor Integration Test",
            RequestorIsdCode = "1",
            RequestorMobileNumber = "0000000000",
            SignerPlace = "Gateway Lab",
            SignerIp = "127.0.0.1",
            GroupNumber = _groupNumber,
            PageSize = 100,
            DcvEnabled = false
        };

        private static bool IsTerminalNoAction(string status) =>
            string.Equals(status, Constants.ApiV2.StatusRevoked, StringComparison.OrdinalIgnoreCase)
            || string.Equals(status, Constants.ApiV2.StatusCancelled, StringComparison.OrdinalIgnoreCase)
            || string.Equals(status, Constants.ApiV2.StatusRejected, StringComparison.OrdinalIgnoreCase)
            || string.Equals(status, Constants.ApiV2.StatusExpired, StringComparison.OrdinalIgnoreCase);

        private static bool IsPending(string status) =>
            !string.IsNullOrEmpty(status) && status.StartsWith("pending-", StringComparison.OrdinalIgnoreCase);

        private sealed class Row
        {
            public string OrderId;
            public string Before = "-";
            public string Action = "none";
            public string After = "-";
            public string Notes = string.Empty;
        }

        [SkippableFact]
        public async Task V2_CleanupExplicitOrders_RevokeOrCancelListedIdsOnly()
        {
            Skip.If(!_v2Enabled,
                "V2 credentials not configured in ~/.env_certinext_v2 (CERTINEXT_USE_V2_API, API_URL, CLIENT_ID, CLIENT_SECRET).");
            string flag = Environment.GetEnvironmentVariable(OptInFlag);
            Skip.If(string.IsNullOrWhiteSpace(flag),
                $"Opt-in: set {OptInFlag}=<comma-separated order ids> as a real environment variable.");

            var ids = flag.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(s => s.Trim()).Distinct(StringComparer.Ordinal).ToList();
            Assert.NotEmpty(ids);
            Assert.True(ids.Count <= MaxOrders, $"At most {MaxOrders} order ids per run.");
            Assert.All(ids, id => Assert.Matches("^[0-9]{1,20}$", id)); // digits only: refuse anything pattern-like

            var cfg = BuildConfig();
            using var client = new CERTInextClient(cfg);
            string family = Constants.ApiV2.FamilySsl;
            bool dryRun = Environment.GetEnvironmentVariable("CERTINEXT_V2_CLEANUP_DRYRUN") == "1";
            if (dryRun) W("DRY RUN: track + details only; no revoke/cancel will be sent.");
            bool forceCancel = Environment.GetEnvironmentVariable("CERTINEXT_V2_CLEANUP_FORCE_CANCEL") == "1";
            Assert.True(!forceCancel || ids.Count == 1, "CERTINEXT_V2_CLEANUP_FORCE_CANCEL requires exactly one order id.");
            if (forceCancel) W("FORCE CANCEL: one raw cancel attempt (no revoke, no retry) for the single listed order.");

            W($"V2 order cleanup: {ids.Count} listed order(s), family={family}");

            // 1) Read-only detail lookup (creation date, domain) from a narrow order-report window.
            //    Only the listed ids are retained; nothing here drives an action.
            var listed = new Dictionary<string, OrderReportEntryV2>(StringComparer.Ordinal);
            try
            {
                string from = DateTime.UtcNow.AddDays(-1).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
                string to = DateTime.UtcNow.AddDays(1).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
                int scanned = 0;
                await foreach (var e in client.ListOrdersV2Async(from, to, 100))
                {
                    scanned++;
                    if (e?.OrderNumber != null && ids.Contains(e.OrderNumber))
                        listed[e.OrderNumber] = e;
                }
                W($"order-report window {from}..{to}: scanned={scanned}, matched listed ids={listed.Count}");
            }
            catch (Exception ex)
            {
                W("order-report lookup failed (details only; cleanup continues): " + Describe(ex));
            }

            foreach (var id in ids)
            {
                if (listed.TryGetValue(id, out var e))
                    W($"detail order={id} domain={e.DomainName} orderStatus={e.OrderStatus} certStatus={e.CertificateStatus} " +
                      $"orderDate={e.OrderDate} productCode={e.ProductCode} requestNumber={e.RequestNumber}");
                else
                    W($"detail order={id} NOT present in order-report window");
            }

            // 2) Per-order: track -> act -> track.
            var rows = new List<Row>();
            foreach (var id in ids)
            {
                var row = new Row { OrderId = id };
                rows.Add(row);

                V2OrderStatusResponse before = null;
                try
                {
                    before = await client.TrackOrderV2Async(family, id);
                    row.Before = before.Status ?? "(null)";
                    W($"track-before order={id} status={before.Status} domain={before.Domain} variant={before.ProductVariant} " +
                      $"issuedAt={before.IssuedAt} expiresAt={before.ExpiresAt}");
                }
                catch (KeyNotFoundException)
                {
                    row.Before = "NOT FOUND";
                    row.Action = "skipped (not found in " + family + ")";
                    W($"order={id} not found in family {family}; no action taken");
                    continue;
                }
                catch (Exception ex)
                {
                    row.Before = "TRACK ERROR";
                    row.Action = "skipped";
                    row.Notes = Scrub(Describe(ex));
                    continue;
                }

                string status = before.Status;
                if (dryRun)
                {
                    row.Action = "dry-run (none)";
                    row.After = row.Before;
                    continue;
                }
                try
                {
                    if (IsTerminalNoAction(status))
                    {
                        row.Action = "skip (already " + status + ")";
                    }
                    else if (forceCancel)
                    {
                        // Single attempt via the raw helper (same POST .../cancel endpoint as CancelOrderV2Async)
                        // so the exact HTTP status and body detail are captured; no retry, no other mutation.
                        row.Action = "force-cancel (single attempt)";
                        try
                        {
                            await V2RawHttpHelpers.CancelSslOrderRawAsync(_apiUrl, _clientId, _clientSecret, id, CleanupReason);
                            row.Action += " -> accepted (2xx)";
                        }
                        catch (Exception cex)
                        {
                            row.Action += " -> REJECTED";
                            row.Notes += "cancel response: " + Scrub(Describe(cex));
                        }
                    }
                    else if (string.Equals(status, Constants.ApiV2.StatusIssued, StringComparison.OrdinalIgnoreCase))
                    {
                        row.Action = await RevokeAsync(client, family, id, row);
                    }
                    else if (IsPending(status))
                    {
                        var outcome = await client.CancelOrderV2Async(family, id, CleanupReason);
                        row.Action = "cancel -> " + outcome;
                    }
                    else
                    {
                        row.Action = "skip (unrecognised status; not acting)";
                    }
                }
                catch (Exception ex)
                {
                    row.Action += (row.Action == "none" ? "" : "; ") + "ACTION FAILED";
                    row.Notes += (row.Notes.Length > 0 ? " | " : "") + Scrub(Describe(ex));
                }

                try
                {
                    var after = await client.TrackOrderV2Async(family, id);
                    row.After = after.Status ?? "(null)";
                    if (after.Revocation != null)
                        row.Notes += (row.Notes.Length > 0 ? " | " : "") +
                                     $"revocation.reason={after.Revocation.Reason} processedAt={after.Revocation.ProcessedAt}";
                }
                catch (Exception ex)
                {
                    row.After = "TRACK ERROR";
                    row.Notes += (row.Notes.Length > 0 ? " | " : "") + Scrub(Describe(ex));
                }
            }

            if (forceCancel)
            {
                try
                {
                    string from2 = DateTime.UtcNow.AddDays(-1).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
                    string to2 = DateTime.UtcNow.AddDays(1).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
                    bool found = false;
                    await foreach (var e2 in client.ListOrdersV2Async(from2, to2, 100))
                        if (e2?.OrderNumber != null && ids.Contains(e2.OrderNumber))
                        {
                            found = true;
                            W($"listing-after order={e2.OrderNumber} orderStatus={e2.OrderStatus} certStatus={e2.CertificateStatus} orderDate={e2.OrderDate}");
                        }
                    if (!found) W("listing-after: listed order not present in window");
                }
                catch (Exception lex) { W("listing-after failed: " + Describe(lex)); }
            }

            W("=== result: order | before | action | after | notes ===");
            foreach (var r in rows)
                W($"RESULT {r.OrderId} | {r.Before} | {r.Action} | {r.After} | {r.Notes}");

            if (dryRun || forceCancel) return; // force-cancel is a probe: outcome is reported, not asserted

            // Pass only when every listed order ended in a terminal non-issued state.
            var bad = rows.Where(r => !IsTerminalNoAction(r.After)).Select(r => $"{r.OrderId}({r.After})").ToList();
            Assert.True(bad.Count == 0, "Orders not in a terminal state after cleanup: " + string.Join(", ", bad));
        }

        /// <summary>
        /// Revoke an issued order. Tries "superseded" (what plugin reason 4 maps to); if CERTInext
        /// rejects it, records the exact rejection in <paramref name="row"/> and retries once with
        /// "unspecified" so a spec-vs-live reason discrepancy is surfaced instead of hidden.
        /// </summary>
        private static async Task<string> RevokeAsync(CERTInextClient client, string family, string id, Row row)
        {
            try
            {
                await client.RevokeOrderV2Async(family, id,
                    new V2RevokeRequest { Reason = "superseded", Note = CleanupReason });
                return "revoke(reason=superseded)";
            }
            catch (Exception ex)
            {
                row.Notes += "revoke(superseded) rejected: " + Scrub(Describe(ex));
            }

            await client.RevokeOrderV2Async(family, id,
                new V2RevokeRequest { Reason = "unspecified", Note = CleanupReason });
            return "revoke(reason=unspecified, after superseded rejected)";
        }
    }
}
