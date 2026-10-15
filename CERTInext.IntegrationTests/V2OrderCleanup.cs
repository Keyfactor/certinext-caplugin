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
using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Sandbox order cleanup keyed on the order's own V2 status, not on what <c>GetSingleRecord</c>
    /// returns. <c>GetSingleRecord</c> reports an order as pending until its certificate is
    /// downloadable, and right after <c>issued</c> the download can still return 422 (EMS-1165); a
    /// cleanup that cancels whenever the record is not yet GENERATED therefore cancels an order that
    /// is already issuing, and the sandbox still produces the certificate (leaked order 9185757376,
    /// and the <c>F001</c> child of a cancelled OV order). So: <c>issued</c> is revoked (one retry on
    /// "still being processed"), anything not yet terminal is cancelled, and the order is re-tracked
    /// afterwards to confirm the outcome.
    /// </summary>
    internal static class V2OrderCleanup
    {
        public static async Task<bool> RevokeOrCancelAsync(
            CERTInextClient client, string orderId, string cancelReason, Action<string> log)
        {
            if (string.IsNullOrWhiteSpace(orderId))
                return true;

            try
            {
                var (family, status) = await client.ResolveAndTrackOrderV2WithFamilyAsync(orderId);
                string st = status.Status ?? string.Empty;
                if (IsTerminal(st))
                {
                    log($"Cleanup: order {orderId} already terminal ({st}).");
                    return true;
                }

                if (string.Equals(st, Constants.ApiV2.StatusIssued, StringComparison.OrdinalIgnoreCase))
                {
                    var revoke = new V2RevokeRequest { Reason = "superseded", Note = "V2 integration test cleanup" };
                    try
                    {
                        await client.RevokeOrderV2Async(family, orderId, revoke);
                    }
                    catch (InvalidOperationException ex) when (ex.Message.Contains("still being processed"))
                    {
                        await Task.Delay(TimeSpan.FromSeconds(15));
                        await client.RevokeOrderV2Async(family, orderId, revoke);
                    }
                    var after = await client.ResolveAndTrackOrderV2Async(orderId);
                    log($"Cleanup: revoked issued order {orderId}; re-tracked status={after.Status}.");
                    return IsTerminal(after.Status);
                }

                var outcome = await client.CancelOrderV2Async(family, orderId, cancelReason);
                var tracked = await client.ResolveAndTrackOrderV2Async(orderId);
                log($"Cleanup: cancelled non-issued order {orderId} (was {st}) -> {outcome}; re-tracked status={tracked.Status}.");
                return IsTerminal(tracked.Status);
            }
            catch (Exception ex)
            {
                log($"Cleanup FAILED for order {orderId}: {ex.GetType().Name}: {ex.Message}. " +
                    "Revoke/cancel it by hand in the CERTInext portal if it should not remain pending.");
                return false;
            }
        }

        private static bool IsTerminal(string status) =>
            string.Equals(status, Constants.ApiV2.StatusRevoked, StringComparison.OrdinalIgnoreCase)
            || string.Equals(status, Constants.ApiV2.StatusCancelled, StringComparison.OrdinalIgnoreCase)
            || string.Equals(status, Constants.ApiV2.StatusRejected, StringComparison.OrdinalIgnoreCase);
    }
}
