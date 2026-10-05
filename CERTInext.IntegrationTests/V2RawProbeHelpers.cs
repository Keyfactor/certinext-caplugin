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
//
// Shared raw-HTTP helpers for this project's V2 "raw-body place-then-cancel" triage probes.
// Before this file existed, OrganizationBlockV2ProbeTests.cs had its own private
// GetV2AccessTokenAsync/CancelSslOrderRawAsync pair (token-fetch inlined directly into its
// CancelSslOrderRawAsync), and IdempotencyKeyV2ProbeTests.cs carried a near-identical private
// copy of both as two separate methods. Issue 0058 asked that a third file (V2GapProbeTests.cs)
// reuse rather than triplicate that logic, so both methods below were extracted here and all
// three files now call them.
//
// Behavior for the two pre-existing call sites is unchanged: both methods default to no
// explicit RestSharp timeout (the <c>timeout</c> parameter defaults to null), exactly matching
// what the two original private copies did. Callers that need the longer timeout this repo's
// newer V2 probes use for slow sandbox endpoints (EmailNotificationsV2ProbeTests /
// UccDcvShapeV2ProbeTests / UccPendingSanOrderProbeTests' 120s <c>NewApiClient</c>) pass it
// explicitly via the optional timeout parameter on each method.
namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    using System;
    using System.Text.Json;
    using System.Threading.Tasks;
    using RestSharp;

    internal static class V2RawProbeHelpers
    {
        /// <summary>
        /// Builds a <see cref="RestClient"/> against <paramref name="baseUrl"/>. When
        /// <paramref name="timeout"/> is null (the default), this is exactly
        /// <c>new RestClient(baseUrl)</c> — the framework default timeout the two original
        /// private helper copies always used.
        /// </summary>
        public static RestClient NewApiClient(string baseUrl, TimeSpan? timeout = null) =>
            timeout.HasValue
                ? new RestClient(new RestClientOptions(baseUrl) { Timeout = timeout.Value })
                : new RestClient(baseUrl);

        /// <summary>
        /// Standalone OAuth2 client_credentials token fetch against <c>{apiUrl}/oauth/token</c>.
        /// Throws if the token call itself is not successful — a failed token call is always a
        /// probe-mechanism failure, never a CA-response finding worth recording.
        /// </summary>
        public static async Task<string> GetV2AccessTokenAsync(
            string apiUrl, string clientId, string clientSecret, TimeSpan? timeout = null)
        {
            string tokenUrl = apiUrl.TrimEnd('/') + "/oauth/token";
            using var tokenClient = NewApiClient(tokenUrl, timeout);
            var tokenReq = new RestRequest(string.Empty, Method.Post);
            tokenReq.AddHeader("Content-Type", "application/x-www-form-urlencoded");
            tokenReq.AddParameter("grant_type", "client_credentials");
            tokenReq.AddParameter("client_id", clientId);
            tokenReq.AddParameter("client_secret", clientSecret);
            var tokenResp = await tokenClient.ExecuteAsync(tokenReq);
            if (!tokenResp.IsSuccessful || string.IsNullOrWhiteSpace(tokenResp.Content))
                throw new Exception($"Token request failed: {(int)tokenResp.StatusCode}");

            using var tokenDoc = JsonDocument.Parse(tokenResp.Content);
            return tokenDoc.RootElement.GetProperty("access_token").GetString();
        }

        /// <summary>
        /// Cancels a V2 SSL order via <c>POST {SslCertificatesPath}/{orderId}/cancel</c>. Throws
        /// on a non-success response — matches the two original private
        /// <c>CancelSslOrderRawAsync</c> copies exactly (both threw on failure; neither returned
        /// a raw status/body).
        /// </summary>
        public static async Task CancelSslOrderRawAsync(
            string apiUrl, string clientId, string clientSecret, string orderId, string reason,
            TimeSpan? timeout = null)
        {
            string accessToken = await GetV2AccessTokenAsync(apiUrl, clientId, clientSecret, timeout);

            using var apiClient = NewApiClient(apiUrl.TrimEnd('/'), timeout);
            var cancelReq = new RestRequest($"{Constants.ApiV2.SslCertificatesPath}/{orderId}/cancel", Method.Post);
            cancelReq.AddHeader("Authorization", $"Bearer {accessToken}");
            cancelReq.AddJsonBody(new { reason });
            var cancelResp = await apiClient.ExecuteAsync(cancelReq);
            if (!cancelResp.IsSuccessful)
                throw new Exception(
                    $"Cancel request failed: {(int)cancelResp.StatusCode} {cancelResp.Content}");
        }
    }
}
