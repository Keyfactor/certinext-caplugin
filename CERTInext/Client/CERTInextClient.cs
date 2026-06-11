// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.Models;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using RestSharp;
using RestSharp.Authenticators;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Client
{
    /// <summary>
    /// RestSharp-based implementation of <see cref="ICERTInextClient"/> that wraps
    /// all CERTInext REST API operations.
    ///
    /// Authentication: the real CERTInext API requires a computed <c>authKey</c> in every
    /// request body meta block: <c>authKey = SHA256(accessKey + ts + txn)</c> (hex, lowercase).
    /// OAuth bearer token authentication is also supported for accounts that have it enabled.
    ///
    /// All endpoints use HTTP POST.  The base URL is configured as-is (e.g.
    /// <c>https://us-api.certinext.io/emSignHub-API/</c>) and endpoint names are
    /// appended directly (e.g. <c>ValidateCredentials</c>).
    /// </summary>
    public class CERTInextClient : ICERTInextClient, IDisposable
    {
        private static readonly ILogger Logger = LogHandler.GetClassLogger<CERTInextClient>();

        private readonly CERTInextConfig _config;
        private readonly RestClient _http;

        // OAuth2 token cache — refreshed when expired
        private string _cachedToken;
        private DateTime _tokenExpiry = DateTime.MinValue;
        private readonly SemaphoreSlim _tokenLock = new SemaphoreSlim(1, 1);

        // ---------------------------------------------------------------------------
        // Construction
        // ---------------------------------------------------------------------------

        public CERTInextClient(CERTInextConfig config)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));

            var isOAuth = config.AuthMode.Equals(Constants.Config.AuthModeOAuth, StringComparison.OrdinalIgnoreCase) ||
                          config.AuthMode.Equals(Constants.Config.AuthModeOAuth2, StringComparison.OrdinalIgnoreCase);

            var options = new RestClientOptions(_config.ApiUrl.TrimEnd('/') + "/")
            {
                ThrowOnAnyError = false,
                Timeout = TimeSpan.FromSeconds(120),
                // OAuth: inject Bearer token per-request via authenticator.
                // AccessKey: no HTTP-level authenticator — auth is in the JSON body meta block.
                Authenticator = isOAuth ? new CERTInextOAuthAuthenticator(GetOrRefreshTokenAsync) : null
            };

            _http = new RestClient(options);
        }

        // ---------------------------------------------------------------------------
        // IDisposable
        // ---------------------------------------------------------------------------

        public void Dispose()
        {
            _http?.Dispose();
            _tokenLock?.Dispose();
        }

        // ---------------------------------------------------------------------------
        // Nested authenticator — injects Authorization: Bearer <token> per-request
        // ---------------------------------------------------------------------------

        /// <summary>
        /// RestSharp authenticator that fetches (or reuses a cached) OAuth2 bearer
        /// token and injects it as an <c>Authorization: Bearer</c> header on every
        /// outgoing request.  The token provider is the client's own
        /// <see cref="GetOrRefreshTokenAsync"/> method, which handles caching and
        /// refresh with a semaphore so concurrent requests don't trigger redundant
        /// token fetches.
        /// </summary>
        private sealed class CERTInextOAuthAuthenticator : AuthenticatorBase
        {
            private readonly Func<CancellationToken, Task<string>> _tokenProvider;

            public CERTInextOAuthAuthenticator(Func<CancellationToken, Task<string>> tokenProvider)
                : base(string.Empty) // base stores the token; we override GetAuthenticationParameter instead
            {
                _tokenProvider = tokenProvider ?? throw new ArgumentNullException(nameof(tokenProvider));
            }

            protected override async ValueTask<Parameter> GetAuthenticationParameter(string accessToken)
            {
                // Fetch (or return the cached) token from the provider.
                // CancellationToken.None is acceptable here because RestSharp does not
                // pass a token through the authenticator interface.
                string token = await _tokenProvider(CancellationToken.None);
                return new HeaderParameter(KnownHeaders.Authorization, $"Bearer {token}");
            }
        }

        // ---------------------------------------------------------------------------
        // ICERTInextClient — real API methods
        // ---------------------------------------------------------------------------

        /// <inheritdoc/>
        public async Task PingAsync(CancellationToken ct = default)
        {
            Logger.MethodEntry(LogLevel.Trace);

            // POST {baseURL}ValidateCredentials — the real health/connectivity probe
            var body = new ValidateCredentialsRequest
            {
                Meta = await BuildMetaAsync(ct)
            };

            var req = new RestRequest(Constants.Api.ValidateCredentialsPath, Method.Post);
            req.AddJsonBody(JsonSerializer.Serialize(body, GetJsonOptions()));

            var sw = System.Diagnostics.Stopwatch.StartNew();
            var resp = await ExecuteWithRetryAsync(req, ct);
            sw.Stop();

            Logger.LogInformation(
                "CERTInext API call: Method=POST, Path={Path}, HttpStatus={Status}, LatencyMs={Latency}, AuthMode={AuthMode}",
                Constants.Api.ValidateCredentialsPath, (int)resp.StatusCode, sw.ElapsedMilliseconds, _config.AuthMode);

            if (!resp.IsSuccessful)
            {
                if (resp.StatusCode == HttpStatusCode.Unauthorized || resp.StatusCode == HttpStatusCode.Forbidden)
                {
                    Logger.LogError(
                        "CERTInext health check authentication failure. HttpStatus={Status}, AuthMode={AuthMode}, LatencyMs={Latency}",
                        (int)resp.StatusCode, _config.AuthMode, sw.ElapsedMilliseconds);
                }
                else
                {
                    Logger.LogError(
                        "CERTInext health check failed. HttpStatus={Status}, LatencyMs={Latency}",
                        (int)resp.StatusCode, sw.ElapsedMilliseconds);
                }

                throw new Exception(
                    $"CERTInext health check failed. HTTP {(int)resp.StatusCode}. See gateway logs for details.");
            }

            // Deserialize and check meta.status = "1"
            var result = DeserializeOrThrow<ValidateCredentialsResponse>(resp, "validate credentials");
            if (result.Meta != null && !result.Meta.IsSuccess)
            {
                // Authentication-failure-shaped event: log at Error so SOX-required
                // SIEM rules on authentication failures fire.  Every other meta-failure
                // call site logs at the LogApiFailure default (Warning).
                LogApiFailure("ValidateCredentials", resp,
                    result.Meta.ErrorCode, result.Meta.ErrorMessage,
                    level: LogLevel.Error);
                throw new Exception(
                    $"CERTInext credential validation failed: {result.Meta.ErrorMessage ?? result.Meta.ErrorCode}. " +
                    "See gateway logs for details.");
            }

            Logger.LogInformation("CERTInext health check successful. LatencyMs={Latency}", sw.ElapsedMilliseconds);
            Logger.MethodExit(LogLevel.Trace);
        }

        /// <inheritdoc/>
        public async Task<GenerateOrderResponse> PlaceOrderAsync(
            GenerateOrderSslRequest request,
            CancellationToken ct = default)
        {
            Logger.MethodEntry(LogLevel.Trace);

            // Inject authentication meta if not already set
            if (request.Meta == null)
                request.Meta = await BuildMetaAsync(ct);

            Logger.LogInformation(
                "Submitting order to CERTInext. ProductCode={ProductCode}",
                request.OrderDetails?.ProductCode);

            GenerateOrderResponse result = null;
            RestResponse resp = null;
            // Cumulative backoff time across all rate-limit retries this call.  Emitted
            // on the success branch so an operator scraping gateway logs for rate-limit
            // pressure (SOC2 CC7.2 anomaly-detection) can correlate by single log line
            // rather than threading per-attempt warnings by OrderNumber.
            double totalRateLimitBackoffSeconds = 0.0;

            // Issue #8 rate-limit retry: the sandbox returns "Inactive Account User."
            // as a generic error string for several conditions, including burst-rate-limit
            // rejection. Empirically this resolves within seconds; auto-retrying lets a
            // transient burst limit hit transparently. After RateLimitMaxAttempts the
            // original exception is propagated unchanged so a genuinely-inactive account
            // surfaces as the same operator-facing failure today.
            for (int attempt = 1; ; attempt++)
            {
                // Refresh the request body's meta block on every retry — txn must be
                // unique per call (CERTInext rejects duplicate txns), and a fresh ts/txn
                // gives the CA a clean canary for whether the limiter has cleared.
                if (attempt > 1)
                    request.Meta = await BuildMetaAsync(ct);

                var req = new RestRequest(Constants.Api.GenerateOrderSslPath, Method.Post);
                req.AddJsonBody(JsonSerializer.Serialize(request, GetJsonOptions()));

                var sw = System.Diagnostics.Stopwatch.StartNew();
                resp = await ExecuteWithRetryAsync(req, ct);
                sw.Stop();

                Logger.LogInformation(
                    "CERTInext API call: Method=POST, Path={Path}, HttpStatus={Status}, LatencyMs={Latency}, AuthMode={AuthMode}, RateLimitRetryAttempt={Attempt}",
                    Constants.Api.GenerateOrderSslPath, (int)resp.StatusCode, sw.ElapsedMilliseconds, _config.AuthMode, attempt);

                if (resp.StatusCode == HttpStatusCode.Unauthorized || resp.StatusCode == HttpStatusCode.Forbidden)
                {
                    Logger.LogError(
                        "PlaceOrder API authentication failure. HttpStatus={Status}, AuthMode={AuthMode}",
                        (int)resp.StatusCode, _config.AuthMode);
                    throw new Exception(
                        $"Authentication failure during certificate order. HTTP {(int)resp.StatusCode}. See gateway logs for details.");
                }

                result = DeserializeOrThrow<GenerateOrderResponse>(resp, "place order");

                if (result.Meta != null && !result.Meta.IsSuccess)
                {
                    LogApiFailure(Constants.Api.GenerateOrderSslPath, resp,
                        result.Meta.ErrorCode, result.Meta.ErrorMessage);

                    // Auto-retry the documented rate-limit surface up to RateLimitMaxAttempts.
                    if (IsRateLimitSurface(result.Meta.ErrorMessage) && attempt < RateLimitMaxAttempts)
                    {
                        double waitSeconds = ComputeRateLimitBackoffSeconds(attempt);
                        totalRateLimitBackoffSeconds += waitSeconds;
                        Logger.LogWarning(
                            "PlaceOrder hit rate-limit-shaped error \"{ErrorMessage}\" (attempt {Attempt}/{Max}). " +
                            "Backing off {WaitSeconds:F1}s before retrying. See Troubleshooting in README for context.",
                            result.Meta.ErrorMessage, attempt, RateLimitMaxAttempts, waitSeconds);
                        try
                        {
                            await Task.Delay(TimeSpan.FromSeconds(waitSeconds), ct);
                        }
                        catch (OperationCanceledException)
                        {
                            throw;
                        }
                        continue; // retry
                    }

                    throw new Exception(
                        $"CERTInext order failed: {result.Meta.ErrorMessage ?? result.Meta.ErrorCode}. " +
                        "See gateway logs for details.");
                }

                // Success — if we retried, emit a single summary line so the rate-limit
                // pressure is correlatable per-call without joining the per-attempt
                // warnings by OrderNumber.  (SOC2 CC7.2 anomaly-detection enablement.)
                if (attempt > 1)
                {
                    Logger.LogInformation(
                        "PlaceOrder succeeded after rate-limit retries. OrderNumber={OrderNumber}, " +
                        "RateLimitRetryCount={RetryCount}, TotalBackoffSeconds={BackoffSeconds:F1}",
                        result.OrderDetails?.OrderNumber, attempt - 1, totalRateLimitBackoffSeconds);
                }
                break; // success
            }

            Logger.LogInformation(
                "CERTInext order placed. OrderNumber={OrderNumber}, RequestNumber={RequestNumber}",
                result.OrderDetails?.OrderNumber, result.OrderDetails?.RequestNumber);
            Logger.MethodExit(LogLevel.Trace);
            return result;
        }

        /// <inheritdoc/>
        public async Task SubmitCsrAsync(SubmitCsrRequest request, CancellationToken ct = default)
        {
            Logger.MethodEntry(LogLevel.Trace);

            if (request.Meta == null)
                request.Meta = await BuildMetaAsync(ct);

            Logger.LogInformation(
                "Submitting CSR to CERTInext. OrderNumber={OrderNumber}",
                request.OrderDetails?.OrderNumber);

            var req = new RestRequest(Constants.Api.SubmitCsrPath, Method.Post);
            req.AddJsonBody(JsonSerializer.Serialize(request, GetJsonOptions()));

            var sw = System.Diagnostics.Stopwatch.StartNew();
            var resp = await ExecuteWithRetryAsync(req, ct);
            sw.Stop();

            Logger.LogInformation(
                "CERTInext API call: Method=POST, Path={Path}, HttpStatus={Status}, LatencyMs={Latency}, AuthMode={AuthMode}",
                Constants.Api.SubmitCsrPath, (int)resp.StatusCode, sw.ElapsedMilliseconds, _config.AuthMode);

            if (!resp.IsSuccessful)
            {
                LogApiFailure(Constants.Api.SubmitCsrPath, resp);
                throw new Exception($"CERTInext SubmitCSR failed. HTTP {(int)resp.StatusCode}. See gateway logs for details.");
            }

            Logger.MethodExit(LogLevel.Trace);
        }

        /// <inheritdoc/>
        public async Task<TrackOrderResponse> TrackOrderAsync(string orderNumber, CancellationToken ct = default)
        {
            Logger.MethodEntry(LogLevel.Trace);

            var body = new TrackOrderRequest
            {
                Meta = await BuildMetaAsync(ct),
                OrderDetails = new TrackOrderDetails { OrderNumber = orderNumber }
            };

            var req = new RestRequest(Constants.Api.TrackOrderPath, Method.Post);
            req.AddJsonBody(JsonSerializer.Serialize(body, GetJsonOptions()));

            var sw = System.Diagnostics.Stopwatch.StartNew();
            var resp = await ExecuteWithRetryAsync(req, ct);
            sw.Stop();

            Logger.LogInformation(
                "CERTInext API call: Method=POST, Path={Path}, HttpStatus={Status}, LatencyMs={Latency}, AuthMode={AuthMode}",
                Constants.Api.TrackOrderPath, (int)resp.StatusCode, sw.ElapsedMilliseconds, _config.AuthMode);

            if (resp.StatusCode == HttpStatusCode.NotFound)
            {
                Logger.LogWarning("CERTInext order not found. OrderNumber={OrderNumber}", orderNumber);
                throw new KeyNotFoundException($"Order '{orderNumber}' was not found in CERTInext.");
            }

            if (resp.StatusCode == HttpStatusCode.Unauthorized || resp.StatusCode == HttpStatusCode.Forbidden)
            {
                Logger.LogError(
                    "TrackOrder API authentication failure. OrderNumber={OrderNumber}, HttpStatus={Status}, AuthMode={AuthMode}",
                    orderNumber, (int)resp.StatusCode, _config.AuthMode);
                throw new Exception(
                    $"Authentication failure tracking order '{orderNumber}'. HTTP {(int)resp.StatusCode}. See gateway logs for details.");
            }

            var result = DeserializeOrThrow<TrackOrderResponse>(resp, $"track order {orderNumber}");

            // A meta status of "0" with errorCode EMS-913 or similar means the order was not found
            if (result.Meta != null && !result.Meta.IsSuccess)
            {
                LogApiFailure($"{Constants.Api.TrackOrderPath} {orderNumber}", resp,
                    result.Meta.ErrorCode, result.Meta.ErrorMessage);
                if (result.Meta.ErrorCode != null &&
                    (result.Meta.ErrorCode.StartsWith("EMS-9") || result.Meta.ErrorMessage?.Contains("not found", StringComparison.OrdinalIgnoreCase) == true))
                {
                    throw new KeyNotFoundException($"Order '{orderNumber}' was not found in CERTInext. Error: {result.Meta.ErrorMessage}");
                }
                throw new Exception(
                    $"CERTInext TrackOrder failed for order '{orderNumber}': {result.Meta.ErrorMessage ?? result.Meta.ErrorCode}.");
            }

            Logger.MethodExit(LogLevel.Trace);
            return result;
        }

        /// <inheritdoc/>
        public async Task<GetCertificateResponse> DownloadCertificateAsync(string orderNumber, CancellationToken ct = default)
        {
            Logger.MethodEntry(LogLevel.Trace);

            var body = new GetCertificateRequest
            {
                Meta = await BuildMetaAsync(ct),
                OrderDetails = new GetCertificateOrderDetails
                {
                    OrderNumber = orderNumber,
                    RequestorEmail = _config.RequestorEmail
                }
            };

            var req = new RestRequest(Constants.Api.GetCertificatePath, Method.Post);
            req.AddJsonBody(JsonSerializer.Serialize(body, GetJsonOptions()));

            var sw = System.Diagnostics.Stopwatch.StartNew();
            var resp = await ExecuteWithRetryAsync(req, ct);
            sw.Stop();

            Logger.LogInformation(
                "CERTInext API call: Method=POST, Path={Path}, HttpStatus={Status}, LatencyMs={Latency}, AuthMode={AuthMode}",
                Constants.Api.GetCertificatePath, (int)resp.StatusCode, sw.ElapsedMilliseconds, _config.AuthMode);

            if (resp.StatusCode == HttpStatusCode.Unauthorized || resp.StatusCode == HttpStatusCode.Forbidden)
            {
                Logger.LogError(
                    "DownloadCertificate API authentication failure. OrderNumber={OrderNumber}, HttpStatus={Status}, AuthMode={AuthMode}",
                    orderNumber, (int)resp.StatusCode, _config.AuthMode);
                throw new Exception(
                    $"Authentication failure downloading certificate for order '{orderNumber}'. HTTP {(int)resp.StatusCode}. See gateway logs for details.");
            }

            var result = DeserializeOrThrow<GetCertificateResponse>(resp, $"download certificate {orderNumber}");

            if (result.Meta != null && !result.Meta.IsSuccess)
            {
                LogApiFailure($"{Constants.Api.GetCertificatePath} {orderNumber}", resp,
                    result.Meta.ErrorCode, result.Meta.ErrorMessage);
                throw new Exception(
                    $"CERTInext GetCertificate failed for order '{orderNumber}': {result.Meta.ErrorMessage ?? result.Meta.ErrorCode}.");
            }

            Logger.MethodExit(LogLevel.Trace);
            return result;
        }

        /// <inheritdoc/>
        public async Task RevokeOrderAsync(RevokeOrderRequest request, CancellationToken ct = default)
        {
            Logger.MethodEntry(LogLevel.Trace);

            if (request.Meta == null)
                request.Meta = await BuildMetaAsync(ct);

            Logger.LogInformation(
                "Submitting revocation request to CERTInext. OrderNumber={OrderNumber}, RevokeReasonId={ReasonId}",
                request.RevocationDetails?.OrderNumber, request.RevocationDetails?.RevokeReasonId);

            var req = new RestRequest(Constants.Api.RevokeOrderPath, Method.Post);
            req.AddJsonBody(JsonSerializer.Serialize(request, GetJsonOptions()));

            var sw = System.Diagnostics.Stopwatch.StartNew();
            var resp = await ExecuteWithRetryAsync(req, ct);
            sw.Stop();

            Logger.LogInformation(
                "CERTInext API call: Method=POST, Path={Path}, HttpStatus={Status}, LatencyMs={Latency}, AuthMode={AuthMode}",
                Constants.Api.RevokeOrderPath, (int)resp.StatusCode, sw.ElapsedMilliseconds, _config.AuthMode);

            if (!resp.IsSuccessful)
            {
                if (resp.StatusCode == HttpStatusCode.Unauthorized || resp.StatusCode == HttpStatusCode.Forbidden)
                {
                    Logger.LogError(
                        "RevokeOrder API authentication failure. OrderNumber={OrderNumber}, HttpStatus={Status}, AuthMode={AuthMode}",
                        request.RevocationDetails?.OrderNumber, (int)resp.StatusCode, _config.AuthMode);
                    throw new Exception(
                        $"Authentication failure revoking order '{request.RevocationDetails?.OrderNumber}'. " +
                        $"HTTP {(int)resp.StatusCode}. See gateway logs for details.");
                }

                string errMsg = ExtractErrorMessage(resp.Content,
                    $"revoke order {request.RevocationDetails?.OrderNumber}");
                Logger.LogError(
                    "RevokeOrder API call failed. OrderNumber={OrderNumber}, HttpStatus={Status}, Error={Error}",
                    request.RevocationDetails?.OrderNumber, (int)resp.StatusCode, errMsg);
                throw new Exception(errMsg);
            }

            // Check meta.status even on HTTP 200
            if (!string.IsNullOrWhiteSpace(resp.Content))
            {
                try
                {
                    var revResp = JsonSerializer.Deserialize<ValidateCredentialsResponse>(resp.Content, GetJsonOptions());
                    if (revResp?.Meta != null && !revResp.Meta.IsSuccess)
                    {
                        LogApiFailure(
                            $"{Constants.Api.RevokeOrderPath} {request.RevocationDetails?.OrderNumber}",
                            resp, revResp.Meta.ErrorCode, revResp.Meta.ErrorMessage);
                        throw new Exception(
                            $"CERTInext RevokeOrder returned failure for order " +
                            $"'{request.RevocationDetails?.OrderNumber}': {revResp.Meta.ErrorMessage ?? revResp.Meta.ErrorCode}.");
                    }
                }
                catch (JsonException)
                {
                    // Non-JSON body on 200 is tolerable for revoke
                }
            }

            Logger.LogInformation(
                "Certificate order revoked in CERTInext. OrderNumber={OrderNumber}, RevokeReasonId={ReasonId}",
                request.RevocationDetails?.OrderNumber, request.RevocationDetails?.RevokeReasonId);
            Logger.MethodExit(LogLevel.Trace);
        }

        /// <inheritdoc/>
        public async IAsyncEnumerable<OrderReportEntry> ListOrdersAsync(
            string orderDateFrom = null,
            int pageSize = Constants.Api.DefaultPageSize,
            [EnumeratorCancellation] CancellationToken ct = default)
        {
            Logger.MethodEntry(LogLevel.Trace);

            int page = 1;
            int totalCount = int.MaxValue; // sentinel until we read the first response

            while (true)
            {
                ct.ThrowIfCancellationRequested();

                var body = new GetOrderReportRequest
                {
                    Meta = await BuildMetaAsync(ct),
                    SearchCriteria = new OrderReportSearchCriteria
                    {
                        OrderDateFrom = orderDateFrom,
                        PageNumber = page.ToString(),
                        PageSize = Math.Min(pageSize, Constants.Api.MaxPageSize).ToString()
                    }
                };

                var req = new RestRequest(Constants.Api.GetOrderReportPath, Method.Post);
                req.AddJsonBody(JsonSerializer.Serialize(body, GetJsonOptions()));

                var sw = System.Diagnostics.Stopwatch.StartNew();
                var resp = await ExecuteWithRetryAsync(req, ct);
                sw.Stop();

                Logger.LogInformation(
                    "CERTInext API call: Method=POST, Path={Path}, Page={Page}, HttpStatus={Status}, LatencyMs={Latency}, AuthMode={AuthMode}",
                    Constants.Api.GetOrderReportPath, page, (int)resp.StatusCode, sw.ElapsedMilliseconds, _config.AuthMode);

                if (resp.StatusCode == HttpStatusCode.Unauthorized || resp.StatusCode == HttpStatusCode.Forbidden)
                {
                    Logger.LogError(
                        "ListOrders authentication failure. Page={Page}, HttpStatus={Status}, AuthMode={AuthMode}",
                        page, (int)resp.StatusCode, _config.AuthMode);
                    throw new Exception(
                        $"Authentication failure during order listing (page {page}). " +
                        $"HTTP {(int)resp.StatusCode}. See gateway logs for details.");
                }

                var listResp = DeserializeOrThrow<GetOrderReportResponse>(resp, $"list orders page {page}");

                if (listResp.Meta != null && !listResp.Meta.IsSuccess)
                {
                    // Empty result set is indicated by a failure meta on some API versions
                    Logger.LogInformation(
                        "GetOrderReport returned meta failure on page {Page}. ErrorCode={ErrorCode}",
                        page, listResp.Meta.ErrorCode);
                    break;
                }

                var ordersArray = listResp.OrderDetails?.OrdersArray;
                if (ordersArray == null || ordersArray.Count == 0)
                    break;

                // Use noOfPages from the response envelope to know when to stop
                if (page == 1)
                    totalCount = listResp.OrderDetails?.TotalNoOfResults ?? int.MaxValue;

                Logger.LogDebug("Fetched page {Page}/{TotalPages} with {Count} orders (totalResults={Total}).",
                    page, listResp.OrderDetails?.NoOfPages, ordersArray.Count,
                    totalCount == int.MaxValue ? "unknown" : totalCount.ToString());

                foreach (var entry in ordersArray)
                    yield return entry;

                // Stop when we have reached the last page
                int noOfPages = listResp.OrderDetails?.NoOfPages ?? 1;
                if (page >= noOfPages)
                    break;

                page++;
            }

            Logger.MethodExit(LogLevel.Trace);
        }

        /// <inheritdoc/>
        public async Task<List<ProductDetail>> GetProductDetailsAsync(CancellationToken ct = default)
        {
            Logger.MethodEntry(LogLevel.Trace);

            var body = new GetProductDetailsRequest
            {
                Meta = await BuildMetaAsync(ct),
                // Pass groupNumber when configured — required by some accounts to return
                // products from the nested categories structure (e.g. sandbox accounts).
                ProductDetails = new ProductDetailsFilter
                {
                    GroupNumber = string.IsNullOrWhiteSpace(_config.GroupNumber) ? null : _config.GroupNumber
                }
            };

            var req = new RestRequest(Constants.Api.GetProductDetailsPath, Method.Post);
            req.AddJsonBody(JsonSerializer.Serialize(body, GetJsonOptions()));

            var sw = System.Diagnostics.Stopwatch.StartNew();
            var resp = await ExecuteWithRetryAsync(req, ct);
            sw.Stop();

            Logger.LogInformation(
                "CERTInext API call: Method=POST, Path={Path}, HttpStatus={Status}, LatencyMs={Latency}, AuthMode={AuthMode}",
                Constants.Api.GetProductDetailsPath, (int)resp.StatusCode, sw.ElapsedMilliseconds, _config.AuthMode);

            if (resp.StatusCode == HttpStatusCode.Unauthorized || resp.StatusCode == HttpStatusCode.Forbidden)
            {
                Logger.LogError(
                    "GetProductDetails API authentication failure. HttpStatus={Status}, AuthMode={AuthMode}",
                    (int)resp.StatusCode, _config.AuthMode);
                throw new Exception(
                    $"Authentication failure retrieving product details. HTTP {(int)resp.StatusCode}. See gateway logs for details.");
            }

            var result = DeserializeOrThrow<GetProductDetailsResponse>(resp, "get product details");

            // The API returns a nested structure: productDetails[].products[].productCode
            // FlattenProducts() extracts all products from all category envelopes.
            var products = result.FlattenProducts();
            Logger.LogInformation("Retrieved {Count} product codes from CERTInext.",
                products.Count);
            Logger.MethodExit(LogLevel.Trace);
            return products;
        }

        // ---------------------------------------------------------------------------
        // ICERTInextClient — legacy wrapper methods
        // ---------------------------------------------------------------------------

        /// <inheritdoc/>
        public async Task<EnrollCertificateResponse> EnrollCertificateAsync(
            EnrollCertificateRequest request,
            CancellationToken ct = default)
        {
            Logger.MethodEntry(LogLevel.Trace);
            Logger.LogInformation("Submitting enrollment request to CERTInext (legacy) for profile {ProfileId}", request.ProfileId);

            // Build a GenerateOrderSSL request from the legacy EnrollCertificateRequest
            var orderReq = BuildOrderRequestFromLegacyEnrollRequest(request);
            var orderResp = await PlaceOrderAsync(orderReq, ct);

            string orderNumber = orderResp.OrderDetails?.OrderNumber;
            if (string.IsNullOrWhiteSpace(orderNumber))
                throw new Exception("CERTInext order placement succeeded but returned no orderNumber.");

            // If the CSR was provided in the legacy request, submit it now if not already included in the order
            // (The real API accepts CSR inline in GenerateOrderSSL; the legacy flow may not have set it)

            // Poll TrackOrder to get the current status
            var trackResp = await TrackOrderAsync(orderNumber, ct);
            string certStatusId = trackResp.OrderDetails?.CertificateStatusId ?? "1";

            // Try to download the certificate if the order is fulfilled
            string pemCert = null;
            string serialNumber = null;
            if (IsCertificateDownloadable(certStatusId))
            {
                try
                {
                    var certResp = await DownloadCertificateAsync(orderNumber, ct);
                    pemCert = certResp.CertificateDetails?.EndEntityCertificate;
                    serialNumber = certResp.CertificateDetails?.CertificateSerialNumber;
                }
                catch (Exception ex)
                {
                    Logger.LogWarning(ex, "Certificate download after order placement failed for order {OrderNumber}. " +
                        "Certificate will be retrieved during next synchronization.", orderNumber);
                }
            }

            int disposition = StatusMapper.CertificateStatusIdToRequestDisposition(certStatusId);

            var legacyResp = new EnrollCertificateResponse
            {
                Id = orderNumber,
                Status = MapCertStatusIdToLegacyString(certStatusId),
                Certificate = pemCert,
                SerialNumber = serialNumber,
                ProfileId = request.ProfileId,
                Message = trackResp.OrderDetails?.CertificateStatus
            };

            Logger.LogInformation(
                "CERTInext enrollment submitted (legacy). OrderNumber={OrderNumber}, CertificateStatusId={StatusId}",
                orderNumber, certStatusId);
            Logger.MethodExit(LogLevel.Trace);
            return legacyResp;
        }

        /// <inheritdoc/>
        public async Task<EnrollCertificateResponse> RenewCertificateAsync(
            string certificateId,
            RenewCertificateRequest request,
            CancellationToken ct = default)
        {
            Logger.MethodEntry(LogLevel.Trace);
            Logger.LogInformation("Submitting renewal request to CERTInext (legacy). PriorOrderNumber={CertId}", certificateId);

            // The real CERTInext API has no dedicated renew endpoint.
            // Retrieve the prior order's product code and domain from TrackOrder,
            // then place a new GenerateOrderSSL order.
            TrackOrderResponse priorTrack;
            try
            {
                priorTrack = await TrackOrderAsync(certificateId, ct);
            }
            catch (KeyNotFoundException)
            {
                throw new KeyNotFoundException($"Cannot renew: prior order '{certificateId}' was not found in CERTInext.");
            }

            // We don't have the product code from TrackOrder — build an order using
            // the config defaults and the CSR from the renewal request.
            var orderReq = new GenerateOrderSslRequest
            {
                Meta = await BuildMetaAsync(ct),
                OrderDetails = new SslOrderDetails
                {
                    ProductCode = _config.DefaultProductCode ?? string.Empty,
                    SaveAndHold = "0",
                    RequestorInformation = new RequestorInformation
                    {
                        RequestorName = request.RequesterName ?? _config.RequestorName,
                        RequestorEmail = request.RequesterEmail ?? _config.RequestorEmail,
                        RequestorIsdCode = _config.RequestorIsdCode ?? "1",
                        RequestorMobileNumber = _config.RequestorMobileNumber ?? string.Empty
                    },
                    SubscriptionDetails = new SubscriptionDetails { Validity = "1" },
                    CertificateInformation = new CertificateInformation
                    {
                        DomainName = priorTrack.OrderDetails?.RequestorInformation?.RequestorName ?? "unknown"
                    },
                    Csr = request.Csr,
                    AgreementDetails = BuildDefaultAgreementDetails()
                }
            };

            var orderResp = await PlaceOrderAsync(orderReq, ct);
            string newOrderNumber = orderResp.OrderDetails?.OrderNumber;

            if (string.IsNullOrWhiteSpace(newOrderNumber))
                throw new Exception("CERTInext renewal order placement succeeded but returned no orderNumber.");

            var trackResp = await TrackOrderAsync(newOrderNumber, ct);
            string certStatusId = trackResp.OrderDetails?.CertificateStatusId ?? "1";

            string pemCert = null;
            string serialNumber = null;
            if (IsCertificateDownloadable(certStatusId))
            {
                try
                {
                    var certResp = await DownloadCertificateAsync(newOrderNumber, ct);
                    pemCert = certResp.CertificateDetails?.EndEntityCertificate;
                    serialNumber = certResp.CertificateDetails?.CertificateSerialNumber;
                }
                catch (Exception ex)
                {
                    Logger.LogWarning(ex, "Certificate download failed for renewed order {OrderNumber}.", newOrderNumber);
                }
            }

            var legacyResp = new EnrollCertificateResponse
            {
                Id = newOrderNumber,
                Status = MapCertStatusIdToLegacyString(certStatusId),
                Certificate = pemCert,
                SerialNumber = serialNumber,
                Message = trackResp.OrderDetails?.CertificateStatus
            };

            Logger.LogInformation(
                "CERTInext renewal submitted (legacy). PriorOrderNumber={PriorId}, NewOrderNumber={NewId}",
                certificateId, newOrderNumber);
            Logger.MethodExit(LogLevel.Trace);
            return legacyResp;
        }

        /// <inheritdoc/>
        public async Task<LegacyGetCertificateResponse> GetCertificateAsync(
            string certificateId,
            CancellationToken ct = default)
        {
            Logger.MethodEntry(LogLevel.Trace);

            // 1. Track order for status and metadata
            TrackOrderResponse trackResp;
            try
            {
                trackResp = await TrackOrderAsync(certificateId, ct);
            }
            catch (KeyNotFoundException)
            {
                Logger.LogWarning("CERTInext order not found. OrderNumber={OrderNumber}", certificateId);
                throw new KeyNotFoundException($"Order '{certificateId}' was not found in CERTInext.");
            }

            string certStatusId = trackResp.OrderDetails?.CertificateStatusId ?? "1";
            string pemCert = null;
            string serialNumber = null;

            // 2. Download certificate if it is available
            if (IsCertificateDownloadable(certStatusId))
            {
                try
                {
                    var certResp = await DownloadCertificateAsync(certificateId, ct);
                    pemCert = certResp.CertificateDetails?.EndEntityCertificate;
                    serialNumber = certResp.CertificateDetails?.CertificateSerialNumber;
                }
                catch (Exception ex)
                {
                    Logger.LogWarning(ex, "Certificate download failed for order {OrderNumber}.", certificateId);
                }
            }

            // 3. Map to legacy type
            var revDetails = trackResp.OrderDetails?.RevocationDetails;
            int? revokeReasonInt = null;
            if (revDetails != null && int.TryParse(revDetails.RevokeReasonId, out int rid))
                revokeReasonInt = rid;

            var result = new LegacyGetCertificateResponse
            {
                Id = certificateId,
                Status = MapCertStatusIdToLegacyString(certStatusId),
                Certificate = pemCert,
                SerialNumber = serialNumber,
                RequesterName = trackResp.OrderDetails?.RequestorInformation?.RequestorName,
                RequesterEmail = trackResp.OrderDetails?.RequestorInformation?.RequestorEmail,
                RevocationReason = revokeReasonInt.HasValue
                    ? StatusMapper.ToRevocationReason((uint)StatusMapper.RevokeReasonIdToCrlCode(revokeReasonInt.Value))
                    : null
            };

            if (!string.IsNullOrWhiteSpace(revDetails?.RevokeProcessedDate) &&
                DateTime.TryParse(revDetails.RevokeProcessedDate, out DateTime revokedAt))
            {
                result.RevokedAt = revokedAt;
            }

            Logger.MethodExit(LogLevel.Trace);
            return result;
        }

        /// <inheritdoc/>
        public async Task RevokeCertificateAsync(
            string certificateId,
            RevokeCertificateRequest request,
            CancellationToken ct = default)
        {
            Logger.MethodEntry(LogLevel.Trace);

            // Map the legacy reason string to a CERTInext revokeReasonId
            uint crlCode = MapLegacyReasonStringToCrlCode(request.Reason);
            string revokeReasonId = StatusMapper.ToRevocationReasonId(crlCode);

            var revokeReq = new RevokeOrderRequest
            {
                Meta = await BuildMetaAsync(ct),
                RevocationDetails = new RevocationDetails
                {
                    OrderNumber = certificateId,
                    RequestorEmail = _config.RequestorEmail,
                    RevokeReasonId = revokeReasonId,
                    RevokeRemarks = request.Comment ?? $"Revoked via Keyfactor Command. Reason: {request.Reason}."
                }
            };

            await RevokeOrderAsync(revokeReq, ct);
            Logger.MethodExit(LogLevel.Trace);
        }

        /// <inheritdoc/>
        public async IAsyncEnumerable<LegacyGetCertificateResponse> ListCertificatesAsync(
            DateTime? issuedAfter = null,
            int pageSize = Constants.Api.DefaultPageSize,
            [EnumeratorCancellation] CancellationToken ct = default)
        {
            // Map the issuedAfter DateTime to an orderDateFrom string if provided
            string orderDateFrom = issuedAfter.HasValue
                ? issuedAfter.Value.ToUniversalTime().ToString("yyyy-MM-dd")
                : null;

            await foreach (var entry in ListOrdersAsync(orderDateFrom, pageSize, ct))
            {
                yield return MapOrderReportEntryToLegacy(entry);
            }
        }

        /// <inheritdoc/>
        public async Task<List<ProfileInfo>> GetProfilesAsync(CancellationToken ct = default)
        {
            Logger.MethodEntry(LogLevel.Trace);

            var products = await GetProductDetailsAsync(ct);
            var profiles = new List<ProfileInfo>();

            foreach (var p in products)
            {
                profiles.Add(new ProfileInfo
                {
                    Id = p.ProductCode,
                    Name = p.ProductName,
                    Description = p.ProductType,
                    Active = p.Active,
                    DefaultValidityDays = 365
                });
            }

            Logger.LogInformation("Retrieved {Count} profiles from CERTInext.", profiles.Count);
            Logger.MethodExit(LogLevel.Trace);
            return profiles;
        }

        // ---------------------------------------------------------------------------
        // ICERTInextClient — DCV methods
        // ---------------------------------------------------------------------------

        /// <inheritdoc/>
        public async Task<GetDcvResponse> GetDcvAsync(
            string orderNumber,
            string domainName,
            string dcvMethod,
            CancellationToken ct = default)
        {
            Logger.MethodEntry(LogLevel.Trace);

            var body = new GetDcvRequest
            {
                Meta = await BuildMetaAsync(ct),
                DcvDetails = new DcvRequestDetails
                {
                    RequestorEmail = _config.RequestorEmail,
                    OrderNumber = orderNumber,
                    DomainName = domainName,
                    DcvMethod = dcvMethod
                }
            };

            var req = new RestRequest(Constants.Api.GetDcvPath, Method.Post);
            req.AddJsonBody(JsonSerializer.Serialize(body, GetJsonOptions()));

            var sw = System.Diagnostics.Stopwatch.StartNew();
            var resp = await ExecuteWithRetryAsync(req, ct);
            sw.Stop();

            Logger.LogInformation(
                "CERTInext API call: Method=POST, Path={Path}, OrderNumber={OrderNumber}, Domain={Domain}, HttpStatus={Status}, LatencyMs={Latency}",
                Constants.Api.GetDcvPath, orderNumber, domainName, (int)resp.StatusCode, sw.ElapsedMilliseconds);

            if (resp.StatusCode == HttpStatusCode.Unauthorized || resp.StatusCode == HttpStatusCode.Forbidden)
            {
                Logger.LogError(
                    "GetDcv API authentication failure. OrderNumber={OrderNumber}, Domain={Domain}, HttpStatus={Status}",
                    orderNumber, domainName, (int)resp.StatusCode);
                throw new Exception(
                    $"Authentication failure calling GetDcv for order '{orderNumber}' domain '{domainName}'. HTTP {(int)resp.StatusCode}. See gateway logs for details.");
            }

            var result = DeserializeOrThrow<GetDcvResponse>(resp, $"get DCV token {orderNumber}/{domainName}");

            if (result.Meta != null && !result.Meta.IsSuccess)
            {
                LogApiFailure(
                    $"{Constants.Api.GetDcvPath} {orderNumber}/{domainName}",
                    resp, result.Meta.ErrorCode, result.Meta.ErrorMessage);
                throw new Exception(
                    $"CERTInext GetDcv failed for order '{orderNumber}' domain '{domainName}': {result.Meta.ErrorMessage ?? result.Meta.ErrorCode}.");
            }

            // SOX CC7.3: log token presence (never value) so each DCV step is independently
            // auditable — an auditor must be able to confirm the token was obtained before
            // StageValidation was called.
            Logger.LogInformation(
                "GetDcv response received. OrderNumber={OrderNumber}, Domain={Domain}, TokenPresent={TokenPresent}",
                orderNumber, domainName, !string.IsNullOrWhiteSpace(result.DcvDetails?.Token));

            Logger.MethodExit(LogLevel.Trace);
            return result;
        }

        /// <inheritdoc/>
        public async Task VerifyDcvAsync(
            string orderNumber,
            string domainName,
            string dcvMethod,
            CancellationToken ct = default)
        {
            Logger.MethodEntry(LogLevel.Trace);

            var body = new VerifyDcvRequest
            {
                Meta = await BuildMetaAsync(ct),
                DcvDetails = new DcvRequestDetails
                {
                    RequestorEmail = _config.RequestorEmail,
                    OrderNumber = orderNumber,
                    DomainName = domainName,
                    DcvMethod = dcvMethod
                }
            };

            var req = new RestRequest(Constants.Api.VerifyDcvPath, Method.Post);
            req.AddJsonBody(JsonSerializer.Serialize(body, GetJsonOptions()));

            var sw = System.Diagnostics.Stopwatch.StartNew();
            var resp = await ExecuteWithRetryAsync(req, ct);
            sw.Stop();

            Logger.LogInformation(
                "CERTInext API call: Method=POST, Path={Path}, OrderNumber={OrderNumber}, Domain={Domain}, HttpStatus={Status}, LatencyMs={Latency}",
                Constants.Api.VerifyDcvPath, orderNumber, domainName, (int)resp.StatusCode, sw.ElapsedMilliseconds);

            if (resp.StatusCode == HttpStatusCode.Unauthorized || resp.StatusCode == HttpStatusCode.Forbidden)
            {
                Logger.LogError(
                    "VerifyDcv API authentication failure. OrderNumber={OrderNumber}, Domain={Domain}, HttpStatus={Status}",
                    orderNumber, domainName, (int)resp.StatusCode);
                throw new Exception(
                    $"Authentication failure calling VerifyDcv for order '{orderNumber}' domain '{domainName}'. HTTP {(int)resp.StatusCode}. See gateway logs for details.");
            }

            if (!resp.IsSuccessful)
                throw new Exception(
                    $"CERTInext VerifyDcv failed for order '{orderNumber}' domain '{domainName}'. HTTP {(int)resp.StatusCode}. See gateway logs for details.");

            // Attempt to read meta.status from the response body
            if (!string.IsNullOrWhiteSpace(resp.Content))
            {
                try
                {
                    var verifyResp = JsonSerializer.Deserialize<VerifyDcvResponse>(resp.Content, GetJsonOptions());
                    if (verifyResp?.Meta != null && !verifyResp.Meta.IsSuccess)
                    {
                        // SOX CC7.3 + issue #8: log the failure with the raw body so an
                        // auditor / operator can see exactly what CERTInext returned.
                        LogApiFailure(
                            $"{Constants.Api.VerifyDcvPath} {orderNumber}/{domainName}",
                            resp, verifyResp.Meta.ErrorCode, verifyResp.Meta.ErrorMessage);
                        throw new Exception(
                            $"CERTInext VerifyDcv returned failure for order '{orderNumber}' domain '{domainName}': {verifyResp.Meta.ErrorMessage ?? verifyResp.Meta.ErrorCode}.");
                    }
                }
                catch (JsonException) { /* non-JSON 200 body is acceptable */ }
            }

            // SOX CC7.3 / SOC2 CC7.3: log success only after the meta check so the log entry
            // unambiguously reflects that CERTInext acknowledged the verification request.
            Logger.LogInformation(
                "DCV verification succeeded. OrderNumber={OrderNumber}, Domain={Domain}", orderNumber, domainName);
            Logger.MethodExit(LogLevel.Trace);
        }

        // ---------------------------------------------------------------------------
        // Auth helpers
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Builds the meta authentication block for a CERTInext API request.
        /// For AccessKey auth: authKey = SHA256(accessKey + ts + txn) (hex, lowercase).
        /// For OAuth auth: the bearer token is injected as an HTTP header automatically by
        /// <see cref="CERTInextOAuthAuthenticator"/> — authKey is left empty in the meta block
        /// (the server accepts the bearer token in lieu of authKey).  The meta block is still
        /// required for ver/ts/txn/accountNumber in both auth modes.
        /// </summary>
        private Task<RequestMeta> BuildMetaAsync(CancellationToken ct)
        {
            string ts = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:sszzz");
            string txn = GenerateTxnId();

            string authKey;
            if (_config.AuthMode.Equals(Constants.Config.AuthModeOAuth, StringComparison.OrdinalIgnoreCase) ||
                _config.AuthMode.Equals(Constants.Config.AuthModeOAuth2, StringComparison.OrdinalIgnoreCase))
            {
                // OAuth: bearer token is injected by CERTInextOAuthAuthenticator per-request.
                // Leave authKey empty in the meta block — the API accepts the bearer token
                // in the Authorization header instead.
                authKey = string.Empty;
            }
            else
            {
                // AccessKey: compute SHA256(accessKey + ts + txn)
                authKey = ComputeAuthKey(_config.ApiKey, ts, txn);
            }

            // SOC2 CC7.2: log credential use at Debug only — this is called on every outbound
            // request, so Information would flood the log and degrade anomaly detection signal.
            // Per-operation audit entries (LogInformation) are emitted at the call sites above.
            Logger.LogDebug(
                "Outbound API request authenticated. AuthMode={AuthMode}, AccountNumber={AccountNumber}, " +
                "ApiKeyPresent={Present}",
                _config.AuthMode, _config.AccountNumber, !string.IsNullOrEmpty(_config.ApiKey));

            return Task.FromResult(new RequestMeta
            {
                Ver = Constants.Api.MetaVersion,
                Ts = ts,
                Txn = txn,
                AccountNumber = _config.AccountNumber,
                AuthKey = authKey
            });
        }

        /// <summary>
        /// Computes the CERTInext authKey: SHA256(accessKey + ts + txn) as lowercase hex.
        ///
        /// Implemented with BouncyCastle (per the project's crypto policy: all hashing and
        /// key handling goes through BouncyCastle, never BCL System.Security.Cryptography).
        /// </summary>
        private static string ComputeAuthKey(string accessKey, string ts, string txn)
        {
            string input = accessKey + ts + txn;
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            var digest = new Org.BouncyCastle.Crypto.Digests.Sha256Digest();
            digest.BlockUpdate(inputBytes, 0, inputBytes.Length);
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        /// <summary>
        /// Generates a unique transaction ID (decimal, up to 18 digits).
        ///
        /// `txn` is part of the SHA-256 input for the CERTInext authKey
        /// (<c>SHA256(accessKey + ts + txn)</c>).  A predictable txn shrinks the search
        /// space against a leaked accessKey, so we use a cryptographically-strong source
        /// rather than <see cref="Random.Shared"/> — per the project's BouncyCastle-only
        /// crypto policy, that source is <c>Org.BouncyCastle.Security.SecureRandom</c>.
        /// </summary>
        private static readonly Org.BouncyCastle.Security.SecureRandom _txnRandom =
            new Org.BouncyCastle.Security.SecureRandom();

        private static string GenerateTxnId()
        {
            // Produce a positive long in [1, 1e18). NextLong() returns the full Int64
            // range including negatives — mask off the sign bit and reduce.
            long val = (_txnRandom.NextLong() & long.MaxValue) % 1_000_000_000_000_000_000L + 1L;
            return val.ToString();
        }

        /// <summary>
        /// Returns a valid OAuth2 access token, refreshing it if expired. Thread-safe.
        /// </summary>
        private async Task<string> GetOrRefreshTokenAsync(CancellationToken ct)
        {
            if (!string.IsNullOrEmpty(_cachedToken) && DateTime.UtcNow < _tokenExpiry)
                return _cachedToken;

            await _tokenLock.WaitAsync(ct);
            try
            {
                if (!string.IsNullOrEmpty(_cachedToken) && DateTime.UtcNow < _tokenExpiry)
                    return _cachedToken;

                Logger.LogInformation(
                    "OAuth2 token acquisition attempt started. TokenUrl={TokenUrl}, ClientId={ClientId}",
                    _config.OAuthTokenUrl, _config.OAuthClientId);

                using var tokenClient = new RestClient(_config.OAuthTokenUrl);
                var tokenReq = new RestRequest(string.Empty, Method.Post);
                tokenReq.AddHeader("Content-Type", "application/x-www-form-urlencoded");
                tokenReq.AddParameter("grant_type", "client_credentials");
                tokenReq.AddParameter("client_id", _config.OAuthClientId);
                tokenReq.AddParameter("client_secret", _config.OAuthClientSecret);

                var tokenResp = await tokenClient.ExecuteAsync(tokenReq, ct);
                if (!tokenResp.IsSuccessful || string.IsNullOrWhiteSpace(tokenResp.Content))
                {
                    // SOX CC6.1 (credential confidentiality): NEVER log tokenResp.Content,
                    // tokenResp.ErrorMessage, or tokenResp.ErrorException — RestSharp's
                    // failure paths can echo the original request including the
                    // `client_secret` form value.  Only StatusCode + non-secret config
                    // identifiers are safe to log here.
                    Logger.LogError(
                        "OAuth2 token acquisition failed. TokenUrl={TokenUrl}, ClientId={ClientId}, HttpStatus={Status}",
                        _config.OAuthTokenUrl, _config.OAuthClientId, (int)tokenResp.StatusCode);
                    throw new Exception(
                        $"Failed to obtain OAuth2 token from CERTInext. HTTP {(int)tokenResp.StatusCode}. See gateway logs for details.");
                }

                var tokenPayload = JsonSerializer.Deserialize<OAuth2TokenResponse>(tokenResp.Content, GetJsonOptions());

                if (tokenPayload == null || string.IsNullOrEmpty(tokenPayload.AccessToken))
                {
                    Logger.LogError(
                        "OAuth2 token acquisition failed — response did not contain access_token. TokenUrl={TokenUrl}",
                        _config.OAuthTokenUrl);
                    throw new Exception("OAuth2 token response from CERTInext did not contain an access_token.");
                }

                _cachedToken = tokenPayload.AccessToken;
                _tokenExpiry = DateTime.UtcNow.AddSeconds(Math.Max(tokenPayload.ExpiresIn - 60, 30));

                Logger.LogInformation(
                    "OAuth2 token acquired. TokenUrl={TokenUrl}, ClientId={ClientId}, ExpiresAt={Expiry:u}",
                    _config.OAuthTokenUrl, _config.OAuthClientId, _tokenExpiry);
                return _cachedToken;
            }
            finally
            {
                _tokenLock.Release();
            }
        }

        // ---------------------------------------------------------------------------
        // Retry helper
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Executes a <see cref="RestRequest"/> with up to <paramref name="maxAttempts"/>
        /// attempts, retrying on HTTP 5xx and network-level failures (no status code).
        /// 4xx responses are returned immediately — client errors will not be resolved
        /// by retrying.
        /// </summary>
        private async Task<RestResponse> ExecuteWithRetryAsync(
            RestRequest req,
            CancellationToken ct,
            int maxAttempts = 3)
        {
            RestResponse resp = null;
            for (int attempt = 1; attempt <= maxAttempts; attempt++)
            {
                resp = await _http.ExecuteAsync(req, ct);

                // Success or 4xx client error — return immediately
                bool isClientError = (int)resp.StatusCode >= 400 && (int)resp.StatusCode < 500;
                if (resp.IsSuccessful || isClientError)
                    return resp;

                if (attempt < maxAttempts)
                {
                    Logger.LogWarning(
                        "CERTInext API returned {Status} on attempt {Attempt}/{Max} — retrying...",
                        (int)resp.StatusCode, attempt, maxAttempts);
                }
            }

            // Return the last response (caller handles the error)
            return resp;
        }

        // ---------------------------------------------------------------------------
        // Legacy helper — maps legacy reason string to CRL code
        // ---------------------------------------------------------------------------

        private static uint MapLegacyReasonStringToCrlCode(string reason)
        {
            switch (reason?.ToLowerInvariant())
            {
                case "keycompromise": return 1;
                case "cacompromise": return 2;
                case "affiliationchanged": return 3;
                case "superseded": return 4;
                case "cessationofoperation": return 5;
                case "certificatehold": return 6;
                case "removefromcrl": return 8;
                case "privilegewithdrawn": return 9;
                case "aacompromise": return 10;
                default: return 0; // unspecified -> maps to KeyCompromise in ToRevocationReasonId
            }
        }

        private static bool IsCertificateDownloadable(string certStatusId)
        {
            if (!int.TryParse(certStatusId, out int id)) return false;
            return id == Constants.CertificateStatusId.CertificateGenerated ||
                   id == Constants.CertificateStatusId.CertificateDownloaded ||
                   id == Constants.CertificateStatusId.OrderAutoApproved ||
                   id == Constants.CertificateStatusId.RekeyApproved ||
                   id == Constants.CertificateStatusId.ApprovedBySecondApprover;
        }

        private static string MapCertStatusIdToLegacyString(string certStatusId)
        {
            if (!int.TryParse(certStatusId, out int id)) return "pending";
            int disposition = StatusMapper.CertificateStatusIdToRequestDisposition(id);
            switch (disposition)
            {
                case (int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.GENERATED: return "issued";
                case (int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.REVOKED: return "revoked";
                case (int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.EXTERNALVALIDATION: return "pending_approval";
                case (int)Keyfactor.PKI.Enums.EJBCA.EndEntityStatus.FAILED: return "failed";
                default: return "pending";
            }
        }

        private static LegacyGetCertificateResponse MapOrderReportEntryToLegacy(OrderReportEntry entry)
        {
            // Note: GetOrderReport does not return requestor name/email in the ordersArray.
            // Those fields are only available via TrackOrder on individual orders.
            System.DateTime? orderDate = null;
            if (!string.IsNullOrWhiteSpace(entry.OrderDate)
                && System.DateTime.TryParse(entry.OrderDate,
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
                    out var parsed))
            {
                orderDate = parsed;
            }

            return new LegacyGetCertificateResponse
            {
                Id = string.IsNullOrWhiteSpace(entry.OrderNumber) ? entry.RequestNumber : entry.OrderNumber,
                Status = MapCertStatusIdToLegacyString(entry.CertificateStatusId),
                Subject = entry.DomainName,
                ProfileId = entry.ProductCode,
                OrderDate = orderDate
            };
        }

        private GenerateOrderSslRequest BuildOrderRequestFromLegacyEnrollRequest(EnrollCertificateRequest request)
        {
            // Map ValidityDays → CERTInext's year-based validity. Default 1.
            string validityYears = request.ValidityDays.HasValue
                ? Math.Ceiling(request.ValidityDays.Value / 365.0).ToString("0")
                : (string.IsNullOrWhiteSpace(_config.SubscriptionValidityYears)
                    ? "1"
                    : _config.SubscriptionValidityYears);

            string requestorName  = request.RequesterName  ?? _config.RequestorName  ?? "Keyfactor Gateway";
            string requestorEmail = request.RequesterEmail ?? _config.RequestorEmail ?? string.Empty;
            string requestorIsd   = string.IsNullOrWhiteSpace(_config.RequestorIsdCode) ? "1" : _config.RequestorIsdCode;
            string requestorMobile = _config.RequestorMobileNumber ?? string.Empty;

            return new GenerateOrderSslRequest
            {
                // Meta will be set by PlaceOrderAsync
                OrderDetails = new SslOrderDetails
                {
                    ProductCode = request.ProfileId ?? _config.DefaultProductCode ?? string.Empty,
                    AccountingModel = string.IsNullOrWhiteSpace(_config.AccountingModel) ? "2" : _config.AccountingModel,
                    SaveAndHold = "0",
                    EmailNotifications = string.IsNullOrWhiteSpace(_config.EmailNotifications) ? "0" : _config.EmailNotifications,

                    // delegationInformation — routes the order to the configured account group.
                    // Omitted entirely when GroupNumber is blank (the model JsonIgnore-WhenNull
                    // handles property absence further down).
                    DelegationInformation = !string.IsNullOrWhiteSpace(_config.GroupNumber)
                        ? new DelegationInformation { GroupNumber = _config.GroupNumber }
                        : null,

                    // organizationDetails — declares pre-vetted org when configured. This is the
                    // single biggest factor in how quickly CERTInext releases an order from
                    // Pending System RA. When OrganizationNumber is blank we omit the whole
                    // block (the model is JsonIgnore-WhenNull) so the order falls back to the
                    // unvetted path — same behavior as the prior plugin builds.
                    OrganizationDetails = !string.IsNullOrWhiteSpace(_config.OrganizationNumber)
                        ? new OrganizationDetails
                        {
                            PreVetting = "1",
                            OrganizationNumber = _config.OrganizationNumber
                        }
                        : null,

                    RequestorInformation = new RequestorInformation
                    {
                        RequestorName = requestorName,
                        RequestorEmail = requestorEmail,
                        RequestorIsdCode = requestorIsd,
                        RequestorMobileNumber = requestorMobile
                    },
                    SubscriptionDetails = new SubscriptionDetails
                    {
                        Validity = validityYears,
                        AutoRenew = string.IsNullOrWhiteSpace(_config.SubscriptionAutoRenew) ? "0" : _config.SubscriptionAutoRenew,
                        RenewCriteria = string.IsNullOrWhiteSpace(_config.SubscriptionRenewCriteriaDays) ? "30" : _config.SubscriptionRenewCriteriaDays
                    },
                    CertificateInformation = new CertificateInformation
                    {
                        DomainName = ExtractCnFromSubject(request.Subject) ?? "unknown",
                        AdditionalDomains = BuildAdditionalDomains(request.Sans),
                        AutoSecureWww = string.IsNullOrWhiteSpace(_config.AutoSecureWww) ? "0" : _config.AutoSecureWww
                    },

                    // technicalPointOfContact — each field falls back to the requestor default
                    // when its TechnicalContact* counterpart is blank.
                    TechnicalPointOfContact = new TechnicalPointOfContact
                    {
                        TpcName = string.IsNullOrWhiteSpace(_config.TechnicalContactName) ? requestorName : _config.TechnicalContactName,
                        TpcEmail = string.IsNullOrWhiteSpace(_config.TechnicalContactEmail) ? requestorEmail : _config.TechnicalContactEmail,
                        TpcIsdCode = string.IsNullOrWhiteSpace(_config.TechnicalContactIsdCode) ? requestorIsd : _config.TechnicalContactIsdCode,
                        TpcMobileNumber = string.IsNullOrWhiteSpace(_config.TechnicalContactMobileNumber) ? requestorMobile : _config.TechnicalContactMobileNumber
                    },

                    Csr = request.Csr,
                    AgreementDetails = BuildDefaultAgreementDetails(),
                    AdditionalInformation = new AdditionalInformation
                    {
                        Remarks = request.Comment ?? "Issued via Keyfactor Command AnyCA REST Gateway."
                    }
                }
            };
        }

        private AgreementDetails BuildDefaultAgreementDetails()
        {
            // SOC1 accuracy-of-processing: the subscriber agreement is a legal artefact
            // and the SignerIp it carries is part of the audit record CERTInext stores.
            // Submitting 127.0.0.1 is a misrepresentation. We retain the fallback so we
            // don't break existing deployments (and our enrollment never fails just
            // because SignerIp is blank), but a missing value emits a Warning so an
            // auditor sees the misrepresentation as an actionable signal in the gateway log.
            string signerIp = _config.SignerIp;
            if (string.IsNullOrWhiteSpace(signerIp))
            {
                Logger.LogWarning(
                    "Connector config SignerIp is empty — falling back to 127.0.0.1 for the " +
                    "subscriber agreement. Set the SignerIp config field to the gateway host's " +
                    "actual public-routable IP so the audit record is accurate.");
                signerIp = "127.0.0.1";
            }
            return new AgreementDetails
            {
                AcceptAgreement = "1",
                SignerName = _config.RequestorName ?? "Keyfactor Gateway",
                SignerPlace = _config.SignerPlace ?? "Gateway",
                SignerIp = signerIp
            };
        }

        private static string ExtractCnFromSubject(string subject)
        {
            if (string.IsNullOrWhiteSpace(subject)) return null;
            foreach (var part in subject.Split(','))
            {
                string trimmed = part.Trim();
                if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                    return trimmed.Substring(3);
            }
            return null;
        }

        private static List<string> BuildAdditionalDomains(System.Collections.Generic.List<SanEntry> sans)
        {
            if (sans == null || sans.Count == 0) return null;
            var domains = new List<string>();
            foreach (var san in sans)
            {
                if (string.Equals(san.Type, "dns", StringComparison.OrdinalIgnoreCase) &&
                    !string.IsNullOrWhiteSpace(san.Value))
                    domains.Add(san.Value);
            }
            return domains.Count > 0 ? domains : null;
        }

        // ---------------------------------------------------------------------------
        // Deserialization helpers
        // ---------------------------------------------------------------------------

        private static T DeserializeOrThrow<T>(RestResponse resp, string operation) where T : class
        {
            if (!resp.IsSuccessful)
            {
                string errMsg = ExtractErrorMessage(resp.Content, operation);
                Logger.LogError(
                    "CERTInext API error during '{Operation}': HttpStatus={Status}, Error={Error}",
                    operation, (int)resp.StatusCode, errMsg);
                throw new Exception(errMsg);
            }

            if (string.IsNullOrWhiteSpace(resp.Content))
                throw new Exception($"CERTInext returned an empty body for operation '{operation}'.");

            T result;
            try
            {
                result = JsonSerializer.Deserialize<T>(resp.Content, GetJsonOptions());
            }
            catch (JsonException jex)
            {
                throw new Exception(
                    $"Failed to deserialize CERTInext response for operation '{operation}'. " +
                    $"Content length: {resp.Content?.Length}. Error: {jex.Message}", jex);
            }

            if (result == null)
                throw new Exception($"Deserialized a null result for operation '{operation}'.");

            return result;
        }

        // SOC2 CC7.2 DoS guard: cap the size of any response body we parse here. CERTInext
        // error envelopes are always under a few KB; a multi-MB body is either a misrouted
        // response or a hostile payload aimed at exhausting our JsonDocument buffer.
        private const int MaxErrorBodyBytes = 64 * 1024;

        // ---------------------------------------------------------------------------
        // Rate-limit retry — see GitHub issue #8.
        //
        // The CERTInext sandbox returns the generic string "Inactive Account User." for
        // several distinct conditions including burst-rate-limit rejection. Empirically
        // this resolves within seconds — auto-retrying lets a transient burst limit hit
        // transparently while still surfacing the original exception text for genuinely
        // inactive accounts (after RateLimitMaxAttempts the throw is unchanged).
        // ---------------------------------------------------------------------------

        private const int RateLimitMaxAttempts = 5;
        private const double RateLimitBaseBackoffSeconds = 1.0;

        /// <summary>
        /// True when <paramref name="errorMessage"/> matches the documented rate-limit
        /// surface CERTInext uses on its sandbox. Substring + case-insensitive match;
        /// the trailing punctuation/whitespace varies across observed payloads.
        ///
        /// <para>
        /// <b>Contract:</b> callers MUST only invoke this inside the
        /// <c>!result.Meta.IsSuccess</c> branch of an API response.  CERTInext's
        /// successful responses are not currently observed to include this phrase,
        /// but the predicate is intentionally permissive to handle CA-side wording
        /// drift, and we want the safety net of the surrounding failure context.
        /// </para>
        ///
        /// <para>
        /// <b>Known cost:</b> a genuinely-inactive account (admin disabled, billing
        /// hold) returns the same error string as a rate-limit hit.  Today there is
        /// no distinguishing <c>errorCode</c> field in the observed payloads, so
        /// callers gated by this predicate will exhaust their full retry budget
        /// (5 attempts × ~31 s total wait) before propagating the original failure
        /// to the gateway.  Quota cost: up to 5 enrollment attempts per affected
        /// call.  See GitHub issue #8 for the discussion.
        /// </para>
        /// </summary>
        internal static bool IsRateLimitSurface(string errorMessage)
        {
            if (string.IsNullOrEmpty(errorMessage)) return false;
            return errorMessage.IndexOf("Inactive Account User", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        /// <summary>
        /// Exponential backoff with ±25% jitter for the rate-limit retry inside
        /// <see cref="PlaceOrderAsync"/>.  Attempts 1..5 produce roughly
        /// 1s / 2s / 4s / 8s / 16s of nominal delay.
        ///
        /// <para>
        /// <b>Thundering-herd assumption:</b> jitter is sampled from a process-wide
        /// <see cref="Org.BouncyCastle.Security.SecureRandom"/> (<c>_txnRandom</c>),
        /// so concurrent callers in the same process get independent samples.
        /// Multiple gateway pods hitting the same CERTInext tenant each have their
        /// own seeded instance, so jitter is also independent across pods.  The
        /// ±25% spread on the 16s nominal at attempt 5 produces a 4s window — wide
        /// enough to de-correlate from the documented "~16 orders / 10 s" sandbox
        /// limit if a multi-pod fleet hits the limit simultaneously.
        /// </para>
        ///
        /// Exposed <c>internal</c> so unit tests can verify the schedule.
        /// </summary>
        internal static double ComputeRateLimitBackoffSeconds(int attempt)
        {
            if (attempt < 1) attempt = 1;
            double nominal = RateLimitBaseBackoffSeconds * Math.Pow(2, attempt - 1);
            // ±25% jitter via SecureRandom — non-cryptographic randomness is fine for
            // jitter, but we already have a SecureRandom instance for txn IDs and
            // reusing it is one fewer source of randomness to think about.
            double jitterFactor = 0.75 + _txnRandom.NextDouble() * 0.5;
            return nominal * jitterFactor;
        }

        // Cap on the response body length we include in operator-facing warning logs.
        // 4 KB is comfortably more than every observed CERTInext error envelope (typically
        // <500 B) while still bounding the log line if a misrouted response ever shows up.
        // See GitHub issue #8 — operators need the raw body to disambiguate misleading
        // CA error strings (e.g. the sandbox's "Inactive Account User." rate-limit surface).
        private const int LoggedResponseBodyCapBytes = 4 * 1024;

        /// <summary>
        /// Truncates <paramref name="s"/> to at most <paramref name="max"/> characters,
        /// appending a "(truncated, N more chars)" marker so log readers can tell at a
        /// glance that the value was cut.  Returns the input unchanged when short enough.
        /// </summary>
        private static string Truncate(string s, int max)
        {
            if (string.IsNullOrEmpty(s) || s.Length <= max) return s;
            return s.Substring(0, max) + $"…(truncated, {s.Length - max} more chars)";
        }

        /// <summary>
        /// Scrubs known credential-bearing keys out of a JSON-ish body before it goes
        /// into a log line.  CERTInext error envelopes are not currently observed to
        /// echo request fields, but the response shape isn't contractually fixed and
        /// the <c>authKey</c> digest in the request meta block IS a replayable
        /// privileged credential under SOX (anyone with one valid
        /// <c>(ts, txn, authKey)</c> triple can replay until the timestamp window expires).
        /// Defense-in-depth: redact before logging, not after a leak.
        ///
        /// Conservative substring/regex pass — handles JSON, form-urlencoded, and
        /// header-line shapes.  Exposed <c>internal</c> for unit-testing.
        /// </summary>
        internal static string RedactCredentials(string body)
        {
            if (string.IsNullOrEmpty(body)) return body;

            // JSON: "authKey": "..."  → "authKey":"***REDACTED***"
            // JSON: "client_secret":"..."  → same
            // JSON: "ApiKey":"..."  → same (defensive — not currently sent on the wire,
            //  but the field name is a common one and the cost of redacting it is zero).
            body = System.Text.RegularExpressions.Regex.Replace(
                body,
                @"(?i)""(authKey|client_secret|apiKey|accessKey|password)""\s*:\s*""[^""]*""",
                @"""$1"":""***REDACTED***""");

            // Form-urlencoded: client_secret=... or authKey=... (before any & or end)
            body = System.Text.RegularExpressions.Regex.Replace(
                body,
                @"(?i)\b(authKey|client_secret|apiKey|accessKey|password)=([^&\s""]+)",
                "$1=***REDACTED***");

            // Authorization header lines if a header dump ever ends up in body shape.
            // Match through end-of-line so multi-token values (e.g. "Bearer <token>")
            // are fully scrubbed, not just the scheme word.
            body = System.Text.RegularExpressions.Regex.Replace(
                body,
                @"(?im)^Authorization:[^\r\n]*",
                "Authorization: ***REDACTED***");

            return body;
        }

        /// <summary>
        /// Writes a structured log capturing every diagnostic field available for a
        /// non-success CERTInext API response — HTTP status, the CERTInext-side error
        /// code and message, and the (truncated, credential-scrubbed) raw response body.
        /// Call this immediately before throwing so the exception's "See gateway logs
        /// for details" instruction actually points somewhere useful.
        ///
        /// Background: issue #8 surfaced that the sandbox returns the generic string
        /// <c>"Inactive Account User."</c> for several conditions including burst
        /// rate-limit rejection.  Without the raw body in the log, an operator has no
        /// way to disambiguate "the account is genuinely inactive" from "you submitted
        /// 16 orders in 10 seconds and the CA's burst quota kicked in."
        ///
        /// <para>
        /// <b>Do NOT call this helper from the OAuth token-exchange path</b> — that
        /// request body contains the plaintext <c>client_secret</c>, and while
        /// <see cref="RedactCredentials"/> scrubs known credential keys defensively,
        /// the token-exchange path has its own explicit log-suppression comment at
        /// the existing throw site and we want to keep that path's blast radius tight.
        /// </para>
        ///
        /// Default <paramref name="level"/> is <see cref="LogLevel.Warning"/> — meta-failure-on-HTTP-200
        /// is the CA saying "no" to a request, a business outcome rather than a plugin
        /// fault.  Callers handling authentication failures should pass
        /// <see cref="LogLevel.Error"/> so SOX-loggable authentication events match
        /// the SIEM-alert level convention.
        /// </summary>
        private static void LogApiFailure(
            string operationContext,
            RestResponse resp,
            string errorCode = null,
            string errorMessage = null,
            LogLevel level = LogLevel.Warning)
        {
            string sanitizedBody = RedactCredentials(resp?.Content) ?? "(empty)";
            Logger.Log(
                level,
                "CERTInext API non-success. Operation={Operation}, HttpStatus={HttpStatus}, " +
                "ErrorCode={ErrorCode}, ErrorMessage={ErrorMessage}, ResponseBody={ResponseBody}",
                operationContext,
                (int?)resp?.StatusCode ?? 0,
                errorCode ?? "(none)",
                errorMessage ?? "(none)",
                Truncate(sanitizedBody, LoggedResponseBodyCapBytes));
        }

        private static string ExtractErrorMessage(string content, string operation)
        {
            if (string.IsNullOrWhiteSpace(content))
                return $"CERTInext returned no body for operation '{operation}'.";

            if (content.Length > MaxErrorBodyBytes)
            {
                Logger.LogWarning(
                    "CERTInext response body for '{Operation}' exceeded the parser size cap " +
                    "({Length} bytes, cap {Cap}). Truncating before JSON parse to avoid memory exhaustion.",
                    operation, content.Length, MaxErrorBodyBytes);
                content = content.Substring(0, MaxErrorBodyBytes);
            }

            try
            {
                // Try to parse as a CERTInext response with a meta block
                using var doc = JsonDocument.Parse(content);
                if (doc.RootElement.TryGetProperty("meta", out var meta))
                {
                    string errMsg = null;
                    string errCode = null;
                    if (meta.TryGetProperty("errorMessage", out var em)) errMsg = em.GetString();
                    if (meta.TryGetProperty("errorCode", out var ec)) errCode = ec.GetString();
                    if (!string.IsNullOrWhiteSpace(errMsg) || !string.IsNullOrWhiteSpace(errCode))
                        return $"CERTInext error during '{operation}': {errMsg ?? errCode} [{errCode}]";
                }

                // Fall back to legacy ApiErrorResponse shape
                if (doc.RootElement.TryGetProperty("message", out var legacyMsg))
                    return $"CERTInext error during '{operation}': {legacyMsg.GetString()}";
            }
            catch
            {
                // Fall through to safe generic message
            }

            return $"CERTInext returned an unrecognised error body for operation '{operation}'. " +
                   "See gateway logs for details.";
        }

        private static JsonSerializerOptions GetJsonOptions() => new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        };
    }
}
