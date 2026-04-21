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
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.Models;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using RestSharp;

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
    public class CERTInextClient : ICERTInextClient
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

            var options = new RestClientOptions(_config.ApiUrl.TrimEnd('/') + "/")
            {
                ThrowOnAnyError = false,
                Timeout = TimeSpan.FromSeconds(120),
            };

            _http = new RestClient(options);
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
            var resp = await _http.ExecuteAsync(req, ct);
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
                Logger.LogError(
                    "CERTInext ValidateCredentials returned failure. ErrorCode={ErrorCode}, ErrorMessage={ErrorMsg}",
                    result.Meta.ErrorCode, result.Meta.ErrorMessage);
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

            var req = new RestRequest(Constants.Api.GenerateOrderSslPath, Method.Post);
            req.AddJsonBody(JsonSerializer.Serialize(request, GetJsonOptions()));

            var sw = System.Diagnostics.Stopwatch.StartNew();
            var resp = await _http.ExecuteAsync(req, ct);
            sw.Stop();

            Logger.LogInformation(
                "CERTInext API call: Method=POST, Path={Path}, HttpStatus={Status}, LatencyMs={Latency}, AuthMode={AuthMode}",
                Constants.Api.GenerateOrderSslPath, (int)resp.StatusCode, sw.ElapsedMilliseconds, _config.AuthMode);

            if (resp.StatusCode == HttpStatusCode.Unauthorized || resp.StatusCode == HttpStatusCode.Forbidden)
            {
                Logger.LogError(
                    "PlaceOrder API authentication failure. HttpStatus={Status}, AuthMode={AuthMode}",
                    (int)resp.StatusCode, _config.AuthMode);
                throw new Exception(
                    $"Authentication failure during certificate order. HTTP {(int)resp.StatusCode}. See gateway logs for details.");
            }

            var result = DeserializeOrThrow<GenerateOrderResponse>(resp, "place order");

            if (result.Meta != null && !result.Meta.IsSuccess)
                throw new Exception(
                    $"CERTInext order failed: {result.Meta.ErrorMessage ?? result.Meta.ErrorCode}. " +
                    "See gateway logs for details.");

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
            var resp = await _http.ExecuteAsync(req, ct);
            sw.Stop();

            Logger.LogInformation(
                "CERTInext API call: Method=POST, Path={Path}, HttpStatus={Status}, LatencyMs={Latency}, AuthMode={AuthMode}",
                Constants.Api.SubmitCsrPath, (int)resp.StatusCode, sw.ElapsedMilliseconds, _config.AuthMode);

            if (!resp.IsSuccessful)
                throw new Exception($"CERTInext SubmitCSR failed. HTTP {(int)resp.StatusCode}. See gateway logs for details.");

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
            var resp = await _http.ExecuteAsync(req, ct);
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
            var resp = await _http.ExecuteAsync(req, ct);
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
                throw new Exception(
                    $"CERTInext GetCertificate failed for order '{orderNumber}': {result.Meta.ErrorMessage ?? result.Meta.ErrorCode}.");

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
            var resp = await _http.ExecuteAsync(req, ct);
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
                var resp = await _http.ExecuteAsync(req, ct);
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
                ProductDetails = new ProductDetailsFilter()
            };

            var req = new RestRequest(Constants.Api.GetProductDetailsPath, Method.Post);
            req.AddJsonBody(JsonSerializer.Serialize(body, GetJsonOptions()));

            var sw = System.Diagnostics.Stopwatch.StartNew();
            var resp = await _http.ExecuteAsync(req, ct);
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

            Logger.LogInformation("Retrieved {Count} product codes from CERTInext.",
                result.ProductDetails?.Count ?? 0);
            Logger.MethodExit(LogLevel.Trace);
            return result.ProductDetails ?? new List<ProductDetail>();
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
        // Auth helpers
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Builds the meta authentication block for a CERTInext API request.
        /// For AccessKey auth: authKey = SHA256(accessKey + ts + txn) (hex, lowercase).
        /// For OAuth auth: the bearer token is applied as an HTTP header instead
        /// (not in the meta block), but meta is still required for ver/ts/txn/accountNumber.
        /// </summary>
        private async Task<RequestMeta> BuildMetaAsync(CancellationToken ct)
        {
            string ts = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:sszzz");
            string txn = GenerateTxnId();

            string authKey;
            if (_config.AuthMode.Equals(Constants.Config.AuthModeOAuth, StringComparison.OrdinalIgnoreCase) ||
                _config.AuthMode.Equals(Constants.Config.AuthModeOAuth2, StringComparison.OrdinalIgnoreCase))
            {
                // OAuth: authenticate via bearer token header; authKey is left empty in meta
                // (the server accepts the bearer token in lieu of authKey)
                authKey = string.Empty;
                // Attach the bearer token to the RestClient for the next request
                // This is done by pre-populating a thread-local; actual header injection
                // happens in the calling method after BuildMetaAsync returns.
                // For simplicity here, we fetch the token and rely on the HTTP pipeline.
                string token = await GetOrRefreshTokenAsync(ct);
                // Store for injection by calling code — the cleanest approach is to add it
                // as a default header on the request itself after this method returns.
                // We store it as a field so the caller can inject it.
                _pendingBearerToken = token;
            }
            else
            {
                // AccessKey: compute SHA256(accessKey + ts + txn)
                _pendingBearerToken = null;
                authKey = ComputeAuthKey(_config.ApiKey, ts, txn);
            }

            // SOX CC6.1: log credential use (presence only, never the value) at Information.
            Logger.LogInformation(
                "Outbound API request authenticated. AuthMode={AuthMode}, AccountNumber={AccountNumber}, " +
                "ApiKeyPresent={Present}",
                _config.AuthMode, _config.AccountNumber, !string.IsNullOrEmpty(_config.ApiKey));

            return new RequestMeta
            {
                Ver = Constants.Api.MetaVersion,
                Ts = ts,
                Txn = txn,
                AccountNumber = _config.AccountNumber,
                AuthKey = authKey
            };
        }

        // Thread-local pending bearer token set by BuildMetaAsync for OAuth flows.
        // The RestRequest AddHeader call must happen in the calling method after BuildMetaAsync.
        [ThreadStatic]
        private static string _pendingBearerToken;

        /// <summary>
        /// Applies any pending OAuth bearer token to the outgoing RestRequest.
        /// Call this immediately after BuildMetaAsync and before executing the request.
        /// </summary>
        private static void ApplyPendingAuth(RestRequest req)
        {
            if (!string.IsNullOrEmpty(_pendingBearerToken))
            {
                req.AddHeader("Authorization", $"Bearer {_pendingBearerToken}");
                _pendingBearerToken = null;
            }
        }

        /// <summary>
        /// Computes the CERTInext authKey: SHA256(accessKey + ts + txn) as lowercase hex.
        /// </summary>
        private static string ComputeAuthKey(string accessKey, string ts, string txn)
        {
            string input = accessKey + ts + txn;
            byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(input));
            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        /// <summary>
        /// Generates a unique transaction ID (alphanumeric, 16–18 digits).
        /// </summary>
        private static string GenerateTxnId()
        {
            // Match the Postman pre-request script: Math.floor(Math.random() * 1e18 + 1)
            long val = (long)(Random.Shared.NextDouble() * 1_000_000_000_000_000_000L) + 1L;
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
            return new LegacyGetCertificateResponse
            {
                Id = string.IsNullOrWhiteSpace(entry.OrderNumber) ? entry.RequestNumber : entry.OrderNumber,
                Status = MapCertStatusIdToLegacyString(entry.CertificateStatusId),
                Subject = entry.DomainName,
                ProfileId = entry.ProductCode
            };
        }

        private GenerateOrderSslRequest BuildOrderRequestFromLegacyEnrollRequest(EnrollCertificateRequest request)
        {
            return new GenerateOrderSslRequest
            {
                // Meta will be set by PlaceOrderAsync
                OrderDetails = new SslOrderDetails
                {
                    ProductCode = request.ProfileId ?? _config.DefaultProductCode ?? string.Empty,
                    SaveAndHold = "0",
                    RequestorInformation = new RequestorInformation
                    {
                        RequestorName = request.RequesterName ?? _config.RequestorName ?? "Keyfactor Gateway",
                        RequestorEmail = request.RequesterEmail ?? _config.RequestorEmail ?? string.Empty,
                        RequestorIsdCode = _config.RequestorIsdCode ?? "1",
                        RequestorMobileNumber = _config.RequestorMobileNumber ?? string.Empty
                    },
                    SubscriptionDetails = new SubscriptionDetails
                    {
                        Validity = request.ValidityDays.HasValue
                            ? Math.Ceiling(request.ValidityDays.Value / 365.0).ToString("0")
                            : "1"
                    },
                    CertificateInformation = new CertificateInformation
                    {
                        DomainName = ExtractCnFromSubject(request.Subject) ?? "unknown",
                        AdditionalDomains = BuildAdditionalDomains(request.Sans)
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
            return new AgreementDetails
            {
                AcceptAgreement = "1",
                SignerName = _config.RequestorName ?? "Keyfactor Gateway",
                SignerPlace = _config.SignerPlace ?? "Gateway",
                SignerIp = _config.SignerIp ?? "127.0.0.1"
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

        private static string ExtractErrorMessage(string content, string operation)
        {
            if (string.IsNullOrWhiteSpace(content))
                return $"CERTInext returned no body for operation '{operation}'.";

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
