// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Client
{
    /// <summary>
    /// Abstraction over the CERTInext REST API.  Inject a mock implementation in unit tests.
    ///
    /// The real CERTInext API uses HTTP POST for all operations.  Every request body
    /// contains a <c>meta</c> block with a computed <c>authKey = SHA256(accessKey + ts + txn)</c>.
    /// Endpoint names are appended directly to the configured base URL (no path prefix).
    ///
    /// Primary identifiers:
    ///   - <c>orderNumber</c> from <see cref="GenerateOrderResponse"/> is the stable
    ///     CARequestID stored in Keyfactor Command.
    ///   - Certificate data is retrieved via separate TrackOrder + GetCertificate calls.
    /// </summary>
    public interface ICERTInextClient : IDisposable
    {
        /// <summary>
        /// Verifies that the CERTInext API is reachable and the credentials are valid
        /// by calling POST {baseURL}ValidateCredentials.
        /// Throws if the connectivity check fails.
        /// </summary>
        Task PingAsync(CancellationToken ct = default);

        /// <summary>
        /// Places a new SSL/TLS certificate order via POST {baseURL}GenerateOrderSSL.
        /// Returns the order response containing the <c>orderNumber</c> (CARequestID).
        /// </summary>
        Task<GenerateOrderResponse> PlaceOrderAsync(
            GenerateOrderSslRequest request,
            CancellationToken ct = default);

        /// <summary>
        /// Submits a CSR to an existing order via POST {baseURL}SubmitCSR.
        /// Required when the order was placed without a CSR (saveAndHold flow).
        /// </summary>
        Task SubmitCsrAsync(
            SubmitCsrRequest request,
            CancellationToken ct = default);

        /// <summary>
        /// Retrieves the current status of an order via POST {baseURL}TrackOrder.
        /// Returns order status, certificate status ID, expiry date, and revocation details.
        /// </summary>
        Task<TrackOrderResponse> TrackOrderAsync(
            string orderNumber,
            CancellationToken ct = default);

        /// <summary>
        /// Downloads the issued certificate for a fulfilled order via POST {baseURL}GetCertificate.
        /// Returns the PEM-encoded end-entity certificate and chain.
        /// </summary>
        Task<GetCertificateResponse> DownloadCertificateAsync(
            string orderNumber,
            CancellationToken ct = default);

        /// <summary>
        /// Revokes a certificate via POST {baseURL}RevokeOrder.
        /// </summary>
        Task RevokeOrderAsync(
            RevokeOrderRequest request,
            CancellationToken ct = default);

        /// <summary>
        /// Pages through all orders/certificates via POST {baseURL}GetOrderReport.
        /// Used for synchronization.  Optionally filtered by order date.
        /// </summary>
        IAsyncEnumerable<OrderReportEntry> ListOrdersAsync(
            string orderDateFrom = null,
            int pageSize = Constants.Api.DefaultPageSize,
            CancellationToken ct = default);

        /// <summary>
        /// Returns all active product codes visible to the configured credentials
        /// via POST {baseURL}GetProductDetails.
        /// </summary>
        Task<List<ProductDetail>> GetProductDetailsAsync(CancellationToken ct = default);

        // -----------------------------------------------------------------------
        // Legacy methods — retained for backward compatibility with CERTInextCAPlugin
        // and existing unit tests while the plugin is incrementally updated.
        // These wrap the real API methods using the inferred REST design types.
        // -----------------------------------------------------------------------

        /// <summary>
        /// LEGACY: Places an order and returns an inferred-style enrollment response.
        /// Wraps <see cref="PlaceOrderAsync"/> and <see cref="TrackOrderAsync"/>.
        /// Use <see cref="PlaceOrderAsync"/> for new code.
        /// </summary>
        Task<EnrollCertificateResponse> EnrollCertificateAsync(
            EnrollCertificateRequest request,
            CancellationToken ct = default);

        /// <summary>
        /// LEGACY: Renews an existing certificate and returns an inferred-style response.
        /// The real CERTInext API has no dedicated renew endpoint — this places a new order.
        /// Use <see cref="PlaceOrderAsync"/> for new code.
        /// </summary>
        Task<EnrollCertificateResponse> RenewCertificateAsync(
            string certificateId,
            RenewCertificateRequest request,
            CancellationToken ct = default);

        /// <summary>
        /// LEGACY: Returns an inferred-style single certificate record combining
        /// TrackOrder and GetCertificate data.
        /// Use <see cref="TrackOrderAsync"/> + <see cref="DownloadCertificateAsync"/> for new code.
        /// </summary>
        Task<LegacyGetCertificateResponse> GetCertificateAsync(
            string certificateId,
            CancellationToken ct = default);

        /// <summary>
        /// LEGACY: Revokes a certificate using the inferred-style request type.
        /// Wraps <see cref="RevokeOrderAsync"/>.
        /// Use <see cref="RevokeOrderAsync"/> for new code.
        /// </summary>
        Task RevokeCertificateAsync(
            string certificateId,
            RevokeCertificateRequest request,
            CancellationToken ct = default);

        /// <summary>
        /// LEGACY: Pages through certificates returning inferred-style records.
        /// Wraps <see cref="ListOrdersAsync"/>.
        /// Use <see cref="ListOrdersAsync"/> for new code.
        /// </summary>
        IAsyncEnumerable<LegacyGetCertificateResponse> ListCertificatesAsync(
            DateTime? issuedAfter = null,
            int pageSize = Constants.Api.DefaultPageSize,
            CancellationToken ct = default);

        /// <summary>
        /// LEGACY: Returns inferred-style profile objects.
        /// Wraps <see cref="GetProductDetailsAsync"/>.
        /// Use <see cref="GetProductDetailsAsync"/> for new code.
        /// </summary>
        Task<List<ProfileInfo>> GetProfilesAsync(CancellationToken ct = default);

        // -----------------------------------------------------------------------
        // DCV — domain control validation endpoints (used for DV/OV SSL orders)
        // -----------------------------------------------------------------------

        /// <summary>
        /// Fetches the DCV token for a single domain on an existing order via POST {baseURL}GetDcv.
        /// The token is the TXT record value to publish (for dcvMethod=1 / DNS TXT).
        /// </summary>
        Task<GetDcvResponse> GetDcvAsync(
            string orderNumber,
            string domainName,
            string dcvMethod,
            CancellationToken ct = default);

        /// <summary>
        /// Instructs CERTInext to verify the DCV token for a domain via POST {baseURL}VerifyDcv.
        /// Call after the DNS TXT record has been published and propagated.
        /// </summary>
        Task VerifyDcvAsync(
            string orderNumber,
            string domainName,
            string dcvMethod,
            CancellationToken ct = default);

        // -----------------------------------------------------------------------
        // V2 REST API methods — only active when UseV2Api = true
        // -----------------------------------------------------------------------

        /// <summary>
        /// V2 connectivity check via GET /api/certinext/v2/auth/me.
        /// Throws if the V2 endpoint is unreachable or credentials are invalid.
        /// </summary>
        Task PingV2Async(CancellationToken ct = default);

        /// <summary>
        /// Places a new order via POST /api/certinext/v2/{productFamilySlug}.
        /// The product code is sent as the X-Product-Code header.
        /// An Idempotency-Key is generated automatically.
        /// </summary>
        Task<V2CreateOrderResponse> PlaceOrderV2Async(
            string productFamilySlug,
            string productCode,
            V2CreateSslOrderRequest request,
            CancellationToken ct = default);

        /// <summary>
        /// Submits a CSR to an existing V2 order via PUT /api/certinext/v2/{family}/{orderId}/csr.
        /// </summary>
        Task SubmitCsrV2Async(
            string productFamilySlug,
            string orderId,
            string csrPem,
            CancellationToken ct = default);

        /// <summary>
        /// Returns the current status of a V2 order via GET /api/certinext/v2/{family}/{orderId}.
        /// Throws <see cref="KeyNotFoundException"/> when the order does not exist in that family.
        /// </summary>
        Task<V2OrderStatusResponse> TrackOrderV2Async(
            string productFamilySlug,
            string orderId,
            CancellationToken ct = default);

        /// <summary>
        /// Downloads the issued certificate for a V2 order.
        /// GET /api/certinext/v2/{family}/{orderId}/certificate
        /// </summary>
        Task<V2CertificateDownloadResponse> DownloadCertificateV2Async(
            string productFamilySlug,
            string orderId,
            CancellationToken ct = default);

        /// <summary>
        /// Revokes a V2 certificate via POST /api/certinext/v2/{family}/{orderId}/revoke.
        /// An Idempotency-Key is generated automatically.
        /// </summary>
        Task RevokeOrderV2Async(
            string productFamilySlug,
            string orderId,
            V2RevokeRequest request,
            CancellationToken ct = default);

        /// <summary>
        /// Returns V2 auth/me response (accountNumber, authType).
        /// </summary>
        Task<V2AuthMeResponse> GetAuthMeV2Async(CancellationToken ct = default);

        /// <summary>
        /// Resolves the product-family slug for the given V2 order ID by probing all three
        /// families (ssl → private-pki → signature), then returns the track response.
        /// Throws <see cref="KeyNotFoundException"/> if the order is not found in any family.
        /// </summary>
        Task<V2OrderStatusResponse> ResolveAndTrackOrderV2Async(
            string orderId,
            CancellationToken ct = default);

        /// <summary>
        /// Resolves the product-family slug for the given V2 order ID and downloads the certificate.
        /// Throws <see cref="KeyNotFoundException"/> if the order is not found in any family.
        /// </summary>
        Task<V2CertificateDownloadResponse> ResolveAndDownloadCertificateV2Async(
            string orderId,
            CancellationToken ct = default);

        /// <summary>
        /// Returns the DCV challenge details for a V2 SSL order.
        /// GET /api/certinext/v2/ssl-certificates/{orderId}/dcv
        /// </summary>
        Task<V2DcvChallengeResponse> GetDcvV2Async(string orderId, CancellationToken ct = default);

        /// <summary>
        /// Asks CERTInext to verify the DNS TXT record for the given domain on a V2 order.
        /// POST /api/certinext/v2/ssl-certificates/{orderId}/dcv/verify
        /// Both 200 OK and 204 No Content are treated as success.
        /// Throws <see cref="InvalidOperationException"/> on 422 (verification failed).
        /// </summary>
        Task<V2DcvVerifyResponse> VerifyDcvV2Async(string orderId, string domain, CancellationToken ct = default);

        /// <summary>
        /// Returns the list of products available in the V2 catalog.
        /// GET /api/certinext/v2/catalog/products
        /// </summary>
        Task<List<ProductDetail>> GetProductDetailsV2Async(CancellationToken ct = default);
    }
}
