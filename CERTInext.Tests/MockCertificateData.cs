// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Static helpers that return realistic fake CERTInext API response objects and
    /// JSON payloads.  Shared by both WireMock and Moq test classes.
    ///
    /// The real CERTInext API uses HTTP POST for all endpoints.  All responses include
    /// a "meta" wrapper with status "1" (success) or "0" (failure).
    /// </summary>
    internal static class MockCertificateData
    {
        // -----------------------------------------------------------------------
        // A minimal but valid self-signed PEM certificate used in all responses.
        // (Not cryptographically real — just valid base64 that WireMock/tests can
        //  treat as a string placeholder.)
        // -----------------------------------------------------------------------
        public const string FakePemCertificate =
            "-----BEGIN CERTIFICATE-----\n" +
            "MIICpDCCAYwCCQDU0G6oSvbhdjANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls\n" +
            "b2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD\n" +
            "VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7\n" +
            "o4qne60TB3wolLBbUBqHkpMODFMmZc6ePRxKSRnKbBoJTBhSN1MMjBqVFbxDsP7\n" +
            "-----END CERTIFICATE-----\n";

        public const string FakeCsrPem =
            "-----BEGIN CERTIFICATE REQUEST-----\n" +
            "MIICijCCAXICAQAwRTELMAkGA1UEBhMCVVMxEzARBgNVBAgMClNvbWUtU3RhdGUx\n" +
            "ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN\n" +
            "-----END CERTIFICATE REQUEST-----\n";

        // Well-known IDs used across tests
        // These are numeric order numbers matching the real CERTInext API model.
        public const string OrderNumber1 = "ORD-AAA-111";
        public const string OrderNumber2 = "ORD-BBB-222";
        public const string OrderNumber3 = "ORD-CCC-333";

        // Aliases for backward compatibility with Moq-based tests that use CertId1/2/3
        public const string CertId1 = OrderNumber1;
        public const string CertId2 = OrderNumber2;
        public const string CertId3 = OrderNumber3;

        // Product codes used in GetProductDetails responses
        public const string ProfileIdTls = "tls-server";
        public const string ProfileIdClient = "client-auth";

        // -----------------------------------------------------------------------
        // Real CERTInext API response JSON helpers
        // -----------------------------------------------------------------------

        /// <summary>Success meta block for use in all response JSON.</summary>
        private static string SuccessMetaJson(string txn = "123456789") =>
            $@"{{""ver"":""1.0"",""ts"":""2024-06-01T00:00:00+00:00"",""txn"":""{txn}"",""status"":""1"",""errorCode"":"""",""errorMessage"":""""}}";

        /// <summary>Failure meta block for use in error response JSON.</summary>
        private static string FailureMetaJson(string errorCode = "EMS-001", string errorMessage = "Error") =>
            $@"{{""ver"":""1.0"",""ts"":""2024-06-01T00:00:00+00:00"",""txn"":""123456789"",""status"":""0"",""errorCode"":""{errorCode}"",""errorMessage"":""{errorMessage}""}}";

        // POST /ValidateCredentials
        public static string ValidateCredentialsSuccessJson() =>
            $@"{{""meta"":{SuccessMetaJson()}}}";

        public static string ValidateCredentialsFailureJson(string code = "EMS-001", string msg = "Invalid credentials") =>
            $@"{{""meta"":{FailureMetaJson(code, msg)}}}";

        // POST /GenerateOrderSSL
        public static string GenerateOrderSuccessJson(string orderNumber = "ORD-AAA-111") =>
            $@"{{
  ""meta"":{SuccessMetaJson()},
  ""orderDetails"":{{
    ""orderNumber"":""{orderNumber}"",
    ""requestNumber"":""REQ-001"",
    ""trackingURL"":""https://certinext.io/track/{orderNumber}""
  }}
}}";

        // POST /TrackOrder — certificate generated (certificateStatusId=9)
        public static string TrackOrderIssuedJson(string orderNumber = "ORD-AAA-111") =>
            $@"{{
  ""meta"":{SuccessMetaJson()},
  ""orderDetails"":{{
    ""orderNumber"":""{orderNumber}"",
    ""orderStatusId"":""4"",
    ""certificateStatusId"":""9"",
    ""certificateExpiryDate"":""2025-06-01"",
    ""requestorInformation"":{{""requestorName"":""Test User"",""requestorEmail"":""test@example.com""}},
    ""revocationDetails"":null
  }}
}}";

        // POST /TrackOrder — pending (certificateStatusId=1 = SetupPending, not downloadable)
        public static string TrackOrderPendingJson(string orderNumber = "ORD-BBB-222") =>
            $@"{{
  ""meta"":{SuccessMetaJson()},
  ""orderDetails"":{{
    ""orderNumber"":""{orderNumber}"",
    ""orderStatusId"":""1"",
    ""certificateStatusId"":""1"",
    ""certificateExpiryDate"":null,
    ""requestorInformation"":{{""requestorName"":""Test User"",""requestorEmail"":""test@example.com""}},
    ""revocationDetails"":null
  }}
}}";

        // POST /TrackOrder — revoked (certificateStatusId=22)
        public static string TrackOrderRevokedJson(string orderNumber = "ORD-CCC-333") =>
            $@"{{
  ""meta"":{SuccessMetaJson()},
  ""orderDetails"":{{
    ""orderNumber"":""{orderNumber}"",
    ""orderStatusId"":""5"",
    ""certificateStatusId"":""22"",
    ""certificateExpiryDate"":""2025-01-01"",
    ""requestorInformation"":{{""requestorName"":""Test User"",""requestorEmail"":""test@example.com""}},
    ""revocationDetails"":{{
      ""revokeReasonId"":""1"",
      ""revokeProcessedDate"":""2024-03-15T00:00:00Z""
    }}
  }}
}}";

        // POST /GetCertificate
        public static string GetCertificateSuccessJson() =>
            $@"{{
  ""meta"":{SuccessMetaJson()},
  ""certificateDetails"":{{
    ""endEntityCertificate"":""{EscapeForJson(FakePemCertificate)}"",
    ""caCertificate"":"""",
    ""rootCertificate"":"""",
    ""expiryDate"":""2025-06-01"",
    ""ceritficateSerialNumber"":""0A1B2C3D4E5F""
  }}
}}";

        // POST /RevokeOrder
        public static string RevokeSuccessJson() =>
            $@"{{""meta"":{SuccessMetaJson()}}}";

        // POST /GetOrderReport — single page with one entry
        public static string OrderReportSinglePageJson() =>
            OrderReportPageJson(new[] { OrderNumber1 }, totalNoOfResults: 1, noOfPages: 1);

        // POST /GetOrderReport — multi-entry page.
        // Matches the live API shape:
        // { "orderDetails": { "noOfPages": N, "totalNoOfResults": N, "ordersArray": [...],
        //                     "pageSize": N, "currentPage": "1" }, "meta": {...} }
        public static string OrderReportPageJson(string[] orderNumbers, int totalNoOfResults, int noOfPages, int currentPage = 1)
        {
            var entries = new System.Text.StringBuilder();
            bool first = true;
            foreach (var on in orderNumbers)
            {
                if (!first) entries.Append(',');
                first = false;
                entries.Append($@"{{
      ""orderNumber"":""{on}"",
      ""requestNumber"":"""",
      ""certificateStatusId"":""9"",
      ""certificateStatus"":""Certificate Downloaded"",
      ""orderStatusId"":""4"",
      ""orderStatus"":""Fulfilled"",
      ""domainName"":""test.example.com"",
      ""organizationName"":""Test Org"",
      ""groupNumber"":""1234567890"",
      ""productCode"":""{ProfileIdTls}"",
      ""certificateSerialNumber"":""0A1B2C3D4E5F"",
      ""certificateExpiryDate"":""2025-06-01"",
      ""issuerCA"":""emSign"",
      ""certificateTrustType"":""Public"",
      ""orderDate"":""2024-06-01"",
      ""expiresWithin"":"""",
      ""tags"":[],
      ""customFields"":[],
      ""countryName"":""IN""
    }}");
            }
            return $@"{{
  ""meta"":{SuccessMetaJson()},
  ""orderDetails"":{{
    ""noOfPages"":{noOfPages},
    ""totalNoOfResults"":{totalNoOfResults},
    ""ordersArray"":[{entries}],
    ""pageSize"":{orderNumbers.Length},
    ""currentPage"":""{currentPage}""
  }}
}}";
        }

        // POST /GetOrderReport — empty response (no results)
        // meta.status="1" but ordersArray is empty; noOfPages=0.
        public static string OrderReportEmptyJson() =>
            $@"{{""meta"":{SuccessMetaJson()},""orderDetails"":{{""noOfPages"":0,""totalNoOfResults"":0,""ordersArray"":[],""pageSize"":0,""currentPage"":""1""}}}}";

        // Overload kept for callers that passed a string totalCount (backward compat in tests)
        public static string OrderReportPageJson(string[] orderNumbers, string totalCount) =>
            OrderReportPageJson(orderNumbers,
                int.TryParse(totalCount, out int tc) ? tc : orderNumbers.Length,
                noOfPages: 1);

        // POST /GetProductDetails
        // Returns the nested category envelope format returned by the real CERTInext API
        // (verified 2026-04). Each category object contains a "products" array.
        // CERTInextClient.GetProductDetailsAsync calls FlattenProducts() to collapse this
        // into a flat List<ProductDetail>.
        public static string GetProductDetailsJson() =>
            $@"{{
  ""meta"":{SuccessMetaJson()},
  ""productDetails"":[
    {{
      ""categoryName"":""SSL/TLS Certificates"",
      ""categoryID"":""3"",
      ""currencyType"":""USD"",
      ""products"":[
        {{""productCode"":""{ProfileIdTls}"",""productName"":""TLS Server"",""productTypeID"":""13""}},
        {{""productCode"":""{ProfileIdClient}"",""productName"":""Client Authentication"",""productTypeID"":""14""}}
      ]
    }}
  ]
}}";

        public static string GetProductDetailsEmptyJson() =>
            $@"{{""meta"":{SuccessMetaJson()},""productDetails"":[]}}";

        // Generic API failure body (meta.status = "0")
        public static string ApiFailureJson(string errorCode = "EMS-100", string errorMessage = "An error occurred") =>
            $@"{{""meta"":{FailureMetaJson(errorCode, errorMessage)}}}";

        // -----------------------------------------------------------------------
        // Profile data (object helpers — used by Moq-based tests)
        // -----------------------------------------------------------------------

        public static List<ProfileInfo> ActiveProfiles() => new List<ProfileInfo>
        {
            new ProfileInfo
            {
                Id = ProfileIdTls,
                Name = "TLS Server",
                Description = "Standard TLS server certificate",
                Active = true,
                DefaultValidityDays = 365
            },
            new ProfileInfo
            {
                Id = ProfileIdClient,
                Name = "Client Authentication",
                Description = "Client auth certificate",
                Active = true,
                DefaultValidityDays = 365
            }
        };

        public static List<ProfileInfo> MixedProfiles() => new List<ProfileInfo>
        {
            new ProfileInfo { Id = ProfileIdTls,    Name = "TLS Server",          Active = true,  DefaultValidityDays = 365 },
            new ProfileInfo { Id = "legacy-profile", Name = "Legacy (inactive)",   Active = false, DefaultValidityDays = 365 },
            new ProfileInfo { Id = ProfileIdClient, Name = "Client Authentication", Active = true,  DefaultValidityDays = 365 }
        };

        // -----------------------------------------------------------------------
        // Enrollment response (object helpers — used by Moq-based plugin tests)
        // -----------------------------------------------------------------------

        public static EnrollCertificateResponse IssuedEnrollResponse(string id = null) =>
            new EnrollCertificateResponse
            {
                Id = id ?? CertId1,
                Status = "issued",
                Certificate = FakePemCertificate,
                SerialNumber = "0A1B2C3D4E5F",
                ProfileId = ProfileIdTls,
                Message = "Certificate issued.",
                IssuedAt = new DateTime(2024, 6, 1, 0, 0, 0, DateTimeKind.Utc),
                ExpiresAt = new DateTime(2025, 6, 1, 0, 0, 0, DateTimeKind.Utc)
            };

        public static EnrollCertificateResponse PendingEnrollResponse(string id = null) =>
            new EnrollCertificateResponse
            {
                Id = id ?? CertId2,
                Status = "pending_approval",
                Certificate = null,
                ProfileId = ProfileIdTls,
                Message = "Awaiting approval."
            };

        // -----------------------------------------------------------------------
        // GetCertificate response (object helpers — used by Moq-based plugin tests)
        // These use the legacy inferred type (LegacyGetCertificateResponse).
        // -----------------------------------------------------------------------

        public static LegacyGetCertificateResponse IssuedCertRecord(string id = null) =>
            new LegacyGetCertificateResponse
            {
                Id = id ?? CertId1,
                Status = "issued",
                Certificate = FakePemCertificate,
                SerialNumber = "0A1B2C3D4E5F",
                Subject = "CN=test.example.com,O=Acme,C=US",
                ProfileId = ProfileIdTls,
                IssuedAt = new DateTime(2024, 6, 1, 0, 0, 0, DateTimeKind.Utc),
                ExpiresAt = new DateTime(2025, 6, 1, 0, 0, 0, DateTimeKind.Utc),
                Csr = FakeCsrPem
            };

        public static LegacyGetCertificateResponse RevokedCertRecord(string id = null) =>
            new LegacyGetCertificateResponse
            {
                Id = id ?? CertId3,
                Status = "revoked",
                Certificate = FakePemCertificate,
                SerialNumber = "AABBCCDD",
                Subject = "CN=revoked.example.com,O=Acme,C=US",
                ProfileId = ProfileIdTls,
                IssuedAt = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                ExpiresAt = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc),
                RevokedAt = new DateTime(2024, 3, 15, 0, 0, 0, DateTimeKind.Utc),
                RevocationReason = "keyCompromise"
            };

        // -----------------------------------------------------------------------
        // OAuth2
        // -----------------------------------------------------------------------

        public static string OAuth2TokenJson(int expiresIn = 3600) =>
            $@"{{""access_token"":""fake-bearer-token-abc123"",""token_type"":""Bearer"",""expires_in"":{expiresIn}}}";

        // -----------------------------------------------------------------------
        // Error responses
        // -----------------------------------------------------------------------

        public static string ServerErrorJson() =>
            @"{""error"":""INTERNAL_ERROR"",""message"":""An unexpected error occurred."",""statusCode"":500}";

        public static string UnauthorizedJson() =>
            @"{""error"":""UNAUTHORIZED"",""message"":""Invalid API key."",""statusCode"":401}";

        // -----------------------------------------------------------------------
        // Helpers
        // -----------------------------------------------------------------------

        private static string EscapeForJson(string s) =>
            s?.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r") ?? string.Empty;
    }
}
