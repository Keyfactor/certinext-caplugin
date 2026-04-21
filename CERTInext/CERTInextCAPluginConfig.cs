// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.Collections.Generic;
using System.Text.Json.Serialization;
using Keyfactor.AnyGateway.Extensions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext
{
    /// <summary>
    /// Provides the UI annotation metadata for all CA connector and enrollment template
    /// configuration fields shown in the Keyfactor Command console.
    /// </summary>
    public static class CERTInextCAPluginConfig
    {
        /// <summary>
        /// Returns the annotation metadata for all CA connector-level configuration fields.
        /// These appear in the Command UI when an administrator sets up the CA connector.
        /// </summary>
        public static Dictionary<string, PropertyConfigInfo> GetCAConnectorAnnotations()
        {
            return new Dictionary<string, PropertyConfigInfo>
            {
                [Constants.Config.ApiUrl] = new PropertyConfigInfo
                {
                    Comments = "REQUIRED: CERTInext API base URL. " +
                               "Sandbox (US): https://sandbox-us-api.certinext.io/emSignHub-API/ — " +
                               "Production (US): https://us-api.certinext.io/ — " +
                               "Production (Global/India): https://api.certinext.io/",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.AccountNumber] = new PropertyConfigInfo
                {
                    Comments = "REQUIRED: Your CERTInext account number (numeric string). " +
                               "Available in the CERTInext portal.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.AuthMode] = new PropertyConfigInfo
                {
                    Comments = "REQUIRED: Authentication mode. " +
                               "'AccessKey' (default) — uses authKey = SHA256(accessKey + ts + txn) in every request body. " +
                               "'OAuth' — uses an OAuth2 bearer token (requires OAuthTokenUrl, OAuthClientId, OAuthClientSecret).",
                    Hidden = false,
                    DefaultValue = Constants.Config.AuthModeAccessKey,
                    Type = "String"
                },
                [Constants.Config.ApiKey] = new PropertyConfigInfo
                {
                    Comments = "REQUIRED when AuthMode is 'AccessKey': the REST API Access Key generated in the " +
                               "CERTInext portal under Integrations → APIs. " +
                               "This value is used to compute authKey = SHA256(accessKey + ts + txn); " +
                               "it is never transmitted directly.",
                    Hidden = true,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.OAuth2TokenUrl] = new PropertyConfigInfo
                {
                    Comments = "OAuth token endpoint URL. Required when AuthMode is 'OAuth'.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.OAuth2ClientId] = new PropertyConfigInfo
                {
                    Comments = "OAuth client ID. Required when AuthMode is 'OAuth'.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.OAuth2ClientSecret] = new PropertyConfigInfo
                {
                    Comments = "OAuth client secret. Required when AuthMode is 'OAuth'.",
                    Hidden = true,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.RequestorName] = new PropertyConfigInfo
                {
                    Comments = "REQUIRED: Default requestor name submitted with all certificate orders. " +
                               "This is the name of the person/service responsible for the certificates.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.RequestorEmail] = new PropertyConfigInfo
                {
                    Comments = "REQUIRED: Default requestor email submitted with all certificate orders. " +
                               "Must be a valid email address registered in your CERTInext account.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.RequestorIsdCode] = new PropertyConfigInfo
                {
                    Comments = "International dialing code for the requestor phone number (e.g. '1' for US). Default: '1'.",
                    Hidden = false,
                    DefaultValue = "1",
                    Type = "String"
                },
                [Constants.Config.RequestorMobileNumber] = new PropertyConfigInfo
                {
                    Comments = "Requestor mobile number (digits only, no country code).",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                ["SignerPlace"] = new PropertyConfigInfo
                {
                    Comments = "City or location of the subscriber agreement signer. Required by CERTInext for all orders.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                ["SignerIp"] = new PropertyConfigInfo
                {
                    Comments = "IP address of the subscriber agreement signer. Required by CERTInext for all orders.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                ["DefaultProductCode"] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Default numeric product code used when not specified at template level. " +
                               "Product codes are provided by eMudhra (e.g. the SSL DV 1-year code for your account). " +
                               "Retrieve available codes from Integrations → APIs → GetProductDetails.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.Config.IgnoreExpired] = new PropertyConfigInfo
                {
                    Comments = "If true, expired certificates will be skipped during synchronization. Default: false.",
                    Hidden = false,
                    DefaultValue = false,
                    Type = "Boolean"
                },
                [Constants.Config.PageSize] = new PropertyConfigInfo
                {
                    Comments = "Number of orders to fetch per page during synchronization. " +
                               $"Default: {Constants.Api.DefaultPageSize}, max: {Constants.Api.MaxPageSize}.",
                    Hidden = false,
                    DefaultValue = Constants.Api.DefaultPageSize,
                    Type = "Number"
                },
                [Constants.Config.Enabled] = new PropertyConfigInfo
                {
                    Comments = "Flag to Enable or Disable gateway functionality. Disabling is primarily used to allow " +
                               "creation of the CA connector prior to configuration information being available.",
                    Hidden = false,
                    DefaultValue = true,
                    Type = "Boolean"
                }
            };
        }

        /// <summary>
        /// Returns the annotation metadata for all per-template enrollment parameters.
        /// These appear in the Command UI when an administrator configures a certificate template.
        /// </summary>
        public static Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
        {
            return new Dictionary<string, PropertyConfigInfo>
            {
                [Constants.EnrollmentParam.ProductCode] = new PropertyConfigInfo
                {
                    Comments = "REQUIRED: The numeric CERTInext product code for this certificate type " +
                               "(e.g. '844' for DV SSL 1-year). Provided by eMudhra for your account. " +
                               "Overrides the connector-level DefaultProductCode when set.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.EnrollmentParam.ProfileId] = new PropertyConfigInfo
                {
                    Comments = "DEPRECATED: Use ProductCode instead. " +
                               "Kept for backward compatibility — mapped to ProductCode if ProductCode is not set.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.EnrollmentParam.ValidityYears] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Subscription validity in years: 1, 2, or 3. Default: 1. " +
                               "Note: CERTInext validates per 390-day certificate within the subscription; " +
                               "the 'validity' field in the order is the subscription term, not certificate lifetime.",
                    Hidden = false,
                    DefaultValue = 1,
                    Type = "Number"
                },
                [Constants.EnrollmentParam.ValidityDays] = new PropertyConfigInfo
                {
                    Comments = "DEPRECATED: Use ValidityYears instead. " +
                               "If set, value is divided by 365 and rounded up to get the subscription year count.",
                    Hidden = false,
                    DefaultValue = 365,
                    Type = "Number"
                },
                [Constants.EnrollmentParam.AutoApprove] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: If true, the gateway will attempt automatic approval of certificates " +
                               "that are returned in a pending-approval state. Default: false.",
                    Hidden = false,
                    DefaultValue = false,
                    Type = "Boolean"
                },
                [Constants.EnrollmentParam.RequesterName] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Default requester name to include in the enrollment request. " +
                               "Used when no requester name can be derived from the subject.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.EnrollmentParam.RequesterEmail] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Default requester email address. " +
                               "Used when no email can be derived from the subject.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                },
                [Constants.EnrollmentParam.RenewalWindowDays] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Number of days before expiration within which a renewal is attempted " +
                               "instead of a reissue. Default: 90.",
                    Hidden = false,
                    DefaultValue = 90,
                    Type = "Number"
                },
                [Constants.EnrollmentParam.KeyType] = new PropertyConfigInfo
                {
                    Comments = "OPTIONAL: Key algorithm to request (e.g. 'RSA2048', 'RSA4096', 'EC256', 'EC384'). " +
                               "If omitted, the profile default is used.",
                    Hidden = false,
                    DefaultValue = string.Empty,
                    Type = "String"
                }
            };
        }
    }

    /// <summary>
    /// Strongly-typed configuration object deserialized from the CA connector's
    /// <see cref="IAnyCAPluginConfigProvider.CAConnectionData"/> dictionary.
    /// </summary>
    public class CERTInextConfig
    {
        // -----------------------------------------------------------------------
        // Required
        // -----------------------------------------------------------------------

        /// <summary>
        /// CERTInext API base URL, e.g. "https://us-api.certinext.io/emSignHub-API/".
        /// Must end with a trailing slash or the endpoint path segment.
        /// </summary>
        [JsonPropertyName("ApiUrl")]
        public string ApiUrl { get; set; } = string.Empty;

        /// <summary>
        /// CERTInext account number (numeric string) used in every request meta block.
        /// </summary>
        [JsonPropertyName("AccountNumber")]
        public string AccountNumber { get; set; } = string.Empty;

        // -----------------------------------------------------------------------
        // Authentication
        // -----------------------------------------------------------------------

        /// <summary>
        /// Authentication mode: "AccessKey" (default) or "OAuth".
        /// </summary>
        [JsonPropertyName("AuthMode")]
        public string AuthMode { get; set; } = Constants.Config.AuthModeAccessKey;

        /// <summary>
        /// Raw REST API Access Key generated in CERTInext portal (Integrations → APIs).
        /// Used to compute authKey = SHA256(accessKey + ts + txn).
        /// Required when AuthMode is "AccessKey".
        /// NEVER logged or transmitted directly — only the derived authKey is sent.
        /// </summary>
        [JsonPropertyName("ApiKey")]
        public string ApiKey { get; set; } = string.Empty;

        /// <summary>OAuth token endpoint URL. Required when AuthMode is "OAuth".</summary>
        [JsonPropertyName("OAuthTokenUrl")]
        public string OAuthTokenUrl { get; set; } = string.Empty;

        /// <summary>OAuth client ID. Required when AuthMode is "OAuth".</summary>
        [JsonPropertyName("OAuthClientId")]
        public string OAuthClientId { get; set; } = string.Empty;

        /// <summary>OAuth client secret. Required when AuthMode is "OAuth".</summary>
        [JsonPropertyName("OAuthClientSecret")]
        public string OAuthClientSecret { get; set; } = string.Empty;

        // Legacy OAuth2 property aliases (kept for JSON round-trip compat)
        [JsonPropertyName("OAuth2TokenUrl")]
        public string OAuth2TokenUrl { get => OAuthTokenUrl; set => OAuthTokenUrl = value; }
        [JsonPropertyName("OAuth2ClientId")]
        public string OAuth2ClientId { get => OAuthClientId; set => OAuthClientId = value; }
        [JsonPropertyName("OAuth2ClientSecret")]
        public string OAuth2ClientSecret { get => OAuthClientSecret; set => OAuthClientSecret = value; }

        // Unused legacy fields — retained so existing config snapshots deserialize cleanly
        [JsonPropertyName("Username")]
        public string Username { get; set; } = string.Empty;
        [JsonPropertyName("Password")]
        public string Password { get; set; } = string.Empty;

        // -----------------------------------------------------------------------
        // Requestor defaults — injected into order requests when not overridden
        // by template parameters
        // -----------------------------------------------------------------------

        /// <summary>Default requestor name sent with all orders.</summary>
        [JsonPropertyName("RequestorName")]
        public string RequestorName { get; set; } = string.Empty;

        /// <summary>Default requestor email sent with all orders.</summary>
        [JsonPropertyName("RequestorEmail")]
        public string RequestorEmail { get; set; } = string.Empty;

        /// <summary>Default ISD (country) code for requestor phone. Default "1" (US).</summary>
        [JsonPropertyName("RequestorIsdCode")]
        public string RequestorIsdCode { get; set; } = "1";

        /// <summary>Default requestor mobile number.</summary>
        [JsonPropertyName("RequestorMobileNumber")]
        public string RequestorMobileNumber { get; set; } = string.Empty;

        /// <summary>Subscriber agreement signer place (city/location). Required by CERTInext.</summary>
        [JsonPropertyName("SignerPlace")]
        public string SignerPlace { get; set; } = string.Empty;

        /// <summary>Subscriber agreement signer IP address. Required by CERTInext.</summary>
        [JsonPropertyName("SignerIp")]
        public string SignerIp { get; set; } = string.Empty;

        /// <summary>
        /// Default product code used when the template-level ProductCode is not specified.
        /// Product codes are numeric strings provided by eMudhra (e.g. "844" for DV SSL 1-year).
        /// </summary>
        [JsonPropertyName("DefaultProductCode")]
        public string DefaultProductCode { get; set; } = string.Empty;

        // -----------------------------------------------------------------------
        // Sync / behaviour
        // -----------------------------------------------------------------------

        [JsonPropertyName("IgnoreExpired")]
        public bool IgnoreExpired { get; set; } = false;

        [JsonPropertyName("PageSize")]
        public int PageSize { get; set; } = Constants.Api.DefaultPageSize;

        [JsonPropertyName("Enabled")]
        public bool Enabled { get; set; } = true;
    }
}
