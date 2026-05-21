// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0

using System;
using System.Collections.Generic;
using System.IO;
using Keyfactor.Extensions.CAPlugin.CERTInext;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Shared xUnit class fixture that loads live CERTInext credentials from
    /// ~/.env_certinext and constructs a real <see cref="CERTInextClient"/>.
    ///
    /// Tests should call <see cref="IntegrationSkip.IfNotConfigured"/> at the top
    /// of every test method so the test is skipped gracefully when credentials are
    /// absent (e.g. in CI environments that do not have access to the live API).
    /// </summary>
    public sealed class IntegrationTestFixture : IDisposable
    {
        // ---------------------------------------------------------------------------
        // Credential properties
        // ---------------------------------------------------------------------------

        public string ApiUrl { get; }
        public string AccessKey { get; }
        public string AccountNumber { get; }
        public string GroupNumber { get; }
        public string OrgNumber { get; }
        public string ProductCode { get; }
        public string RequestorEmail { get; }
        public string RequestorName { get; }

        // ---------------------------------------------------------------------------
        // Cloudflare DCV credentials (optional)
        // ---------------------------------------------------------------------------

        /// <summary>Cloudflare API token with DNS:Edit permission on <see cref="CloudflareZoneId"/>.</summary>
        public string CloudflareApiToken { get; }

        /// <summary>Cloudflare Zone ID for the domain used in DCV integration tests.</summary>
        public string CloudflareZoneId { get; }

        /// <summary>
        /// True when Cloudflare credentials are present, enabling real DNS DCV tests.
        /// When false, DCV integration tests fall back to a <see cref="StubDomainValidator"/>.
        /// </summary>
        public bool IsCloudflareConfigured { get; }

        /// <summary>
        /// True when at minimum ApiUrl and AccessKey are both non-empty,
        /// indicating that live credential configuration is present.
        /// </summary>
        public bool IsConfigured { get; }

        // ---------------------------------------------------------------------------
        // Live client
        // ---------------------------------------------------------------------------

        /// <summary>
        /// A fully-configured <see cref="CERTInextClient"/> ready for live API calls.
        /// Only valid when <see cref="IsConfigured"/> is true.
        /// </summary>
        public CERTInextClient Client { get; }

        /// <summary>
        /// The <see cref="CERTInextConfig"/> used to construct <see cref="Client"/>.
        /// Exposed so plugin smoke tests can pass it to the plugin test constructor.
        /// </summary>
        public CERTInextConfig Config { get; }

        // ---------------------------------------------------------------------------
        // Construction
        // ---------------------------------------------------------------------------

        public IntegrationTestFixture()
        {
            string envPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".env_certinext");

            var env = LoadEnvFile(envPath);

            // Promote env-file values into the process environment so that any code
            // calling System.Environment.GetEnvironmentVariable() picks them up.
            foreach (var kv in env)
                if (System.Environment.GetEnvironmentVariable(kv.Key) == null)
                    System.Environment.SetEnvironmentVariable(kv.Key, kv.Value);

            ApiUrl        = GetEnvValue(env, "CERTINEXT_API_URL");
            AccessKey     = GetEnvValue(env, "CERTINEXT_ACCESS_KEY");
            AccountNumber = GetEnvValue(env, "CERTINEXT_ACCOUNT_NUMBER");
            GroupNumber   = GetEnvValue(env, "CERTINEXT_GROUP_NUMBER");
            OrgNumber     = GetEnvValue(env, "CERTINEXT_ORG_NUMBER");
            ProductCode   = GetEnvValue(env, "CERTINEXT_PRODUCT_CODE");
            RequestorEmail = GetEnvValue(env, "CERTINEXT_REQUESTOR_EMAIL");
            RequestorName  = GetEnvValue(env, "CERTINEXT_REQUESTOR_NAME");

            CloudflareApiToken    = GetEnvValue(env, "CERTINEXT_CF_API_TOKEN");
            CloudflareZoneId      = GetEnvValue(env, "CERTINEXT_CF_ZONE_ID");
            IsCloudflareConfigured = !string.IsNullOrWhiteSpace(CloudflareApiToken) &&
                                     !string.IsNullOrWhiteSpace(CloudflareZoneId);

            IsConfigured = !string.IsNullOrWhiteSpace(ApiUrl) &&
                           !string.IsNullOrWhiteSpace(AccessKey);

            if (IsConfigured)
            {
                Config = new CERTInextConfig
                {
                    ApiUrl             = ApiUrl.TrimEnd('/') + "/",
                    AuthMode           = "AccessKey",
                    ApiKey             = AccessKey,
                    AccountNumber      = AccountNumber,
                    GroupNumber        = GroupNumber,
                    OrganizationNumber = OrgNumber,
                    RequestorName      = string.IsNullOrWhiteSpace(RequestorName)
                                             ? "Keyfactor Integration Test"
                                             : RequestorName,
                    RequestorEmail     = RequestorEmail,
                    RequestorIsdCode   = "1",
                    RequestorMobileNumber = "0000000000",
                    SignerPlace         = "Gateway",
                    SignerIp            = "127.0.0.1",
                    DefaultProductCode  = ProductCode,
                    PageSize            = 100
                };

                Client = new CERTInextClient(Config);
            }
        }

        public void Dispose() { }

        // ---------------------------------------------------------------------------
        // Private helpers
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Reads a KEY=VALUE file, stripping blank lines and lines starting with '#'.
        /// Real environment variables overlay the file so CI overrides always win.
        /// </summary>
        private static Dictionary<string, string> LoadEnvFile(string path)
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            if (File.Exists(path))
            {
                foreach (string rawLine in File.ReadAllLines(path))
                {
                    string line = rawLine.Trim();
                    if (string.IsNullOrEmpty(line) || line.StartsWith("#"))
                        continue;

                    int idx = line.IndexOf('=');
                    if (idx <= 0)
                        continue;

                    string key = line.Substring(0, idx).Trim();
                    string val = line.Substring(idx + 1).Trim();
                    result[key] = val;
                }
            }

            // Real environment variables take precedence over the file
            foreach (System.Collections.DictionaryEntry de in System.Environment.GetEnvironmentVariables())
            {
                string k = de.Key?.ToString();
                string v = de.Value?.ToString();
                if (!string.IsNullOrEmpty(k))
                    result[k] = v ?? string.Empty;
            }

            return result;
        }

        private static string GetEnvValue(Dictionary<string, string> env, string key)
        {
            return env.TryGetValue(key, out string val) ? val : string.Empty;
        }
    }
}
