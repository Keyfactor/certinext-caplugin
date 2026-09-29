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
        // Opt-in guard
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Env-var keys that must be set explicitly in the shell and must NOT be
        /// auto-promoted from the env file.  These gate destructive or mutating tests
        /// so a developer cannot accidentally arm them by leaving flags in ~/.env_certinext.
        /// </summary>
        private static readonly System.Collections.Generic.HashSet<string> _optInOnlyFlags =
            new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "CERTINEXT_COMPLETE_PENDING",
                "CERTINEXT_RUN_BULK_TEST",
                "CERTINEXT_V2_RUN_BULK_TEST",
            };

        // ---------------------------------------------------------------------------
        // V1 env keys
        // ---------------------------------------------------------------------------

        internal const string ApiUrlKey             = "CERTINEXT_API_URL";
        internal const string AccessKeyKey          = "CERTINEXT_ACCESS_KEY";
        internal const string AccountNumberKey      = "CERTINEXT_ACCOUNT_NUMBER";
        internal const string GroupNumberKey        = "CERTINEXT_GROUP_NUMBER";
        internal const string OrgNumberKey          = "CERTINEXT_ORG_NUMBER";
        internal const string ProductCodeKey        = "CERTINEXT_PRODUCT_CODE";
        internal const string RequestorEmailKey     = "CERTINEXT_REQUESTOR_EMAIL";
        internal const string RequestorNameKey      = "CERTINEXT_REQUESTOR_NAME";
        internal const string CloudflareApiTokenKey = "CERTINEXT_CF_API_TOKEN";
        internal const string CloudflareZoneIdKey   = "CERTINEXT_CF_ZONE_ID";

        /// <summary>
        /// Path segment every V1 (<c>emSignHub-API</c>) base URL carries. A resolved
        /// <see cref="ApiUrl"/> without it is almost always the V2 base URL from
        /// <c>~/.env_certinext_v2</c> (issue 0017).
        /// </summary>
        internal const string V1ApiPathSegment = "/emSignHub-API";

        /// <summary>
        /// Every env key the V1 side of the harness reads: the keys this fixture resolves, plus
        /// <c>CERTINEXT_DCV_DOMAIN</c>, which V1 <c>DcvLifecycleTests</c> reads straight from
        /// process env. <see cref="V2EnvHelper.LoadAndPromote"/> must never write these into
        /// process env, because real env vars take precedence over <c>~/.env_certinext</c> here
        /// and the V2 file defines the same names with V2 values (issue 0017).
        /// </summary>
        internal static readonly IReadOnlySet<string> V1EnvKeys =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ApiUrlKey,
                AccessKeyKey,
                AccountNumberKey,
                GroupNumberKey,
                OrgNumberKey,
                ProductCodeKey,
                RequestorEmailKey,
                RequestorNameKey,
                CloudflareApiTokenKey,
                CloudflareZoneIdKey,
                "CERTINEXT_DCV_DOMAIN",
            };

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

            ApiUrl        = GetEnvValue(env, ApiUrlKey);
            AccessKey     = GetEnvValue(env, AccessKeyKey);
            AccountNumber = GetEnvValue(env, AccountNumberKey);
            GroupNumber   = GetEnvValue(env, GroupNumberKey);
            OrgNumber     = GetEnvValue(env, OrgNumberKey);
            ProductCode   = GetEnvValue(env, ProductCodeKey);
            RequestorEmail = GetEnvValue(env, RequestorEmailKey);
            RequestorName  = GetEnvValue(env, RequestorNameKey);

            CloudflareApiToken    = GetEnvValue(env, CloudflareApiTokenKey);
            CloudflareZoneId      = GetEnvValue(env, CloudflareZoneIdKey);
            IsCloudflareConfigured = !string.IsNullOrWhiteSpace(CloudflareApiToken) &&
                                     !string.IsNullOrWhiteSpace(CloudflareZoneId);

            IsConfigured = !string.IsNullOrWhiteSpace(ApiUrl) &&
                           !string.IsNullOrWhiteSpace(AccessKey);

            // Issue 0017: fail fast (before promoting anything into process env and before any
            // client/network call) when a V2 base URL has leaked into the V1 fixture. Only
            // checked when the fixture would otherwise be configured, so an unconfigured run
            // still skips cleanly.
            if (IsConfigured)
                EnsureV1ApiUrl(ApiUrl,
                    fromProcessEnvironment: System.Environment.GetEnvironmentVariable(ApiUrlKey) != null);

            // Promote env-file values into the process environment so that any code
            // calling System.Environment.GetEnvironmentVariable() picks them up.
            // Opt-in destructive-test flags are deliberately excluded: they must be
            // set explicitly in the shell so a developer who leaves them in the file
            // does not accidentally arm bulk/mutating tests on every bare `dotnet test`.
            foreach (var kv in env)
                if (System.Environment.GetEnvironmentVariable(kv.Key) == null
                    && !_optInOnlyFlags.Contains(kv.Key))
                    System.Environment.SetEnvironmentVariable(kv.Key, kv.Value);

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
        /// <paramref name="processEnvironment"/> defaults to the real process environment; unit
        /// tests pass their own so they never have to mutate shared process state.
        /// </summary>
        internal static Dictionary<string, string> LoadEnvFile(
            string path, System.Collections.IDictionary processEnvironment = null)
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
                    string val = ParseEnvValue(line.Substring(idx + 1));
                    result[key] = val;
                }
            }

            // Real environment variables take precedence over the file
            foreach (System.Collections.DictionaryEntry de in
                     processEnvironment ?? System.Environment.GetEnvironmentVariables())
            {
                string k = de.Key?.ToString();
                string v = de.Value?.ToString();
                if (!string.IsNullOrEmpty(k))
                    result[k] = v ?? string.Empty;
            }

            return result;
        }

        /// <summary>
        /// Parses a raw value from a <c>KEY=VALUE</c> env-file line: trims surrounding
        /// whitespace, then strips a single pair of matching surrounding double or single
        /// quotes if present.  Without quote stripping a line like
        /// <c>CERTINEXT_REQUESTOR_NAME="Keyfactor Plugin Test"</c> would parse as the 24-char
        /// literal <c>"Keyfactor Plugin Test"</c> (quotes included), diverging from any
        /// other shell-style env consumer reading the same file.  See GitHub issue #8.
        /// Exposed <c>internal</c> for direct unit-testing.
        /// </summary>
        internal static string ParseEnvValue(string rawValue)
        {
            if (rawValue is null) return string.Empty;
            string val = rawValue.Trim();
            if (val.Length >= 2 &&
                ((val[0] == '"' && val[val.Length - 1] == '"') ||
                 (val[0] == '\'' && val[val.Length - 1] == '\'')))
            {
                val = val.Substring(1, val.Length - 2);
            }
            return val;
        }

        /// <summary>
        /// Throws <see cref="InvalidOperationException"/> when <paramref name="apiUrl"/> lacks
        /// the V1 <see cref="V1ApiPathSegment"/>, i.e. a V2 base URL has leaked into the V1
        /// fixture (issue 0017). Left unchecked, every V1 call 404s and surfaces as the
        /// misleading "unrecognised error body" (issue 0044). The message names the key and
        /// where it came from, and shows only scheme/host/path — never credentials, userinfo,
        /// or query strings. Exposed <c>internal</c> for direct unit-testing.
        /// </summary>
        internal static void EnsureV1ApiUrl(string apiUrl, bool fromProcessEnvironment)
        {
            if (string.IsNullOrWhiteSpace(apiUrl) ||
                apiUrl.IndexOf(V1ApiPathSegment, StringComparison.OrdinalIgnoreCase) >= 0)
                return;

            string shown = Uri.TryCreate(apiUrl.Trim(), UriKind.Absolute, out Uri uri)
                ? $"{uri.Scheme}://{uri.Authority}{uri.AbsolutePath}"
                : "(not an absolute URL)";
            string source = fromProcessEnvironment
                ? "the process environment (real env vars override ~/.env_certinext)"
                : "~/.env_certinext";

            throw new InvalidOperationException(
                $"IntegrationTestFixture: {ApiUrlKey} resolved to '{shown}' (from {source}), which lacks " +
                $"the V1 path segment '{V1ApiPathSegment}'. This looks like a CERTInext V2 base URL leaking " +
                "into the V1 fixture (issue 0017); V1 calls against it fail with 'unrecognised error body'. " +
                "Source only ~/.env_certinext into the shell (set -a; . ~/.env_certinext; set +a), never " +
                "~/.env_certinext_v2 — the V2 tests read that file from disk themselves. In an already-" +
                $"polluted shell, run 'unset {ApiUrlKey}' or open a fresh shell.");
        }

        private static string GetEnvValue(Dictionary<string, string> env, string key)
        {
            return env.TryGetValue(key, out string val) ? val : string.Empty;
        }
    }
}
