// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.Extensions.CAPlugin.CERTInext.Models;
using Keyfactor.Logging;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
#if SUPPORTS_DCV
using IDomainValidatorFactory = Keyfactor.AnyGateway.Extensions.IDomainValidatorFactory;
#endif

namespace Keyfactor.Extensions.CAPlugin.CERTInext
{
    /// <summary>
    /// Keyfactor AnyCA REST Gateway plugin for CERTInext (eMudhra).
    /// Implements <see cref="IAnyCAPlugin"/> to route Keyfactor Command certificate
    /// lifecycle operations through the CERTInext REST API.
    /// </summary>
    public class CERTInextCAPlugin : IAnyCAPlugin, IDisposable
    {
        private readonly ILogger _logger = LogHandler.GetClassLogger<CERTInextCAPlugin>();

        private CERTInextConfig _config;
        private ICERTInextClient _client;
        private ICertificateDataReader _certificateDataReader;
        // Typed as `object` — NOT `IDomainValidatorFactory` — so the .NET JIT does not
        // eagerly resolve the v3.3-only IDomainValidatorFactory type when it compiles
        // any method on this class.  Resolving an instance field's declared type is
        // part of the JIT's per-class metadata load, distinct from constructor-signature
        // reflection (which we already protected in the issue #7 first pass).  On a
        // gateway host whose IAnyCAPlugin assembly is v3.2.0.0 (no IDomainValidatorFactory),
        // declaring the field with the missing type causes TypeLoadException the first
        // time ANY instance method on the class is compiled — typically Initialize.
        //
        // Reads of this field perform an `as IDomainValidatorFactory` cast inside method
        // bodies (see DomainValidatorFactory below).  Casts in method bodies are JIT-lazy
        // per-method, so the type is only resolved on hosts that actually have it.
        //
        // `volatile` because the field is written by SetDomainValidatorFactory and read
        // by EnrollNewAsync / TryRunDcvDuringSyncAsync, which can run on different threads.
        // See GitHub issue #7 for the full reasoning.
        // On the no-DCV build (IAnyCAPlugin 3.2.0, SUPPORTS_DCV undefined) this field is
        // intentionally never assigned — its assignment sites (the factory ctor and
        // SetDomainValidatorFactory) are fenced out, so it stays null and the Initialize
        // DCV-wiring check reports "not wired". Suppress CS0649 for that case; on the
        // SUPPORTS_DCV build it is assigned normally and the pragma is a no-op.
#pragma warning disable CS0649
        private volatile object _domainValidatorFactory;
#pragma warning restore CS0649

        /// <summary>
        /// Returns the injected <see cref="IDomainValidatorFactory"/> when one is
        /// available, or <c>null</c> when DCV is not wired up.  The cast is inside this
        /// property body (and therefore JIT-lazy) so the missing-type case on a v3.2
        /// gateway host stays compileable and never triggers <c>TypeLoadException</c>
        /// at runtime.  All read sites in this class go through this property.
        /// </summary>
#if SUPPORTS_DCV
        private IDomainValidatorFactory DomainValidatorFactory =>
            _domainValidatorFactory as IDomainValidatorFactory;
#endif

        // True when the client was passed in via a test-injection constructor and therefore
        // should not be disposed by this class (the test owns the mock's lifetime).
        private bool _clientWasInjected;

        // Guards against concurrent DCV attempts on the same order — two overlapping sync
        // cycles, or a sync overlapping with a GetSingleRecord refresh, must not both try
        // to stage TXT records for the same order. The value byte is unused; this is a set.
        private readonly ConcurrentDictionary<string, byte> _dcvInFlight = new();

        // ---------------------------------------------------------------------------
        // Constructors
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Production constructor — the only public constructor the gateway DI container
        /// sees. Deliberately parameterless to ensure plugin load succeeds on gateway
        /// versions whose <c>Keyfactor.AnyGateway.IAnyCAPlugin</c> assembly does not
        /// contain <see cref="IDomainValidatorFactory"/> (e.g. 25.4.0 ships v3.2.0.0).
        ///
        /// If the host gateway exposes an <see cref="IDomainValidatorFactory"/> instance
        /// it should be injected via <see cref="SetDomainValidatorFactory"/> after
        /// construction.  When no factory is provided, DCV silently no-ops and orders
        /// are returned in their pending state for the gateway to advance on the next
        /// sync cycle.
        ///
        /// See <see href="https://github.com/Keyfactor/certinext-caplugin/issues/7"/>.
        /// </summary>
        public CERTInextCAPlugin() { }

        /// <summary>
        /// Internal constructor used by unit and integration tests to inject a mock
        /// <see cref="ICERTInextClient"/> and bypass network I/O.  A default
        /// <see cref="CERTInextConfig"/> is supplied so callers that don't invoke
        /// <see cref="Initialize"/> can still read <c>_config</c>.
        /// </summary>
        internal CERTInextCAPlugin(ICERTInextClient client)
        {
            _client = client;
            _clientWasInjected = true;
            _config = new CERTInextConfig();
        }

        /// <summary>
        /// Internal test-injection constructor — pass a mock <see cref="ICERTInextClient"/>
        /// and a mock <see cref="ICertificateDataReader"/> for tests that exercise
        /// RenewOrReissue logic that reads prior certificate data from Command's database.
        /// </summary>
        internal CERTInextCAPlugin(ICERTInextClient client, ICertificateDataReader certDataReader)
        {
            _client = client;
            _clientWasInjected = true;
            _certificateDataReader = certDataReader;
            _config = new CERTInextConfig();
        }

        /// <summary>
        /// Internal test-injection constructor — pass a mock <see cref="ICERTInextClient"/>
        /// and a specific <see cref="CERTInextConfig"/> for tests that need to override
        /// configuration fields such as <c>IgnoreExpired</c>.
        /// </summary>
        internal CERTInextCAPlugin(ICERTInextClient client, CERTInextConfig config)
        {
            _client = client;
            _clientWasInjected = true;
            _config = config ?? new CERTInextConfig();
        }

        /// <summary>
        /// Internal test-injection constructor — pass a mock client, a domain validator
        /// factory, and an optional config for unit-testing the DCV orchestration path.
        ///
        /// This constructor is <c>internal</c> (rather than <c>public</c>) because the
        /// gateway DI container's constructor-discovery reflection on a v3.2 host would
        /// trip <see cref="IDomainValidatorFactory"/>'s missing-type load if this signature
        /// were exposed publicly.  Tests in <c>CERTInext.Tests</c> /
        /// <c>CERTInext.IntegrationTests</c> can still reach it via
        /// <c>[InternalsVisibleTo]</c>.  See issue #7.
        /// </summary>
#if SUPPORTS_DCV
        internal CERTInextCAPlugin(ICERTInextClient client, IDomainValidatorFactory domainValidatorFactory, CERTInextConfig config = null)
        {
            _client = client;
            _clientWasInjected = true;
            _domainValidatorFactory = domainValidatorFactory;
            _config = config ?? new CERTInextConfig();
        }
#endif

        /// <summary>
        /// Injects an <see cref="IDomainValidatorFactory"/> after construction.  Intended
        /// for gateway hosts that can resolve the factory from their own service container
        /// and want DCV enabled — they should call this between <c>new CERTInextCAPlugin()</c>
        /// and <see cref="Initialize"/>.
        ///
        /// Accepts <see cref="object"/> rather than <see cref="IDomainValidatorFactory"/>
        /// so the public method signature does not pull the v3.3-only type into the type's
        /// reflection surface on older gateways.  When the supplied value is not an
        /// <see cref="IDomainValidatorFactory"/>, DCV is left disabled.
        /// </summary>
        public void SetDomainValidatorFactory(object factory)
        {
#if SUPPORTS_DCV
            var typed = factory as IDomainValidatorFactory;
            // SOX change-management / SOC2 CC6.1: log every factory injection so an auditor
            // can confirm which DNS provider plugin is being used to publish TXT records.
            // A bad-faith host could otherwise swap the factory mid-lifecycle with no trail.
            // We deliberately do NOT log the factory instance itself — only its type — to
            // avoid serialising any state it may carry.
            _logger.LogInformation(
                "Domain validator factory set on CERTInext plugin. " +
                "OfferedType={OfferedType}, Accepted={Accepted}",
                factory?.GetType().FullName ?? "(null)", typed != null);
            _domainValidatorFactory = typed;
#else
            // DCV is not supported on this build (IAnyCAPlugin 3.2.0 — no IDomainValidatorFactory).
            // Accept the call for host compatibility but leave DCV disabled. See issue 0003.
            _logger.LogInformation(
                "Domain validator factory offered but DCV is not supported on this build " +
                "(IAnyCAPlugin 3.2.0). OfferedType={OfferedType}",
                factory?.GetType().FullName ?? "(null)");
#endif
        }

        // ---------------------------------------------------------------------------
        // IDisposable
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Disposes the underlying client if it was created by <see cref="Initialize"/>
        /// (not injected via a test constructor). Injected mocks are owned by the caller.
        /// </summary>
        public void Dispose()
        {
            if (!_clientWasInjected)
                (_client as IDisposable)?.Dispose();
        }

        // ---------------------------------------------------------------------------
        // IAnyCAPlugin — Lifecycle
        // ---------------------------------------------------------------------------

        /// <summary>
        /// Called once at gateway startup.  Deserializes the CA connector configuration
        /// and initialises the HTTP client.
        /// </summary>
        public void Initialize(IAnyCAPluginConfigProvider configProvider, ICertificateDataReader certificateDataReader)
        {
            _logger.MethodEntry(LogLevel.Debug);

            _certificateDataReader = certificateDataReader;

            string rawConfig = JsonSerializer.Serialize(configProvider.CAConnectionData);
            _config = JsonSerializer.Deserialize<CERTInextConfig>(rawConfig)
                ?? throw new InvalidOperationException("Failed to deserialize CERTInext plugin configuration.");

            // Only create a real client if one wasn't injected (test scenario)
            _client ??= new CERTInextClient(_config);

            // SOX change-management: log which credential fields are populated (never their values)
            // so an auditor can detect configuration changes between restarts.
            bool hasApiKey      = !string.IsNullOrWhiteSpace(_config.ApiKey);
            bool hasUsername    = !string.IsNullOrWhiteSpace(_config.Username);
            bool hasPassword    = !string.IsNullOrWhiteSpace(_config.Password);
            bool hasClientId    = !string.IsNullOrWhiteSpace(_config.OAuth2ClientId);
            bool hasClientSecret= !string.IsNullOrWhiteSpace(_config.OAuth2ClientSecret);
            bool hasTokenUrl    = !string.IsNullOrWhiteSpace(_config.OAuth2TokenUrl);

            _logger.LogInformation(
                "CERTInext plugin initialized. " +
                "ApiUrl={ApiUrl}, AuthMode={AuthMode}, Enabled={Enabled}, " +
                "ApiKeyPresent={ApiKeyPresent}, UsernamePresent={UsernamePresent}, " +
                "PasswordPresent={PasswordPresent}, OAuth2ClientIdPresent={OAuth2ClientIdPresent}, " +
                "OAuth2ClientSecretPresent={OAuth2ClientSecretPresent}, OAuth2TokenUrlPresent={OAuth2TokenUrlPresent}, " +
                "PageSize={PageSize}, IgnoreExpired={IgnoreExpired}, " +
                "DcvEnabled={DcvEnabled}, DcvTxtRecordTemplate={DcvTxtRecordTemplate}, " +
                "DomainValidatorFactoryInjected={FactoryInjected}",
                _config.ApiUrl, _config.AuthMode, _config.Enabled,
                hasApiKey, hasUsername,
                hasPassword, hasClientId,
                hasClientSecret, hasTokenUrl,
                _config.PageSize, _config.IgnoreExpired,
                _config.DcvEnabled, _config.DcvTxtRecordTemplate,
                _domainValidatorFactory != null);

            // SOC2 CC7.1: surface silent functional downgrades. If DCV is enabled in
            // config but no factory was injected (e.g. v3.2 gateway host), DCV will be
            // skipped at runtime. The operator should know that on every restart.
            if (_config.DcvEnabled && _domainValidatorFactory == null)
            {
                _logger.LogWarning(
                    "DcvEnabled=true but no IDomainValidatorFactory has been injected — " +
                    "DCV will be silently skipped for every enrollment. This usually means the " +
                    "gateway host is on a release that does not provide IDomainValidatorFactory " +
                    "(see GitHub issue #7). Install a DNS provider plugin and upgrade to a " +
                    "gateway image that supplies the factory, or set DcvEnabled=false to clear " +
                    "this warning.");
            }
            _logger.MethodExit(LogLevel.Debug);
        }

        // ---------------------------------------------------------------------------
        // IAnyCAPlugin — Metadata
        // ---------------------------------------------------------------------------

        /// <inheritdoc/>
        public Dictionary<string, PropertyConfigInfo> GetCAConnectorAnnotations()
            => CERTInextCAPluginConfig.GetCAConnectorAnnotations();

        /// <inheritdoc/>
        public Dictionary<string, PropertyConfigInfo> GetTemplateParameterAnnotations()
            => CERTInextCAPluginConfig.GetTemplateParameterAnnotations();

        /// <inheritdoc/>
        public List<string> GetProductIds()
        {
            // The product list is a static constant rather than a live API call because:
            // 1. IAnyCAPlugin.GetProductIds() is synchronous — calling GetAwaiter().GetResult()
            //    on GetProductDetailsAsync would risk deadlock in certain synchronization contexts.
            // 2. The Keyfactor integration-manifest doc tool requires a known list at reflection
            //    time (a live API call at that point returned empty results).
            // 3. CERTInext product names are stable; operators select the correct product and
            //    then provide the numeric ProductCode template parameter to map it to the actual
            //    CERTInext API code for their account (sandbox vs. production).
            return new List<string>
            {
                Constants.Products.DvSsl,
                Constants.Products.DvSslWildcard,
                Constants.Products.DvSslUcc,
                Constants.Products.DvSslWildcardUcc,
                Constants.Products.OvSsl,
                Constants.Products.OvSslWildcard,
                Constants.Products.OvSslUcc,
                Constants.Products.OvSslWildcardUcc,
                Constants.Products.EvSsl,
                Constants.Products.EvSslUcc,
            };
        }

        // ---------------------------------------------------------------------------
        // IAnyCAPlugin — Health and validation
        // ---------------------------------------------------------------------------

        /// <inheritdoc/>
        public async Task Ping()
        {
            _logger.MethodEntry(LogLevel.Debug);

            if (!_config.Enabled)
            {
                _logger.LogWarning("CERTInext connector is disabled — skipping connectivity test.");
                _logger.MethodExit(LogLevel.Debug);
                return;
            }

            try
            {
                await _client.PingAsync();
                // SOC2 CC9.2: connectivity confirmation is a security-relevant event; must be
                // at Information so it survives production log filters.
                _logger.LogInformation("CERTInext ping successful. ApiUrl={ApiUrl}", _config.ApiUrl);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "CERTInext ping failed. ApiUrl={ApiUrl}", _config.ApiUrl);
                throw new Exception($"Unable to reach CERTInext at {_config.ApiUrl}: {ex.Message}", ex);
            }
            finally
            {
                _logger.MethodExit(LogLevel.Debug);
            }
        }

        /// <inheritdoc/>
        public async Task ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
        {
            _logger.MethodEntry(LogLevel.Debug);

            // SOX CC6.1 / SOC2 CC6.1: log the access attempt so that every configuration
            // change event is traceable in the audit trail.
            string attemptedApiUrl  = GetStringValue(connectionInfo, Constants.Config.ApiUrl);
            string attemptedAuthMode = GetStringValue(connectionInfo, Constants.Config.AuthMode, Constants.Config.AuthModeApiKey);
            _logger.LogInformation(
                "CA connection validation attempt started. ApiUrl={ApiUrl}, AuthMode={AuthMode}",
                attemptedApiUrl, attemptedAuthMode);

            // If the connector is explicitly disabled, skip all validation to allow
            // the CA record to be saved before credentials are available.
            if (connectionInfo.TryGetValue(Constants.Config.Enabled, out object enabledObj)
                && enabledObj is bool enabled && !enabled)
            {
                _logger.LogWarning(
                    "CA connection validation skipped — connector is disabled. ApiUrl={ApiUrl}",
                    attemptedApiUrl);
                _logger.MethodExit(LogLevel.Debug);
                return;
            }

            var errors = new List<string>();

            // ApiUrl and AccountNumber are always required
            string apiUrl = GetStringValue(connectionInfo, Constants.Config.ApiUrl);
            if (string.IsNullOrWhiteSpace(apiUrl))
                errors.Add($"'{Constants.Config.ApiUrl}' is required.");
            else if (!Uri.TryCreate(apiUrl, UriKind.Absolute, out _))
                errors.Add($"'{Constants.Config.ApiUrl}' is not a valid absolute URI.");

            string accountNumber = GetStringValue(connectionInfo, Constants.Config.AccountNumber);
            if (string.IsNullOrWhiteSpace(accountNumber))
                errors.Add($"'{Constants.Config.AccountNumber}' is required.");

            // Auth mode — validate the required credentials for the chosen mode
            string authMode = GetStringValue(connectionInfo, Constants.Config.AuthMode, Constants.Config.AuthModeAccessKey);
            switch (authMode.ToUpperInvariant())
            {
                case "ACCESSKEY":
                case "APIKEY":  // legacy alias
                    string apiKey = GetStringValue(connectionInfo, Constants.Config.ApiKey);
                    if (string.IsNullOrWhiteSpace(apiKey))
                        errors.Add($"'{Constants.Config.ApiKey}' is required when AuthMode is 'AccessKey'.");
                    break;

                case "OAUTH":
                case "OAUTH2":
                    string tokenUrl = GetStringValue(connectionInfo, Constants.Config.OAuth2TokenUrl);
                    string clientId = GetStringValue(connectionInfo, Constants.Config.OAuth2ClientId);
                    string clientSecret = GetStringValue(connectionInfo, Constants.Config.OAuth2ClientSecret);
                    if (string.IsNullOrWhiteSpace(tokenUrl))
                        errors.Add($"'{Constants.Config.OAuth2TokenUrl}' is required when AuthMode is 'OAuth'.");
                    if (string.IsNullOrWhiteSpace(clientId))
                        errors.Add($"'{Constants.Config.OAuth2ClientId}' is required when AuthMode is 'OAuth'.");
                    if (string.IsNullOrWhiteSpace(clientSecret))
                        errors.Add($"'{Constants.Config.OAuth2ClientSecret}' is required when AuthMode is 'OAuth'.");
                    break;

                default:
                    errors.Add($"'{Constants.Config.AuthMode}' must be one of: AccessKey, OAuth. Got: '{authMode}'.");
                    break;
            }

            if (errors.Any())
            {
                // SOX CC6.1: log the validation failure at Warning so it survives production log filters.
                _logger.LogWarning(
                    "CA connection validation failed (config errors). ApiUrl={ApiUrl}, AuthMode={AuthMode}, Errors={Errors}",
                    attemptedApiUrl, attemptedAuthMode, string.Join("; ", errors));
                throw new AnyCAValidationException(string.Join(Environment.NewLine, errors));
            }

            // Attempt a live connectivity test using the supplied credentials
            CERTInextConfig tempConfig = null;
            CERTInextClient tempClient = null;
            try
            {
                // Build a transient config from the supplied connectionInfo so we don't
                // rely on the already-initialized _client (which may hold stale creds)
                string rawConfig = JsonSerializer.Serialize(connectionInfo);
                tempConfig = JsonSerializer.Deserialize<CERTInextConfig>(rawConfig);
                tempClient = new CERTInextClient(tempConfig);
                await tempClient.PingAsync();
            }
            catch (Exception ex)
            {
                // SOX CC6.1 / SOC2 CC6.1: authentication/connectivity failure must be logged
                // with sufficient detail to reconstruct the event.
                _logger.LogError(
                    ex,
                    "CA connection validation failed — live connectivity test unsuccessful. " +
                    "ApiUrl={ApiUrl}, AuthMode={AuthMode}",
                    attemptedApiUrl, attemptedAuthMode);

                // The inner exception message is NOT forwarded to the AnyCAValidationException
                // because it may contain HTTP response bodies or header fragments from the
                // transport layer that could leak credentials or session tokens to the UI.
                throw new AnyCAValidationException(
                    "Successfully parsed configuration, but could not connect to CERTInext. " +
                    "See gateway logs for details.");
            }
            finally
            {
                // SOC2 CC6.1 best-effort credential scrubbing: blank out the secret fields
                // on the transient config so they aren't reachable from the still-rooted
                // tempClient instance after this method returns. Not a hard guarantee
                // (the .NET runtime may have already copied them elsewhere) but removes
                // the most obvious post-validation reference chain.
                if (tempConfig != null)
                {
                    tempConfig.ApiKey = string.Empty;
                    tempConfig.OAuthClientSecret = string.Empty;
                    tempConfig.Password = string.Empty;
                }
            }

            _logger.LogInformation(
                "CA connection validation succeeded. ApiUrl={ApiUrl}, AuthMode={AuthMode}",
                attemptedApiUrl, attemptedAuthMode);
            _logger.MethodExit(LogLevel.Debug);
        }

        /// <inheritdoc/>
        public async Task ValidateProductInfo(EnrollmentProductInfo productInfo, Dictionary<string, object> connectionInfo)
        {
            _logger.MethodEntry(LogLevel.Debug);

            string rawConfig = JsonSerializer.Serialize(connectionInfo);
            var tempConfig = JsonSerializer.Deserialize<CERTInextConfig>(rawConfig);
            var tempClient = new CERTInextClient(tempConfig);

            var params_ = new EnrollmentParams(productInfo);
            string profileId = params_.ProfileId;

            _logger.LogInformation(
                "Product/profile validation attempt started. ProfileId={ProfileId}, ProductID={ProductID}",
                profileId, productInfo?.ProductID);

            if (string.IsNullOrWhiteSpace(profileId))
            {
                _logger.LogWarning(
                    "Product/profile validation failed — ProfileId parameter is missing or empty. ProductID={ProductID}",
                    productInfo?.ProductID);
                throw new AnyCAValidationException(
                    $"Template parameter '{Constants.EnrollmentParam.ProfileId}' is required but was not set.");
            }

            try
            {
                var profiles = await tempClient.GetProfilesAsync();
                bool found = profiles.Any(p =>
                    string.Equals(p.Id, profileId, StringComparison.OrdinalIgnoreCase));

                if (!found)
                {
                    var available = string.Join(", ", profiles.Select(p => p.Id));
                    // SOC2 CC7.2: log profile probe misses at Warning to support anomaly detection.
                    _logger.LogWarning(
                        "Product/profile validation failed — ProfileId not found in CERTInext. " +
                        "ProfileId={ProfileId}, AvailableCount={AvailableCount}",
                        profileId, profiles.Count);
                    throw new AnyCAValidationException(
                        $"Profile '{profileId}' was not found in CERTInext. " +
                        $"Available profiles: {available}");
                }
            }
            catch (AnyCAValidationException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Product/profile validation failed — error querying CERTInext profiles. ProfileId={ProfileId}",
                    profileId);
                // Exception message is NOT forwarded to keep error payloads (which may contain
                // sensitive HTTP body content) out of the AnyCAValidationException seen by the UI.
                throw new AnyCAValidationException(
                    $"Unable to validate profile '{profileId}' against CERTInext. " +
                    "See gateway logs for details.");
            }
            finally
            {
                // SOC2 CC6.1 best-effort credential scrubbing (see ValidateCAConnectionInfo).
                if (tempConfig != null)
                {
                    tempConfig.ApiKey = string.Empty;
                    tempConfig.OAuthClientSecret = string.Empty;
                    tempConfig.Password = string.Empty;
                }
            }

            _logger.LogInformation("Product/profile validation succeeded. ProfileId={ProfileId}", profileId);
            _logger.MethodExit(LogLevel.Debug);
        }

        // ---------------------------------------------------------------------------
        // IAnyCAPlugin — Enrollment
        // ---------------------------------------------------------------------------

        /// <inheritdoc/>
        public async Task<EnrollmentResult> Enroll(
            string csr,
            string subject,
            Dictionary<string, string[]> san,
            EnrollmentProductInfo productInfo,
            RequestFormat requestFormat,
            EnrollmentType enrollmentType)
        {
            _logger.MethodEntry(LogLevel.Debug);

            var ep = new EnrollmentParams(productInfo);

            // SOX / SOC2 CC7.3: log the enrollment attempt with full identifying context
            // so the event is independently auditable before any API call is made.
            string sanSummary = san != null && san.Count > 0
                ? string.Join("; ", san.SelectMany(kvp => (kvp.Value ?? Array.Empty<string>())
                    .Select(v => $"{kvp.Key}:{v}")))
                : "(none)";

            _logger.LogInformation(
                "Enrollment attempt started. " +
                "EnrollmentType={EnrollmentType}, RequestFormat={RequestFormat}, Subject={Subject}, " +
                "ProfileId={ProfileId}, SANs={SANs}, " +
                "RequesterName={RequesterName}, RequesterEmail={RequesterEmail}",
                enrollmentType, requestFormat, subject,
                ep.ProfileId, sanSummary,
                ep.RequesterName, ep.RequesterEmail);

            if (string.IsNullOrWhiteSpace(ep.ProfileId))
            {
                _logger.LogError(
                    "Enrollment rejected — ProfileId parameter is missing. Subject={Subject}, EnrollmentType={EnrollmentType}",
                    subject, enrollmentType);
                throw new Exception($"Template parameter '{Constants.EnrollmentParam.ProfileId}' is required.");
            }

            EnrollmentResult result;

            switch (enrollmentType)
            {
                case EnrollmentType.New:
                case EnrollmentType.Reissue:
                    result = await EnrollNewAsync(csr, subject, san, ep);
                    break;

                case EnrollmentType.Renew:
                case EnrollmentType.RenewOrReissue:
                    result = await RenewOrReissueAsync(csr, subject, san, productInfo, ep);
                    break;

                default:
                    _logger.LogError(
                        "Enrollment rejected — unsupported enrollment type. EnrollmentType={EnrollmentType}, Subject={Subject}",
                        enrollmentType, subject);
                    throw new NotSupportedException($"Enrollment type '{enrollmentType}' is not supported.");
            }

            // SOX: the completion log must include the CA-assigned identifier, serial number,
            // subject, and profile so the issued certificate is fully traceable.
            _logger.LogInformation(
                "Enrollment complete. " +
                "EnrollmentType={EnrollmentType}, CARequestID={Id}, Status={Status}, " +
                "SerialNumber={SerialNumber}, Subject={Subject}, ProfileId={ProfileId}",
                enrollmentType, result.CARequestID, result.Status,
                result.Certificate != null ? ExtractSerialFromPem(result.Certificate) : "(pending)",
                subject, ep.ProfileId);
            _logger.MethodExit(LogLevel.Debug);
            return result;
        }

        // ---------------------------------------------------------------------------
        // IAnyCAPlugin — Retrieval
        // ---------------------------------------------------------------------------

        /// <inheritdoc/>
        public async Task<AnyCAPluginCertificate> GetSingleRecord(string caRequestID)
        {
            _logger.MethodEntry(LogLevel.Debug);
            _logger.LogInformation("GetSingleRecord started. CARequestID={Id}", caRequestID);

            try
            {
                var cert = await _client.GetCertificateAsync(caRequestID);

                // Mirror the deferred-DCV behavior of Synchronize: if the order is still in
                // a pending state, try to advance it through DCV before returning. This lets
                // a manual single-record refresh unstick an order whose DCV challenge was
                // only exposed after enrollment returned.
                int status = StatusMapper.ToRequestDisposition(cert.Status);
                if (status == (int)EndEntityStatus.EXTERNALVALIDATION)
                {
                    bool dcvDone = await TryRunDcvDuringSyncAsync(caRequestID, CancellationToken.None);
                    if (dcvDone)
                    {
                        try
                        {
                            cert = await _client.GetCertificateAsync(caRequestID);
                        }
                        catch (Exception refetchEx)
                        {
                            _logger.LogWarning(refetchEx,
                                "Single-record DCV completed but post-DCV refetch failed. CARequestID={Id}",
                                caRequestID);
                        }
                    }
                }

                var record = MapToAnyCAPluginCertificate(cert);

                // SOC2 CC7.3: certificate retrieval is a security-relevant read operation;
                // must be logged at Information so it is captured in production.
                _logger.LogInformation(
                    "GetSingleRecord complete. CARequestID={Id}, Status={Status}, SerialNumber={Serial}",
                    caRequestID, cert.Status, cert.SerialNumber ?? "(none)");
                _logger.MethodExit(LogLevel.Debug);
                return record;
            }
            catch (KeyNotFoundException)
            {
                _logger.LogWarning("Certificate not found in CERTInext. CARequestID={Id}", caRequestID);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving certificate from CERTInext. CARequestID={Id}", caRequestID);
                throw;
            }
        }

        // ---------------------------------------------------------------------------
        // IAnyCAPlugin — Revocation
        // ---------------------------------------------------------------------------

        /// <inheritdoc/>
        public async Task<int> Revoke(string caRequestID, string hexSerialNumber, uint revocationReason)
        {
            _logger.MethodEntry(LogLevel.Debug);

            string reasonString = StatusMapper.ToRevocationReason(revocationReason);

            // SOX: log the revocation attempt before any state change so the intent is
            // recorded even if the API call subsequently fails.  Include ManagedThreadId
            // so revoke events can be correlated against the gateway-supplied
            // RequestingUser scope when the host enriches Keyfactor.Logging with it
            // (segregation-of-duties evidence — SOX CC1.3 / SOC2 CC1.4).
            _logger.LogInformation(
                "Revocation attempt started. " +
                "CARequestID={Id}, HexSerialNumber={Serial}, " +
                "ReasonCode={ReasonCode}, ReasonString={ReasonString}, " +
                "ManagedThreadId={ThreadId}",
                caRequestID, hexSerialNumber, revocationReason, reasonString,
                System.Environment.CurrentManagedThreadId);

            // Verify the certificate is in a revocable state before calling the API
            LegacyGetCertificateResponse current;
            try
            {
                current = await _client.GetCertificateAsync(caRequestID);
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Revocation pre-flight failed — could not retrieve certificate state. " +
                    "CARequestID={Id}, HexSerialNumber={Serial}",
                    caRequestID, hexSerialNumber);
                throw;
            }

            int currentStatus = StatusMapper.ToRequestDisposition(current.Status);
            if (currentStatus == (int)EndEntityStatus.REVOKED)
            {
                _logger.LogWarning(
                    "Revocation skipped — certificate is already revoked. " +
                    "CARequestID={Id}, HexSerialNumber={Serial}, Subject={Subject}",
                    caRequestID, hexSerialNumber, current.Subject);
                return (int)EndEntityStatus.REVOKED;
            }

            if (currentStatus != (int)EndEntityStatus.GENERATED)
            {
                _logger.LogError(
                    "Revocation rejected — certificate is not in a revocable state. " +
                    "CARequestID={Id}, HexSerialNumber={Serial}, CurrentStatus={Status}",
                    caRequestID, hexSerialNumber, current.Status);
                throw new Exception(
                    $"Certificate '{caRequestID}' cannot be revoked: current status is '{current.Status}'. " +
                    $"Only issued certificates may be revoked.");
            }

            var revokeReq = new RevokeCertificateRequest
            {
                Reason = reasonString,
                Comment = $"Revoked via Keyfactor Command. CRL reason code: {revocationReason} ({reasonString})."
            };

            await _client.RevokeCertificateAsync(caRequestID, revokeReq);

            // SOX: the completion log must include both the CA identifier and the X.509 serial
            // number so the revocation event can be correlated with certificate records.
            _logger.LogInformation(
                "Revocation complete. " +
                "CARequestID={Id}, HexSerialNumber={Serial}, Subject={Subject}, " +
                "ReasonCode={ReasonCode}, ReasonString={ReasonString}",
                caRequestID, hexSerialNumber, current.Subject,
                revocationReason, reasonString);
            _logger.MethodExit(LogLevel.Debug);
            return (int)EndEntityStatus.REVOKED;
        }

        // ---------------------------------------------------------------------------
        // IAnyCAPlugin — Synchronisation
        // ---------------------------------------------------------------------------

        /// <inheritdoc/>
        public async Task Synchronize(
            BlockingCollection<AnyCAPluginCertificate> blockingBuffer,
            DateTime? lastSync,
            bool fullSync,
            CancellationToken cancelToken)
        {
            _logger.MethodEntry(LogLevel.Debug);

            DateTime? issuedAfter = fullSync ? (DateTime?)null : lastSync;

            _logger.LogInformation(
                "Starting CERTInext synchronization. FullSync={FullSync}, IssuedAfter={IssuedAfter}",
                fullSync, issuedAfter?.ToString("O") ?? "none");

            int synced = 0;
            int skipped = 0;
            int skippedWithBody = 0;   // skipped records that nonetheless carried a cert body (should be 0)
            int errors = 0;

#if SUPPORTS_DCV
            // DCV-during-sync only actually runs when DCV is enabled AND a DNS provider factory was
            // injected by the host. On a gateway that doesn't supply one (e.g. IAnyCAPlugin 3.2.0
            // hosts), DCV cannot run even on a DCV-capable build — so don't run the gate or report
            // attempt counts that would imply it did (issue 0003). Bounds apply only when operational.
            bool dcvOperational = _config.DcvEnabled && _domainValidatorFactory != null;
            int ageWindowHours = _config.DcvSyncMaxOrderAgeHours;   // 0 = no age filter
            int perPassCap = _config.DcvSyncMaxPerPass;             // 0 = no cap
            int dcvAttempted = 0, dcvSkippedAge = 0, dcvSkippedCap = 0;
#endif

            // Emit-side accounting (issue 0003): what the plugin hands to the gateway buffer.
            int emittedGeneratedWithBody = 0, emittedGeneratedNoBody = 0, emittedRevoked = 0, emittedPending = 0;

            try
            {
                await foreach (var cert in _client.ListCertificatesAsync(
                    issuedAfter, _config.PageSize, cancelToken))
                {
                    cancelToken.ThrowIfCancellationRequested();

                    // Local copy so we can replace it with a post-DCV refetch below
                    var current = cert;

                    try
                    {
                        // Skip expired certificates when IgnoreExpired is configured
                        if (_config.IgnoreExpired
                            && current.ExpiresAt.HasValue
                            && current.ExpiresAt.Value < DateTime.UtcNow)
                        {
                            _logger.LogTrace(
                                "Skipping expired certificate '{Id}' (expires {ExpiresAt:u}).",
                                current.Id, current.ExpiresAt.Value);
                            if (!string.IsNullOrWhiteSpace(current.Certificate)) skippedWithBody++;
                            skipped++;
                            continue;
                        }

                        int status = StatusMapper.ToRequestDisposition(current.Status);

                        // Per-record trace so a sync pass is fully reconstructable from logs
                        // (info-level only emits start/summary). Enable Trace on this category.
                        _logger.LogTrace(
                            "Sync: processing order Id={Id}, listedStatus='{Listed}', mappedStatus={Status}, " +
                            "orderDate={OrderDate}, bodyInListing={HasBody}",
                            current.Id, current.Status, status,
                            current.OrderDate?.ToString("o") ?? "(none)",
                            !string.IsNullOrWhiteSpace(current.Certificate));

                        // Deferred DCV: pending orders (EXTERNALVALIDATION) often need DCV driven
                        // forward during sync — CERTInext parks fresh orders and exposes the DCV
                        // challenge minutes after enrollment, and scans are the only place that gets
                        // picked back up. But attempting DCV for EVERY pending order on EVERY pass is
                        // O(pending) and pathologically slow with a large/abandoned backlog (issue
                        // 0002). Bound it: only recently-placed orders are eligible (age window), and
                        // at most N per pass (cap). Aged-out / over-cap orders are emitted as pending
                        // and revisited on a later pass (the per-minute incremental scan keeps recent
                        // orders moving). Unknown order age → treat as eligible so we never starve a
                        // legitimately-new order.
#if SUPPORTS_DCV
                        if (dcvOperational && status == (int)EndEntityStatus.EXTERNALVALIDATION)
                        {
                            var decision = EvaluateDcvSyncEligibility(
                                current.OrderDate, DateTime.UtcNow, ageWindowHours, dcvAttempted, perPassCap);

                            _logger.LogTrace(
                                "Sync DCV gate: Id={Id}, decision={Decision}, orderDate={OrderDate}, " +
                                "ageWindowHours={Age}, attemptedSoFar={Attempted}, perPassCap={Cap}",
                                current.Id, decision, current.OrderDate?.ToString("o") ?? "(none)",
                                ageWindowHours, dcvAttempted, perPassCap);

                            if (decision == DcvSyncDecision.SkipByAge)
                            {
                                // Issue 0003 / SOC1 completeness: an order past the age window is no
                                // longer advanced by sync (it only ages further), so record its
                                // identity at Information — not just the aggregate count — so an
                                // auditor can see which orders were left parked, and when.
                                _logger.LogInformation(
                                    "Sync: pending DV order aged out of the DCV-during-sync window and will " +
                                    "not be advanced. CARequestID={Id}, OrderDate={OrderDate}, AgeWindowHours={Age}.",
                                    current.Id, current.OrderDate?.ToString("o") ?? "(none)", ageWindowHours);
                                dcvSkippedAge++;
                            }
                            else if (decision == DcvSyncDecision.SkipByCap)
                            {
                                dcvSkippedCap++;
                            }
                            else
                            {
                                dcvAttempted++;
                                bool dcvDone = await TryRunDcvDuringSyncAsync(
                                    current.Id, cancelToken, fastSync: true);
                                if (dcvDone)
                                {
                                    try
                                    {
                                        current = await _client.GetCertificateAsync(current.Id, cancelToken);
                                        status = StatusMapper.ToRequestDisposition(current.Status);
                                    }
                                    catch (Exception refetchEx)
                                    {
                                        _logger.LogWarning(refetchEx,
                                            "Sync DCV completed but post-DCV refetch failed. Id={Id}", current.Id);
                                    }
                                }
                            }
                        }
#endif

                        // Skip failed/rejected/cancelled certificates — they have no cert body
                        if (status == (int)EndEntityStatus.FAILED)
                        {
                            _logger.LogTrace(
                                "Skipping certificate '{Id}' with terminal failure status '{Status}'.",
                                current.Id, current.Status);
                            if (!string.IsNullOrWhiteSpace(current.Certificate)) skippedWithBody++;
                            skipped++;
                            continue;
                        }

                        // The order-report listing (ListCertificatesAsync) does NOT include the
                        // certificate body, so an already-issued order arrives here with
                        // current.Certificate == null. Command cannot store a record without a
                        // body, so issued certs were being silently dropped from sync. Refetch the
                        // full certificate (PEM included) for issued/revoked orders whose body is
                        // missing — this mirrors GetSingleRecord and the DCV-completed branch above.
                        // Pending (EXTERNALVALIDATION) records legitimately have no body yet and are
                        // left as-is.
                        if (string.IsNullOrWhiteSpace(current.Certificate)
                            && (status == (int)EndEntityStatus.GENERATED
                                || status == (int)EndEntityStatus.REVOKED))
                        {
                            _logger.LogDebug(
                                "Sync: issued/revoked order Id={Id} has no body in the listing — refetching full certificate.",
                                current.Id);
                            // The order-report listing carries metadata (Subject/DomainName,
                            // ProfileId/ProductCode, OrderDate) that GetCertificateAsync (TrackOrder +
                            // DownloadCertificate) does NOT return. The refetch replaces `current`
                            // wholesale, so carry that listing metadata across or the emitted record
                            // loses its Subject and ProductID (ProductID feeds the Command template).
                            var listed = current;
                            try
                            {
                                current = await _client.GetCertificateAsync(current.Id, cancelToken);
                                current.Subject = string.IsNullOrWhiteSpace(current.Subject) ? listed.Subject : current.Subject;
                                current.ProfileId = string.IsNullOrWhiteSpace(current.ProfileId) ? listed.ProfileId : current.ProfileId;
                                current.OrderDate ??= listed.OrderDate;
                                status = StatusMapper.ToRequestDisposition(current.Status);
                                _logger.LogDebug(
                                    "Sync: refetched order Id={Id} — status={Status}, certBytes={Bytes}, subject={Subject}.",
                                    current.Id, status, current.Certificate?.Length ?? 0, current.Subject);
                            }
                            catch (Exception fetchEx)
                            {
                                _logger.LogWarning(fetchEx,
                                    "Sync: failed to fetch certificate body for issued order '{Id}'; " +
                                    "emitting metadata-only record.", current.Id);
                            }
                        }

                        var record = MapToAnyCAPluginCertificate(current);

                        // Emit-side observability (issue 0003): account for what the plugin hands to
                        // the gateway buffer, broken down by status and whether a cert body is present.
                        // This is the boundary the plugin owns — if these counts show issued records
                        // emitted WITH bodies but the gateway DB lacks them, the gap is gateway-side
                        // persistence, not the plugin. Per-record detail is at Debug; the aggregate is
                        // logged at Information in the completion summary below.
                        bool recordHasBody = !string.IsNullOrWhiteSpace(record.Certificate);
                        if (record.Status == (int)EndEntityStatus.GENERATED)
                        {
                            if (recordHasBody) emittedGeneratedWithBody++; else emittedGeneratedNoBody++;
                        }
                        else if (record.Status == (int)EndEntityStatus.REVOKED)
                        {
                            emittedRevoked++;
                        }
                        else if (record.Status == (int)EndEntityStatus.EXTERNALVALIDATION)
                        {
                            emittedPending++;
                        }
                        _logger.LogDebug(
                            "Sync emit: CARequestID={Id}, Status={Status}, CertBytes={CertBytes}, Subject={Subject}",
                            record.CARequestID, record.Status, record.Certificate?.Length ?? 0, current.Subject);

                        blockingBuffer.Add(record, cancelToken);
                        synced++;
                    }
                    catch (OperationCanceledException)
                    {
                        // SOC1 completeness: log the cancellation event so the sync termination
                        // reason is captured in the audit trail.
                        _logger.LogWarning(
                            "CERTInext synchronization cancelled by caller. " +
                            "FullSync={FullSync}, Synced={Synced}, Skipped={Skipped}, Errors={Errors}",
                            fullSync, synced, skipped, errors);
                        throw;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error processing certificate '{Id}' during synchronization.", cert.Id);
                        errors++;

                        // SOC1 completeness/accuracy: a sync that hits an error-rate cliff
                        // must report a failure, not silently 'complete' with zero useful
                        // records. Abort if we have at least 50 records' worth of evidence
                        // AND more than 25% of all records seen so far are errors.
                        int totalSeen = synced + skipped + errors;
                        if (totalSeen >= 50 && errors > totalSeen / 4)
                        {
                            _logger.LogError(
                                "CERTInext synchronization aborted — error rate ({Errors}/{Total}) " +
                                "exceeded 25% threshold. Likely CA-side outage; will retry on next sync cycle.",
                                errors, totalSeen);
                            throw new Exception(
                                $"CERTInext synchronization aborted after {errors}/{totalSeen} records failed " +
                                "(>25% error rate). See gateway logs for the underlying CA errors.");
                        }
                    }
                }

                // Build the DCV-during-sync clause for the ACTUAL runtime state so the summary
                // never implies DCV ran when it couldn't (issue 0003 / SOC2 CC7.3 accuracy).
                string dcvClause;
#if SUPPORTS_DCV
                if (dcvOperational)
                    dcvClause = $"DCV-during-sync: Attempted={dcvAttempted}, SkippedByAge={dcvSkippedAge} (>{ageWindowHours}h), SkippedByCap={dcvSkippedCap} (cap={perPassCap}).";
                else
                    dcvClause = $"DCV-during-sync: not active (DcvEnabled={_config.DcvEnabled}, DnsProviderInjected={_domainValidatorFactory != null}) — pending orders left as EXTERNALVALIDATION.";
#else
                dcvClause = "DCV-during-sync: not supported on this build (IAnyCAPlugin 3.2.0).";
#endif
                _logger.LogInformation(
                    "CERTInext synchronization complete. Synced={Synced}, Skipped={Skipped} (withBody={SkippedWithBody}), " +
                    "Errors={Errors}. Emitted to gateway buffer: GeneratedWithBody={GenWithBody}, " +
                    "GeneratedNoBody={GenNoBody}, Revoked={Revoked}, Pending={Pending}. {DcvClause}",
                    synced, skipped, skippedWithBody, errors,
                    emittedGeneratedWithBody, emittedGeneratedNoBody, emittedRevoked, emittedPending,
                    dcvClause);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("CERTInext synchronization was cancelled.");
                throw;
            }
            finally
            {
                // Signal to the gateway framework that no more items will be added to the buffer.
                // This must be called on both normal exit and cancellation so the consumer
                // (gateway) does not block indefinitely waiting for more records.
                blockingBuffer.CompleteAdding();
            }

            _logger.MethodExit(LogLevel.Debug);
        }

        // ---------------------------------------------------------------------------
        // Private helpers
        // ---------------------------------------------------------------------------

        /// <summary>The DCV-during-sync gate outcome for a single pending order (issue 0002).</summary>
        internal enum DcvSyncDecision { Attempt, SkipByAge, SkipByCap }

        /// <summary>
        /// Decides whether to attempt DCV completion for a pending order during a sync pass,
        /// bounding the work so a large pending backlog can't make sync slow (issue 0002).
        /// Pure/stateless so it is unit-testable without the DCV machinery.
        ///
        /// Rules (checked in order):
        ///  - Age: when <paramref name="ageWindowHours"/> &gt; 0, only orders placed within that
        ///    window are eligible. A missing <paramref name="orderDateUtc"/> is treated as eligible
        ///    so a legitimately-new order is never starved by unknown age.
        ///  - Cap: when <paramref name="perPassCap"/> &gt; 0, at most that many orders are attempted
        ///    per pass; once <paramref name="attemptedSoFar"/> reaches it, the rest are deferred.
        /// A value of 0 for either bound disables that bound.
        /// </summary>
        internal static DcvSyncDecision EvaluateDcvSyncEligibility(
            DateTime? orderDateUtc, DateTime nowUtc, int ageWindowHours, int attemptedSoFar, int perPassCap)
        {
            bool eligibleByAge = ageWindowHours <= 0
                || !orderDateUtc.HasValue
                || (nowUtc - orderDateUtc.Value).TotalHours <= ageWindowHours;
            if (!eligibleByAge)
                return DcvSyncDecision.SkipByAge;

            bool eligibleByCap = perPassCap <= 0 || attemptedSoFar < perPassCap;
            if (!eligibleByCap)
                return DcvSyncDecision.SkipByCap;

            return DcvSyncDecision.Attempt;
        }

        /// <summary>
        /// Handles New and Reissue enrollment flows by submitting a fresh certificate
        /// request to CERTInext.
        /// </summary>
        private async Task<EnrollmentResult> EnrollNewAsync(
            string csr,
            string subject,
            Dictionary<string, string[]> san,
            EnrollmentParams ep)
        {
            _logger.MethodEntry(LogLevel.Debug);
            var enrollReq = new EnrollCertificateRequest
            {
                ProfileId = ep.ProfileId,
                Csr = csr,
                ValidityDays = ep.ValidityDays > 0 ? ep.ValidityDays : (int?)null,
                Subject = subject,
                Sans = BuildSanList(san, csr),
                RequesterName = string.IsNullOrWhiteSpace(ep.RequesterName) ? null : ep.RequesterName,
                RequesterEmail = string.IsNullOrWhiteSpace(ep.RequesterEmail) ? null : ep.RequesterEmail,
                KeyType = string.IsNullOrWhiteSpace(ep.KeyType) ? null : ep.KeyType,
                Comment = "Issued via Keyfactor Command AnyCA REST Gateway."
            };

            var enrollResp = await _client.EnrollCertificateAsync(enrollReq);

            // Whether the DCV block below took ownership of the in-call issuance wait for this
            // order. Declared outside the #if so both build flavors compile the pickup gate the
            // same way (it simply stays false on the no-DCV build). When true, the synchronous
            // pickup poll is skipped: on the DCV build the DCV path already owns the issuance
            // decision — it either ran WaitForIssuanceAfterDcvAsync itself, deferred to another
            // in-flight caller, or determined the order is terminal / not yet validated — so a
            // second stacked poll would either double the wait or burn the budget polling an
            // order that can never issue in-call (regression guard: a cancelled/rejected order
            // must not be re-polled here after DCV already short-circuited it).
            bool dcvIssuanceWaitRan = false;

#if SUPPORTS_DCV
            // DCV: run domain validation if enabled, the factory was injected, and the
            // order was accepted (not immediately failed).
            string orderNumber = enrollResp.Id;
            if (_domainValidatorFactory != null && _config.DcvEnabled && !string.IsNullOrEmpty(orderNumber))
            {
                // DCV owns the in-call issuance wait for this order from here on: every exit from
                // this block (duplicate in-flight, DCV-validated + issuance poll, terminal order,
                // or challenge-not-yet-exposed) is a decision the pickup poll must not second-guess.
                // Set before any await so it holds on every path out of the block.
                //
                // This is intentionally coarse — keyed on "the DCV subsystem engaged for this order",
                // not on "a DCV wait is actively running". The one case it over-defers is an order
                // whose pending domains are all assigned to a non-DNS-01 method (HTTP/email): DCV does
                // no work, yet pickup is skipped. That is an accepted trade: this plugin only drives
                // DNS-01, so such orders depend on out-of-band validation and would not issue within
                // the ~55s pickup window anyway — the next sync completes them. Distinguishing that
                // sub-case from the terminal/cancelled case (which MUST skip pickup) would require a
                // richer PerformDcvIfNeededAsync result and risk re-opening the terminal-order regression.
                dcvIssuanceWaitRan = true;

                // SOX CC7.3: bound the entire DCV flow with a hard timeout so a stuck
                // DNS provider or extreme propagation delay cannot hold a gateway worker
                // thread indefinitely.  Configurable via DcvTimeoutMinutes (config or
                // CERTINEXT_DCV_TIMEOUT_MINUTES env var); defaults to 10 minutes.
                // Log the resolved limit so an auditor can confirm the configured ceiling.
                int dcvTimeoutMinutes = _config.GetEffectiveDcvTimeoutMinutes();
                _logger.LogInformation(
                    "Starting DCV for order {OrderNumber}. DcvTimeoutMinutes={Timeout}",
                    orderNumber, dcvTimeoutMinutes);
                using var dcvCts = new CancellationTokenSource(TimeSpan.FromMinutes(dcvTimeoutMinutes));

                // Reserve the in-flight slot before running DCV so that any concurrent
                // Synchronize / GetSingleRecord cycle won't try to stage TXT records for the
                // same order from the sync-driven retry path.  If something else already has
                // the slot (the only realistic case: a duplicate Enroll for the same order
                // ID), skip our own attempt and fall through to the pending result — the
                // other caller will produce the same outcome and we shouldn't double-stage.
                bool reserved = _dcvInFlight.TryAdd(orderNumber, 0);
                if (!reserved)
                {
                    _logger.LogInformation(
                        "DCV is already in flight for order {OrderNumber}; Enroll will skip its own DCV attempt " +
                        "and return the pending enroll response. The other caller will drive issuance.",
                        orderNumber);
                }
                else
                {
                    try
                    {
                        bool dcvDone = await PerformDcvIfNeededAsync(orderNumber, dcvCts.Token);
                        if (dcvDone)
                        {
                            // Poll GetCertificate until CERTInext finishes generating the cert OR the
                            // issuance budget expires.  CERTInext issuance is async — DCV may verify
                            // but the cert PEM isn't immediately available.  Without this poll, Enroll
                            // returns a pending result and the cert is picked up on the next sync cycle,
                            // which is undesirable when the whole thing completes in under a minute.
                            var postDcv = await WaitForIssuanceAfterDcvAsync(orderNumber, dcvCts.Token);
                            if (postDcv != null)
                            {
                                return BuildEnrollmentResult(new EnrollCertificateResponse
                                {
                                    Id = postDcv.Id,
                                    Status = postDcv.Status,
                                    Certificate = postDcv.Certificate,
                                    SerialNumber = postDcv.SerialNumber,
                                    Message = $"Post-DCV status: {postDcv.Status}."
                                }, ep.AutoApprove);
                            }
                        }
                    }
                    finally
                    {
                        _dcvInFlight.TryRemove(orderNumber, out _);
                    }
                }
            }
#endif

            // Synchronous certificate pickup (Sectigo-parity): poll for the issued certificate so
            // a fast-issuing order returns GENERATED + PEM in this same call. No-op for the
            // already-issued/failed case and for OV/EV orders that CERTInext issues asynchronously
            // — those fall back to the pending result and are imported by the next sync.
            var newResult = BuildEnrollmentResult(enrollResp, ep.AutoApprove);
            newResult = await PickUpEnrolledCertificateAsync(newResult, enrollResp.Id, dcvIssuanceWaitRan);

            _logger.MethodExit(LogLevel.Debug);
            return newResult;
        }

        /// <summary>
        /// Handles Renew and RenewOrReissue enrollment flows.
        /// Determines whether to renew (API call on existing ID) or fall back to new
        /// issuance depending on the certificate's current state.
        /// </summary>
        private async Task<EnrollmentResult> RenewOrReissueAsync(
            string csr,
            string subject,
            Dictionary<string, string[]> san,
            EnrollmentProductInfo productInfo,
            EnrollmentParams ep)
        {
            // Retrieve the prior certificate serial number from the product parameters.
            // Command injects "PriorCertSN" for renewal flows.
            string priorCertSn = null;
            productInfo.ProductParameters?.TryGetValue("PriorCertSN", out priorCertSn);

            // SOC2 CC6.1: a renewal/reissue read against the gateway's certificate
            // inventory is a logical-access event and must be logged at Information.
            _logger.LogInformation(
                "Renewal/reissue probe — read PriorCertSN from EnrollmentProductInfo. " +
                "Subject={Subject}, PriorCertSN={PriorCertSN}, RenewalWindowDays={WindowDays}",
                subject, string.IsNullOrWhiteSpace(priorCertSn) ? "(none)" : priorCertSn,
                ep.RenewalWindowDays);

            if (string.IsNullOrWhiteSpace(priorCertSn))
            {
                // SOC2 CC7.2: log policy-relevant decisions at Information so they survive
                // production log filters and are available for anomaly detection.
                _logger.LogInformation(
                    "Renewal/reissue has no PriorCertSN — treating as new enrollment. Subject={Subject}",
                    subject);
                return await EnrollNewAsync(csr, subject, san, ep);
            }

            // Resolve the CARequestID for the prior certificate
            string priorCaRequestId;
            try
            {
                priorCaRequestId = await _certificateDataReader.GetRequestIDBySerialNumber(priorCertSn);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "Could not resolve CARequestID for serial '{SN}'. Falling back to new enrollment.", priorCertSn);
                return await EnrollNewAsync(csr, subject, san, ep);
            }

            if (string.IsNullOrWhiteSpace(priorCaRequestId))
            {
                _logger.LogInformation(
                    "CARequestID for serial '{SN}' is empty — falling back to new enrollment. Subject={Subject}",
                    priorCertSn, subject);
                return await EnrollNewAsync(csr, subject, san, ep);
            }

            // Determine whether this is within the renewal window.
            //
            // Semantics (Option A — "window before expiry"):
            //   useRenewalApi = true  when the cert expires within the next RenewalWindowDays.
            //   useRenewalApi = false when the cert expires further away than that (too early → reissue).
            //   useRenewalApi = false when the cert is already expired (graceful degradation → new order).
            //
            // This matches operator expectation: "renew when within N days of expiry".
            // Certs expiring far in the future should be reissued, not renewed via the CA's
            // renew endpoint (which may assume near-expiry context on its side).
            bool useRenewalApi = false;
            try
            {
                DateTime? expiry = _certificateDataReader.GetExpirationDateByRequestId(priorCaRequestId);
                if (expiry.HasValue)
                {
                    DateTime now = DateTime.UtcNow;
                    DateTime renewalWindowEnd = now.AddDays(ep.RenewalWindowDays);
                    // Renew only if the cert is not yet expired AND expires within the window.
                    useRenewalApi = expiry.Value > now && expiry.Value <= renewalWindowEnd;

                    // SOX CC6.2 / SOC2 CC7.2: the renewal window evaluation is a security-relevant
                    // policy decision (determines whether an existing CA record is reused).  Logged
                    // at Information so it survives production log filters and is not suppressible
                    // by log-level configuration.
                    _logger.LogInformation(
                        "Renewal window evaluation complete. " +
                        "PriorCARequestID={PriorId}, CertExpiry={Expiry:O}, " +
                        "RenewalWindowEnd={WindowEnd:O}, RenewalWindowDays={Window}, UseRenewalApi={Use}",
                        priorCaRequestId, expiry.Value, renewalWindowEnd, ep.RenewalWindowDays, useRenewalApi);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "Could not determine expiry for '{Id}'. Defaulting to new enrollment.", priorCaRequestId);
            }

            if (useRenewalApi)
            {
                // SOX / SOC2 CC7.3: log the renewal attempt at Information so the intent is
                // captured before the API call, enabling reconstruction if the call fails.
                _logger.LogInformation(
                    "Renewal via CERTInext renew API started. " +
                    "PriorCARequestID={PriorId}, Subject={Subject}, ProfileId={ProfileId}",
                    priorCaRequestId, subject, ep.ProfileId);

                var renewReq = new RenewCertificateRequest
                {
                    Csr = csr,
                    // Renewals go out as a fresh CERTInext order, so they need the same domain
                    // set as a new enrollment — otherwise a renewed UCC certificate comes back
                    // holding only its primary domain.
                    Subject = subject,
                    Sans = BuildSanList(san, csr),
                    ValidityDays = ep.ValidityDays > 0 ? ep.ValidityDays : (int?)null,
                    RequesterName = string.IsNullOrWhiteSpace(ep.RequesterName) ? null : ep.RequesterName,
                    RequesterEmail = string.IsNullOrWhiteSpace(ep.RequesterEmail) ? null : ep.RequesterEmail,
                    Comment = $"Renewed via Keyfactor Command. Prior ID: {priorCaRequestId}."
                };

                var renewResp = await _client.RenewCertificateAsync(priorCaRequestId, renewReq);
                var renewResult = BuildEnrollmentResult(renewResp, ep.AutoApprove);

                // SOX: log the renewal outcome so the new certificate ID and status are
                // independently recorded (the outer Enroll method also logs, but this
                // ensures the renew path is auditable if the result is further transformed).
                _logger.LogInformation(
                    "Renewal via CERTInext renew API complete. " +
                    "PriorCARequestID={PriorId}, NewCARequestID={NewId}, Status={Status}",
                    priorCaRequestId, renewResult.CARequestID, renewResult.Status);

                // Synchronous certificate pickup (Sectigo-parity), same as the new-enrollment path.
                // The renew path never runs an in-call DCV issuance wait, so pickup always applies.
                renewResult = await PickUpEnrolledCertificateAsync(renewResult, renewResp.Id, dcvIssuanceWaitRan: false);

                return renewResult;
            }
            else
            {
                _logger.LogInformation(
                    "Certificate '{Id}' is outside the renewal window ({Window} days) — issuing new certificate. Subject={Subject}",
                    priorCaRequestId, ep.RenewalWindowDays, subject);
                return await EnrollNewAsync(csr, subject, san, ep);
            }
        }

        // ---------------------------------------------------------------------------
        // DCV helpers
        // ---------------------------------------------------------------------------

        /// <summary>
        /// True when a <c>GetDcv</c> failure is the CERTInext-side "DCV slot is exposed in
        /// TrackOrder but the endpoint won't accept calls yet" condition.  Observed as the
        /// API error <c>EMS-956 "Invalid Request for this API"</c> for several hours after
        /// enrollment — see <c>analysis/certinext-support-ticket-2026-05-12.md</c>.
        ///
        /// Detection is intentionally narrow:
        ///  * If the message contains the literal code <c>EMS-956</c>, treat it as the
        ///    known not-ready condition.
        ///  * Otherwise, only fall back to the human-readable phrase match when *no other*
        ///    <c>EMS-NNN</c> code is present.  Without that guard, an upstream proxy or WAF
        ///    returning a 4xx whose body happens to contain "Invalid Request for this API …"
        ///    plus a different CERTInext code (e.g. EMS-401) would be silently deferred,
        ///    masking a real authentication or input-validation failure.
        /// </summary>
        private static bool IsDcvNotYetReady(Exception ex)
        {
            if (ex == null) return false;
            string msg = ex.Message ?? string.Empty;
            if (msg.IndexOf("EMS-956", StringComparison.OrdinalIgnoreCase) >= 0)
                return true;
            bool hasPhrase = msg.IndexOf("Invalid Request for this API", StringComparison.OrdinalIgnoreCase) >= 0;
            bool hasOtherEmsCode = System.Text.RegularExpressions.Regex.IsMatch(msg, @"\bEMS-\d+\b");
            return hasPhrase && !hasOtherEmsCode;
        }

        // (`DomainValidatorConfigProvider` nested helper removed — it declared an
        // implementation of `Keyfactor.AnyGateway.Extensions.IDomainValidatorConfigProvider`,
        // a v3.3-only interface, but the type was never instantiated anywhere in the
        // plugin. Keeping a nested type whose base list references a missing assembly
        // type is a hazard for CLR class-load on v3.2 hosts (see issue #7). Dead code
        // that costs nothing to remove.)

        /// <summary>
        /// Best-effort DCV retry for an order that may still be pending validation.
        ///
        /// Called from Synchronize and GetSingleRecord so that orders which CERTInext placed
        /// into "Pending for Approver"/"Pending System RA" between enrollment and the next
        /// gateway cycle (when domainVerification was still null at enroll time) can be
        /// driven forward through DCV. Wraps <see cref="PerformDcvIfNeededAsync"/> with:
        ///   * a per-order in-flight guard so overlapping sync cycles or a sync+single
        ///     refresh do not double-stage TXT records,
        ///   * a bounded DCV timeout linked to the caller's cancellation token,
        ///   * swallowing of non-cancellation exceptions so a single bad order does not
        ///     halt a 12-hour sync — the order will be retried on the next cycle.
        ///
        /// Uses a single-shot challenge check (<c>waitForChallengeSeconds=0</c>) by default
        /// because sync runs periodically: if CERTInext hasn't yet exposed the DCV slot for
        /// this order, the next sync cycle will pick it up.  Waiting per-order during sync
        /// scales poorly — a single pending order's 60s budget becomes minutes of wasted
        /// gateway thread time across an account with many orders.  See PR #2 discussion.
        ///
        /// Returns <c>true</c> when DCV actually executed (or DCV is already complete),
        /// <c>false</c> when skipped.
        /// </summary>
        private async Task<bool> TryRunDcvDuringSyncAsync(string orderNumber, CancellationToken ct, bool fastSync = false)
        {
            _logger.MethodEntry(LogLevel.Debug);
#if SUPPORTS_DCV
            if (_domainValidatorFactory == null || !_config.DcvEnabled || string.IsNullOrEmpty(orderNumber))
                return false;

            if (!_dcvInFlight.TryAdd(orderNumber, 0))
            {
                // SOC2 CC7.2: concurrent DCV-attempt collisions are security-relevant
                // (they indicate either a normal overlap of two sync cycles OR an attempt
                // to interleave operations on the same order). Log at Information so the
                // event appears in production logs without verbose-debug being enabled.
                _logger.LogInformation(
                    "DCV already in flight for order {OrderNumber}; skipping concurrent attempt.",
                    orderNumber);
                return false;
            }

            try
            {
                int timeoutMinutes = _config.GetEffectiveDcvTimeoutMinutes();
                using var dcvCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                dcvCts.CancelAfter(TimeSpan.FromMinutes(timeoutMinutes));

                _logger.LogInformation(
                    "Attempting deferred DCV during sync/refresh (single-shot challenge check). " +
                    "OrderNumber={OrderNumber}, DcvTimeoutMinutes={Timeout}",
                    orderNumber, timeoutMinutes);

                return await PerformDcvIfNeededAsync(orderNumber, dcvCts.Token,
                    waitForChallengeSecondsOverride: 0,
                    propagationDelaySecondsOverride: fastSync ? Constants.Dcv.SyncPropagationDelaySeconds : (int?)null);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "Deferred DCV attempt failed for order {OrderNumber}. Order will be retried on the next sync cycle.",
                    orderNumber);
                return false;
            }
            finally
            {
                _dcvInFlight.TryRemove(orderNumber, out _);
            }
#else
            // DCV is not supported on this build (IAnyCAPlugin 3.2.0). No-op: pending orders
            // are reported as EXTERNALVALIDATION and not advanced during sync. See issue 0003.
            await Task.CompletedTask;
            return false;
#endif
        }

        /// <summary>
        /// Runs DNS DCV for any domains on <paramref name="orderNumber"/> that are still pending
        /// validation.  Returns <c>true</c> when DCV steps were executed, <c>false</c> when
        /// skipped (order already issued, no pending domains, or factory not available).
        ///
        /// Rule: if the order is already issued we never attempt DCV — it would be a no-op
        /// at best and could confuse the CA at worst.
        ///
        /// <paramref name="waitForChallengeSecondsOverride"/> lets the sync path force a
        /// single-shot challenge check (pass <c>0</c>) so a sync cycle doesn't spend up to
        /// <c>DcvWaitForChallengeSeconds</c> per pending order waiting for CERTInext to
        /// expose the DCV slot — sync runs periodically, so unexposed orders are picked up
        /// on the next cycle instead.  Enroll passes <c>null</c> to keep the full configured
        /// budget (user-visible latency benefits from a one-shot end-to-end finish).
        /// </summary>
#if SUPPORTS_DCV
        private async Task<bool> PerformDcvIfNeededAsync(
            string orderNumber,
            CancellationToken ct,
            int? waitForChallengeSecondsOverride = null,
            int? propagationDelaySecondsOverride = null)
        {
            // Poll TrackOrder until CERTInext exposes the DCV challenge (domainVerification
            // populated) OR the cert reaches a terminal state OR the wait budget expires.
            // Under concurrent enrollment load CERTInext sometimes takes a few seconds to
            // materialize the slot after GenerateOrderSSL returns — without this wait a
            // race-condition order skips DCV entirely and waits for the next sync cycle.
            int waitBudgetSeconds = waitForChallengeSecondsOverride
                ?? _config.GetEffectiveDcvWaitForChallengeSeconds();
            // Challenge-wait poll interval is clamped to [1s, 5s] so it's responsive even
            // when an admin has set DcvPropagationDelaySeconds high for slow zones (that
            // setting governs how long we wait *after* publishing a TXT record, which is a
            // different, slower concern than how often we re-check TrackOrder here).
            int challengePollSeconds = Math.Max(1, Math.Min(5, _config.DcvPropagationDelaySeconds > 0 ? _config.DcvPropagationDelaySeconds : 5));
            var waitDeadline = DateTime.UtcNow.AddSeconds(Math.Max(0, waitBudgetSeconds));

            TrackOrderResponse track = null;
            API.TrackOrderDomainVerification domainVerification = null;
            int pollAttempts = 0;

            while (true)
            {
                pollAttempts++;
                ct.ThrowIfCancellationRequested();
                track = await _client.TrackOrderAsync(orderNumber, ct);

                // Skip DCV entirely if the certificate is already issued or revoked
                if (track.OrderDetails != null
                    && int.TryParse(track.OrderDetails.CertificateStatusId, out int certStatusId))
                {
                    int disposition = StatusMapper.CertificateStatusIdToRequestDisposition(certStatusId);
                    if (disposition == (int)EndEntityStatus.GENERATED || disposition == (int)EndEntityStatus.REVOKED)
                    {
                        _logger.LogDebug(
                            "DCV skipped — order {OrderNumber} is already in terminal state (certificateStatusId={Status}).",
                            orderNumber, certStatusId);
                        return false;
                    }
                }

                // Skip if the order itself reached a terminal failure state.  Without this
                // the cached-DCV path below could still return true on a cancelled order
                // (domainVerification.Status = "1" survives the cancellation), sending the
                // caller into a wasted DcvWaitForIssuanceSeconds-long GetCertificate poll
                // that can never resolve. OrderStatusId 4 = cancelled, 5 = rejected.
                if (track.OrderDetails?.OrderStatusId is "4" or "5")
                {
                    _logger.LogDebug(
                        "DCV skipped — order {OrderNumber} is cancelled/rejected " +
                        "(orderStatusId={OrderStatus}).",
                        orderNumber, track.OrderDetails.OrderStatusId);
                    return false;
                }

                domainVerification = track.OrderDetails?.DomainVerification;
                if (domainVerification != null)
                    break;

                // domainVerification still null — sleep and retry if we have budget left.
                if (waitBudgetSeconds <= 0 || DateTime.UtcNow >= waitDeadline)
                {
                    _logger.LogInformation(
                        "DCV challenge not exposed by CERTInext within {Budget}s for order {OrderNumber} " +
                        "(attempted {Attempts} TrackOrder polls). Deferring to next sync cycle.",
                        waitBudgetSeconds, orderNumber, pollAttempts);
                    return false;
                }

                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(challengePollSeconds), ct);
                }
                catch (OperationCanceledException)
                {
                    return false;
                }
            }

            // If DCV is already validated CERTInext-side, the plugin has no DCV work to
            // do — but CERTInext's certificate generation may still be in flight (this
            // happens when CERTInext has cached a prior DCV validation for the parent
            // domain).  Return true so the caller can run the issuance poll and pick up
            // the cert directly from Enroll() instead of leaving it for the next sync.
            //
            // Treat "DCV done" as EITHER the overall aggregate Status flipping to "1"
            // OR every individual per-domain dcvStatus being "1" — observed in the wild
            // that the per-domain field can flip before the parent aggregate.
            var allDomainEntries = domainVerification.GetDomainEntries();
            bool aggregateValidated = string.Equals(
                domainVerification.Status, Constants.Dcv.StatusValidated, StringComparison.Ordinal);
            bool everyDomainValidated = allDomainEntries.Count > 0
                && allDomainEntries.All(kvp => string.Equals(
                    kvp.Value?.DcvStatus, Constants.Dcv.StatusValidated, StringComparison.Ordinal));
            if (aggregateValidated || everyDomainValidated)
            {
                _logger.LogInformation(
                    "DCV is already validated for order {OrderNumber} " +
                    "(aggregateStatus={Aggregate}, perDomainAllValidated={PerDomain}). " +
                    "Skipping DNS-TXT staging; caller may run the issuance poll.",
                    orderNumber, aggregateValidated, everyDomainValidated);
                return true;
            }

            // Include domains that are pending DCV and either have no method set yet,
            // or are already assigned to DNS TXT (numeric "1" from API or label from TrackOrder).
            // Domains assigned to HTTP or email DCV are excluded — we must not override them.
            var pendingDomains = domainVerification.GetDomainEntries()
                .Where(kvp =>
                {
                    if (!string.Equals(kvp.Value?.DcvStatus, Constants.Dcv.StatusPending, StringComparison.Ordinal))
                        return false;
                    string method = kvp.Value?.DcvMethod ?? string.Empty;
                    return string.IsNullOrEmpty(method)
                        || string.Equals(method, Constants.Dcv.MethodDnsTxt, StringComparison.Ordinal)
                        || string.Equals(method, Constants.Dcv.MethodDnsTxtLabel, StringComparison.OrdinalIgnoreCase);
                })
                .ToList();

            // SOX CC6.1: validate domain names before passing them to the DNS provider plugin
            // or the CERTInext API.  A malformed domain (empty, whitespace, or containing
            // characters outside the FQDN alphabet) could cause log injection or unexpected
            // DNS plugin behaviour.  Invalid entries are rejected loudly rather than silently
            // skipped so the condition is visible in the audit trail.
            foreach (var (domain, _) in pendingDomains)
            {
                if (string.IsNullOrWhiteSpace(domain))
                    throw new InvalidOperationException(
                        $"TrackOrder returned a blank domain key in domainVerification for order '{orderNumber}'. " +
                        "Cannot proceed with DCV.");

                // Allow standard FQDN characters plus wildcard prefix (*.example.com)
                if (!System.Text.RegularExpressions.Regex.IsMatch(domain, @"^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$"))
                {
                    _logger.LogError(
                        "DCV domain name failed validation and will not be processed. OrderNumber={OrderNumber}, Domain={Domain}",
                        orderNumber, domain);
                    throw new InvalidOperationException(
                        $"TrackOrder returned an invalid domain name '{domain}' in domainVerification for order '{orderNumber}'. " +
                        "Domain names must conform to FQDN syntax.");
                }
            }

            if (pendingDomains.Count == 0)
                return false;

            _logger.LogInformation(
                "DCV required for order {OrderNumber}. Pending DNS TXT domains: [{Domains}]",
                orderNumber, string.Join(", ", pendingDomains.Select(x => x.Key)));

            var stagedValidations = new List<(string domain, string hostname, Keyfactor.AnyGateway.Extensions.IDomainValidator validator)>();

            // Stage DNS TXT records for all pending domains
            foreach (var (domain, _) in pendingDomains)
            {
                GetDcvResponse dcvResp;
                try
                {
                    dcvResp = await _client.GetDcvAsync(orderNumber, domain, Constants.Dcv.MethodDnsTxt, ct);
                }
                catch (Exception ex) when (IsDcvNotYetReady(ex))
                {
                    // CERTInext occasionally exposes the DCV slot in TrackOrder (so
                    // domainVerification is populated and dcvStatus="0") before the GetDcv
                    // endpoint will accept calls for that order — observed as EMS-956
                    // "Invalid Request for this API" for several hours after enrollment.
                    // Treat this as "DCV not ready yet": skip the DCV ceremony for now and
                    // let the sync-driven retry pick it up on a later cycle. We must NOT
                    // throw, because that would fail the entire Enroll call and prevent the
                    // gateway from recording the pending order at all.
                    _logger.LogInformation(
                        "GetDcv not yet accepting calls for order {OrderNumber} domain {Domain} ({Error}). " +
                        "Deferring DCV to the next sync cycle.",
                        orderNumber, domain, ex.Message);
                    return false;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "GetDcv failed for order {OrderNumber} domain {Domain}", orderNumber, domain);
                    throw;
                }

                string token = dcvResp.DcvDetails?.Token;
                if (string.IsNullOrWhiteSpace(token))
                    throw new InvalidOperationException(
                        $"GetDcv returned no token for order '{orderNumber}' domain '{domain}'.");

                string template = string.IsNullOrWhiteSpace(_config.DcvTxtRecordTemplate)
                    ? Constants.Dcv.DefaultTxtRecordTemplate
                    : _config.DcvTxtRecordTemplate;
                string hostname = string.Format(template, domain);

                var validator = DomainValidatorFactory.ResolveDomainValidator(domain, "dns-01");
                if (validator == null)
                    throw new InvalidOperationException(
                        $"No DNS provider plugin is configured for domain '{domain}'. " +
                        "Ensure the appropriate DNS provider plugin is deployed and configured on the gateway.");

                _logger.LogInformation(
                    "Staging DNS TXT record for DCV. OrderNumber={OrderNumber}, Domain={Domain}, Hostname={Hostname}",
                    orderNumber, domain, hostname);

                var stageResult = await validator.StageValidation(hostname, token, ct);
                if (!stageResult.Success)
                    throw new InvalidOperationException(
                        $"Failed to stage DNS validation for '{domain}': {stageResult.ErrorMessage}");

                stagedValidations.Add((domain, hostname, validator));
            }

            if (stagedValidations.Count == 0)
                return false;

            try
            {
                // Allow DNS propagation before asking CERTInext to verify. The sync path passes
                // a short override (issue 0002) so a bounded set of recent pending orders doesn't
                // each burn the full configured delay; Enroll uses the full configured value.
                int delaySeconds = propagationDelaySecondsOverride
                    ?? (_config.DcvPropagationDelaySeconds > 0 ? _config.DcvPropagationDelaySeconds : 30);
                _logger.LogInformation(
                    "Waiting {Delay}s for DNS propagation before verifying DCV. OrderNumber={OrderNumber}",
                    delaySeconds, orderNumber);
                await Task.Delay(TimeSpan.FromSeconds(delaySeconds), ct);

                foreach (var (domain, hostname, _) in stagedValidations)
                {
                    _logger.LogInformation(
                        "Triggering CERTInext DCV verification. OrderNumber={OrderNumber}, Domain={Domain}", orderNumber, domain);
                    await _client.VerifyDcvAsync(orderNumber, domain, Constants.Dcv.MethodDnsTxt, ct);
                }

                // Poll TrackOrder until CERTInext confirms all staged domains are verified
                // before removing TXT records — VerifyDcv triggers an async DNS lookup on
                // their side, so cleanup must wait for dcvStatus=1 on every domain.
                await WaitForDcvVerificationAsync(orderNumber, stagedValidations.Select(s => s.domain).ToList(), ct);
            }
            finally
            {
                // Always clean up staged DNS records — even on failure
                foreach (var (domain, hostname, validator) in stagedValidations)
                {
                    try
                    {
                        await validator.CleanupValidation(hostname, ct);
                        _logger.LogInformation(
                            "DNS TXT record cleaned up. Domain={Domain}, Hostname={Hostname}", domain, hostname);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex,
                            "Failed to clean up DNS TXT record. Domain={Domain}, Hostname={Hostname}", domain, hostname);
                    }
                }
            }

            return true;
        }
#endif

        /// <summary>
        /// Polls <c>GetCertificateAsync</c> until either (a) the certificate reaches a terminal
        /// state (issued or rejected) or (b) the configured <c>DcvWaitForIssuanceSeconds</c>
        /// budget expires.  Returns the final response on success, or <c>null</c> if all polls
        /// failed (so callers fall back to the pending result they already have).
        ///
        /// CERTInext's issuance pipeline is asynchronous on their side: after the plugin's
        /// VerifyDcv triggers and the per-domain DCV is confirmed, the cert generation step
        /// finishes a few seconds later.  Without this poll the plugin would catch the cert
        /// in pending state and return it that way, forcing the gateway to wait for the next
        /// sync cycle.
        /// </summary>
        private async Task<LegacyGetCertificateResponse> WaitForIssuanceAfterDcvAsync(
            string orderNumber, CancellationToken ct)
        {
            int waitBudgetSeconds = _config.GetEffectiveDcvWaitForIssuanceSeconds();

            // Fixed 3-second poll interval. CERTInext's post-DCV issuance step typically
            // completes within 5–15s; polling more aggressively would just add API load,
            // and polling more slowly would push the typical-case latency closer to the
            // budget ceiling. Decoupled from DcvPropagationDelaySeconds (which is for DNS
            // propagation, a different concern) so admins tuning DNS settings don't
            // accidentally make post-DCV polling chunky.
            int pollIntervalSeconds = 3;
            DateTime deadline = DateTime.UtcNow.AddSeconds(Math.Max(0, waitBudgetSeconds));
            LegacyGetCertificateResponse last = null;

            // Admin opt-out: budget <= 0 means "don't wait, let sync pick the cert up".
            // Short-circuit before any API call so the gateway doesn't pay a TrackOrder +
            // optional DownloadCertificate round trip per Enroll when the admin has
            // explicitly disabled the wait.
            if (waitBudgetSeconds <= 0)
            {
                _logger.LogDebug(
                    "Post-DCV issuance wait disabled (DcvWaitForIssuanceSeconds<=0). " +
                    "Order {OrderNumber} will be picked up on the next sync cycle.",
                    orderNumber);
                return null;
            }

            int attempt = 0;
            while (true)
            {
                attempt++;
                ct.ThrowIfCancellationRequested();
                try
                {
                    last = await _client.GetCertificateAsync(orderNumber, ct);
                }
                catch (Exception ex)
                {
                    // Distinguish first-call failure (no result to return, sync must pick up)
                    // from later-poll failure (we have a prior pending result that the caller
                    // can use as a fallback). Without this distinction a repeated first-call
                    // failure would look identical to a working-but-always-pending enroll.
                    _logger.LogWarning(ex,
                        "Post-DCV GetCertificate failed for order {OrderNumber} (attempt {Attempt}). " +
                        "Returning {Outcome}; sync will pick up the cert later.",
                        orderNumber, attempt, last == null ? "pending fallback (no prior result)" : "prior pending result");
                    return last;
                }

                int disposition = StatusMapper.ToRequestDisposition(last.Status);
                if (disposition == (int)EndEntityStatus.GENERATED
                    || disposition == (int)EndEntityStatus.REVOKED
                    || disposition == (int)EndEntityStatus.FAILED)
                {
                    return last;
                }

                if (waitBudgetSeconds <= 0 || DateTime.UtcNow >= deadline)
                {
                    _logger.LogInformation(
                        "Post-DCV issuance not complete within {Budget}s for order {OrderNumber}. " +
                        "Returning pending result; sync will pick up the cert later.",
                        waitBudgetSeconds, orderNumber);
                    return last;
                }

                try
                {
                    await Task.Delay(TimeSpan.FromSeconds(pollIntervalSeconds), ct);
                }
                catch (OperationCanceledException)
                {
                    return last;
                }
            }
        }

        /// <summary>
        /// Polls <see cref="ICERTInextClient.TrackOrderAsync"/> until every domain in
        /// <paramref name="domains"/> reaches <c>dcvStatus=1</c> (verified) or a terminal
        /// failure state (rejected/cancelled), or <paramref name="ct"/> is cancelled.
        /// Called after <c>VerifyDcvAsync</c> to ensure CERTInext has completed its async
        /// DNS lookup before TXT records are cleaned up.
        /// </summary>
        private async Task WaitForDcvVerificationAsync(string orderNumber, IReadOnlyList<string> domains, CancellationToken ct)
        {
            if (domains.Count == 0) return;

            var pending = new HashSet<string>(domains, StringComparer.OrdinalIgnoreCase);
            int pollSeconds = Math.Max(1, _config.DcvPropagationDelaySeconds);

            // Defense-in-depth deadline: SOX CC7.3 requires every wait to be bounded.
            // The caller passes a `ct` derived from a CancellationTokenSource that already
            // cancels after `DcvTimeoutMinutes`, so this method is bounded via that path.
            // We add an explicit internal deadline so a future refactor breaking the
            // cancellation chain (e.g. accidentally passing CancellationToken.None) can't
            // make this loop unbounded — it would still exit on the deadline below.
            var verificationDeadline = DateTime.UtcNow.AddMinutes(_config.GetEffectiveDcvTimeoutMinutes());

            while (pending.Count > 0 && !ct.IsCancellationRequested)
            {
                if (DateTime.UtcNow >= verificationDeadline)
                {
                    _logger.LogWarning(
                        "DCV verification poll exceeded its internal deadline ({Minutes}min). " +
                        "OrderNumber={OrderNumber}, StillPendingDomains=[{Pending}].  " +
                        "Exiting and leaving TXT records for the caller's finally block to clean up.",
                        _config.GetEffectiveDcvTimeoutMinutes(), orderNumber, string.Join(",", pending));
                    return;
                }

                await Task.Delay(TimeSpan.FromSeconds(pollSeconds), ct);

                TrackOrderResponse poll;
                try { poll = await _client.TrackOrderAsync(orderNumber, ct); }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "TrackOrder polling failed during DCV wait. OrderNumber={OrderNumber}", orderNumber);
                    return;
                }

                var entries = poll.OrderDetails?.DomainVerification?.GetDomainEntries()
                              ?? new Dictionary<string, API.DomainVerificationDetail>();

                // Check for order-level terminal failure (cancelled/rejected)
                if (poll.OrderDetails?.OrderStatusId is "4" or "5")
                {
                    _logger.LogWarning(
                        "Order {OrderNumber} reached terminal failure state (OrderStatusId={Status}) during DCV wait. TXT records will be cleaned up.",
                        orderNumber, poll.OrderDetails.OrderStatusId);
                    return;
                }

                foreach (var domain in domains)
                {
                    if (!pending.Contains(domain)) continue;
                    if (!entries.TryGetValue(domain, out var detail)) continue;

                    if (string.Equals(detail.DcvStatus, Constants.Dcv.StatusValidated, StringComparison.Ordinal))
                    {
                        _logger.LogInformation("DCV verified by CERTInext. OrderNumber={OrderNumber}, Domain={Domain}", orderNumber, domain);
                        pending.Remove(domain);
                    }
                    else if (string.Equals(detail.DcvStatus, Constants.Dcv.StatusRejected, StringComparison.Ordinal))
                    {
                        _logger.LogWarning("DCV rejected by CERTInext. OrderNumber={OrderNumber}, Domain={Domain}", orderNumber, domain);
                        pending.Remove(domain);
                    }
                }
            }
        }

        /// <summary>
        /// Synchronous certificate pickup — parity with the legacy Sectigo connector's
        /// <c>PickUpEnrolledCertificate</c>. After an order is submitted, polls
        /// <c>GetCertificate</c> up to <c>PickupRetries</c> times, <c>PickupDelay</c> seconds
        /// apart (after a fixed initial delay), so an order that issues quickly is returned
        /// GENERATED + PEM in the same enrollment call instead of waiting for the next
        /// synchronization. If the certificate has not issued within the budget, the original
        /// pending result is returned unchanged and the order is imported by a later sync —
        /// behaviour identical to before this feature.
        ///
        /// Applies to ALL products. CERTInext issues OV/EV asynchronously (organization
        /// verification, minutes to hours; confirmed by CERTInext support ticket #162763), so
        /// those typically exhaust the budget and fall back to pending; only DV / already-approved
        /// orders return in-call. Never throws — any polling error degrades to the pending result.
        /// </summary>
        private async Task<EnrollmentResult> PickUpEnrolledCertificateAsync(
            EnrollmentResult pendingResult, string orderNumber, bool dcvIssuanceWaitRan)
        {
            // The DCV path already owns the in-call issuance wait for this order — running a second
            // stacked poll here would double the wait budget (when DCV ran WaitForIssuanceAfterDcvAsync)
            // or waste it polling an order DCV already found terminal / not-yet-validated. Defer to
            // the pending result; a later sync completes it.
            if (dcvIssuanceWaitRan)
                return pendingResult;

            // Only a still-pending (external-validation) result can benefit from a pickup poll.
            // An already issued/failed/revoked result is returned as-is.
            if (pendingResult == null
                || pendingResult.Status != (int)EndEntityStatus.EXTERNALVALIDATION)
                return pendingResult;

            // A pending result with no order number cannot be polled — surface the anomaly rather
            // than silently returning, so an un-pollable pending state leaves an audit trace.
            if (string.IsNullOrWhiteSpace(orderNumber))
            {
                _logger.LogWarning(
                    "Synchronous pickup skipped: a pending enrollment was returned with no order " +
                    "number to poll. The certificate can only be reconciled by a later synchronization.");
                return pendingResult;
            }

            int retries = _config.GetEffectivePickupRetries();
            if (retries <= 0)
            {
                _logger.LogInformation(
                    "Synchronous certificate pickup disabled (PickupRetries<=0). Order {OrderNumber} " +
                    "will be picked up on the next synchronization.", orderNumber);
                return pendingResult;
            }

            int delaySeconds = _config.GetEffectivePickupDelaySeconds();

            // Hard ceiling on total in-call occupancy. PickupRetries and PickupDelay are each clamped
            // independently, but their product can still reach ~30 min at the extremes — enough to push
            // Enroll() past Command's own enrollment timeout. If the configured budget would exceed the
            // ceiling, cap the retry count to fit; the remainder is imported by the next synchronization.
            int maxPollRetries = Math.Max(1,
                (Constants.Pickup.MaxTotalWaitSeconds - Constants.Pickup.InitialDelaySeconds) / delaySeconds);
            if (retries > maxPollRetries)
            {
                _logger.LogInformation(
                    "Configured pickup budget (PickupRetries={Configured}, PickupDelaySeconds={Delay}) exceeds the " +
                    "{MaxTotal}s in-call ceiling; capping to {Capped} attempts. The certificate will be imported by " +
                    "the next synchronization if it has not issued by then.",
                    retries, delaySeconds, Constants.Pickup.MaxTotalWaitSeconds, maxPollRetries);
                retries = maxPollRetries;
            }

            _logger.LogInformation(
                "Starting synchronous certificate pickup. OrderNumber={OrderNumber}, PickupRetries={Retries}, " +
                "PickupDelaySeconds={Delay} (max ~{Max}s including a {Initial}s initial delay).",
                orderNumber, retries, delaySeconds,
                Constants.Pickup.InitialDelaySeconds + retries * delaySeconds, Constants.Pickup.InitialDelaySeconds);

            int pollErrors = 0;
            try
            {
                // Small static delay before the first poll — mirrors the Sectigo connector's
                // attempt to let a fast order finish issuing before we start polling at all.
                await Task.Delay(TimeSpan.FromSeconds(Constants.Pickup.InitialDelaySeconds));

                for (int attempt = 1; attempt <= retries; attempt++)
                {
                    try
                    {
                        var cert = await _client.GetCertificateAsync(orderNumber);
                        int disposition = StatusMapper.ToRequestDisposition(cert.Status);

                        // SOC2 CC7.3: record each poll's observed disposition so the issuance
                        // timeline is reconstructable (how many polls ran, what each returned).
                        _logger.LogDebug(
                            "Pickup poll observed status. OrderNumber={OrderNumber}, Attempt={Attempt}/{Retries}, " +
                            "MappedDisposition={Disposition}, Status='{Status}', BodyPresent={HasBody}.",
                            orderNumber, attempt, retries, disposition, cert.Status,
                            !string.IsNullOrWhiteSpace(cert.Certificate));

                        // Issued: only surface GENERATED when the PEM is actually present — never
                        // hand Command a body-less "issued" record. A body-less issued state keeps
                        // polling until the body appears or the budget runs out.
                        if (disposition == (int)EndEntityStatus.GENERATED
                            && !string.IsNullOrWhiteSpace(cert.Certificate))
                        {
                            _logger.LogInformation(
                                "Synchronous pickup complete. OrderNumber={OrderNumber}, SerialNumber={Serial}, " +
                                "Attempt={Attempt}/{Retries}.",
                                orderNumber,
                                string.IsNullOrWhiteSpace(cert.SerialNumber) ? "(none)" : cert.SerialNumber,
                                attempt, retries);
                            return new EnrollmentResult
                            {
                                CARequestID = string.IsNullOrWhiteSpace(cert.Id) ? orderNumber : cert.Id,
                                Certificate = cert.Certificate,
                                Status = (int)EndEntityStatus.GENERATED,
                                StatusMessage = $"Certificate issued successfully. CERTInext ID: {orderNumber}."
                            };
                        }

                        // Terminal non-issued outcomes carry no body and are surfaced immediately.
                        if (disposition == (int)EndEntityStatus.REVOKED
                            || disposition == (int)EndEntityStatus.FAILED)
                        {
                            // SOX/SOC2 CC7.2: an issuance FAILURE must cross the error threshold that
                            // SIEM issuance-failure rules key on (parity with BuildEnrollmentResult's
                            // enroll-time FAILED handling); a REVOKED terminal state is a warning.
                            if (disposition == (int)EndEntityStatus.FAILED)
                                _logger.LogError(
                                    "Order {OrderNumber} reached terminal FAILED status '{Status}' during " +
                                    "synchronous pickup (attempt {Attempt}/{Retries}).",
                                    orderNumber, cert.Status, attempt, retries);
                            else
                                _logger.LogWarning(
                                    "Order {OrderNumber} was REVOKED ('{Status}') during synchronous pickup " +
                                    "(attempt {Attempt}/{Retries}).",
                                    orderNumber, cert.Status, attempt, retries);
                            return new EnrollmentResult
                            {
                                CARequestID = string.IsNullOrWhiteSpace(cert.Id) ? orderNumber : cert.Id,
                                Certificate = cert.Certificate,
                                Status = disposition,
                                StatusMessage = $"Order {orderNumber} reached status '{cert.Status}' during enrollment pickup."
                            };
                        }
                    }
                    catch (Exception ex)
                    {
                        // A transient fetch failure consumes an attempt rather than aborting the
                        // wait; if it never recovers the pending result is returned below.
                        pollErrors++;
                        _logger.LogWarning(ex,
                            "Pickup GetCertificate failed for order {OrderNumber} (attempt {Attempt}/{Retries}).",
                            orderNumber, attempt, retries);
                    }

                    // Delay after every attempt (including the last), matching the Sectigo
                    // connector's pickup cadence so the max-occupancy ceiling is identical.
                    await Task.Delay(TimeSpan.FromSeconds(delaySeconds));
                }

                // SOC1 accuracy: don't attribute non-completion to "OV/EV async by design" when the
                // real cause was every poll erroring (e.g. a CA-side TrackOrder outage). Distinguish
                // the two so the log reflects what actually happened.
                if (pollErrors == retries)
                    _logger.LogWarning(
                        "Synchronous pickup exhausted {Retries} attempts for order {OrderNumber} — ALL polls " +
                        "errored (see preceding warnings). Returning pending result; the next synchronization " +
                        "will re-attempt retrieval.",
                        retries, orderNumber);
                else
                    _logger.LogInformation(
                        "Synchronous pickup did not complete within {Retries} attempts for order {OrderNumber} " +
                        "({Errors} poll error(s); remainder still pending). Returning pending result; the " +
                        "certificate will be imported by the next synchronization. CERTInext issues OV/EV " +
                        "asynchronously by design (support ticket #162763).",
                        retries, orderNumber, pollErrors);
                pendingResult.StatusMessage =
                    $"{pendingResult.StatusMessage} The certificate was not issued within the enrollment-pickup " +
                    "window; it will be imported by a later synchronization.";
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "Synchronous pickup failed for order {OrderNumber}. Returning pending result; " +
                    "sync will pick up the certificate later.", orderNumber);
            }

            return pendingResult;
        }

        /// <summary>
        /// Converts a CERTInext API enrollment/renewal response into the
        /// <see cref="EnrollmentResult"/> expected by the AnyCA gateway.
        /// </summary>
        private EnrollmentResult BuildEnrollmentResult(EnrollCertificateResponse resp, bool autoApprove)
        {
            if (resp == null)
                throw new Exception("CERTInext returned a null enrollment response.");

            int status = StatusMapper.ToRequestDisposition(resp.Status);
            string message;

            switch (status)
            {
                case (int)EndEntityStatus.GENERATED:
                    message = $"Certificate issued successfully. CERTInext ID: {resp.Id}.";
                    break;

                case (int)EndEntityStatus.EXTERNALVALIDATION:
                    message = $"Certificate is pending approval in CERTInext. ID: {resp.Id}. " +
                              "The certificate will be picked up during the next synchronization " +
                              "once approved.";
                    _logger.LogInformation(
                        "Certificate '{Id}' is in pending-approval state.", resp.Id);
                    break;

                case (int)EndEntityStatus.FAILED:
                    message = $"Certificate request failed in CERTInext. Message: {resp.Message}.";
                    _logger.LogError("Enrollment failed for CERTInext ID '{Id}': {Msg}", resp.Id, resp.Message);
                    break;

                default:
                    message = $"Certificate request status is '{resp.Status}'. CERTInext ID: {resp.Id}.";
                    break;
            }

            return new EnrollmentResult
            {
                CARequestID = resp.Id,
                Certificate = resp.Certificate,
                Status = status,
                StatusMessage = message
            };
        }

        /// <summary>
        /// Maps a <see cref="LegacyGetCertificateResponse"/> to the gateway's
        /// <see cref="AnyCAPluginCertificate"/> type.
        /// </summary>
        private static AnyCAPluginCertificate MapToAnyCAPluginCertificate(LegacyGetCertificateResponse cert)
        {
            int status = StatusMapper.ToRequestDisposition(cert.Status);

            return new AnyCAPluginCertificate
            {
                CARequestID = cert.Id,
                Certificate = string.IsNullOrWhiteSpace(cert.Certificate) ? null : cert.Certificate,
                Status = status,
                ProductID = cert.ProfileId,
                CSR = cert.Csr,
                RevocationDate = cert.RevokedAt,
                RevocationReason = cert.RevocationReason != null
                    ? MapRevocationReasonStringToCode(cert.RevocationReason)
                    : 0
            };
        }

        /// <summary>
        /// Converts a CERTInext revocation reason string back to the RFC 5280 integer code
        /// for storage in the Keyfactor Command database.
        /// </summary>
        private static int MapRevocationReasonStringToCode(string reason)
        {
            switch (reason?.ToLowerInvariant())
            {
                case "unspecified": return 0;
                case "keycompromise": return 1;
                case "cacompromise": return 2;
                case "affiliationchanged": return 3;
                case "superseded": return 4;
                case "cessationofoperation": return 5;
                case "certificatehold": return 6;
                case "removefromcrl": return 8;
                case "privilegewithdrawn": return 9;
                case "aacompromise": return 10;
                default: return 0;
            }
        }

        /// <summary>
        /// Builds the <see cref="SanEntry"/> list submitted to CERTInext, from the union of
        /// two sources: the multi-valued SAN dictionary the AnyCA gateway hands us, and the
        /// subjectAltName extension carried inside the CSR itself.
        ///
        /// Both sources are needed. The gateway dictionary is authoritative when Command
        /// populates it, but not every enrollment path does — and the CSR is the only place
        /// the requested names are guaranteed to appear, because the client built it. Union
        /// + de-duplicate rather than preferring one, so a name requested in either place
        /// reaches the order.
        ///
        /// Parsing the CSR here is not redundant with sending the CSR to CERTInext.
        /// CERTInext ignores the CSR's subjectAltName extension outright — measured in
        /// <c>SanSubmissionProbeTests</c>: a CSR carrying two DNS names, submitted with
        /// <c>additionalDomains</c> omitted, produced an order with only the CN registered.
        /// Re-submitting the CSR's names through <c>additionalDomains</c> is the only way a
        /// SAN that exists solely in the CSR reaches the issued certificate.
        ///
        /// History (UCC SANs silently dropped): the gateway keys this dictionary
        /// <c>dnsname</c>, not <c>dns</c>. <see cref="MapSanType"/> did not recognize
        /// <c>dnsname</c>, so every DNS SAN was typed <c>"dnsname"</c>, filtered out by the
        /// DNS-only test in <c>BuildAdditionalDomains</c>, and the order went to CERTInext
        /// with no <c>additionalDomains</c> at all. The certificate came back holding only
        /// the CN, which reads as the CA stripping SANs supplied on the CSR.
        /// </summary>
        private List<SanEntry> BuildSanList(Dictionary<string, string[]> san, string csr)
        {
            var result = new List<SanEntry>();
            // Type+value identity, so the same name requested as two different SAN types is
            // preserved while an exact repeat across the two sources collapses.
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            void Add(string type, string value)
            {
                if (string.IsNullOrWhiteSpace(value)) return;
                string trimmed = value.Trim();
                if (!seen.Add($"{type}|{trimmed}")) return;
                result.Add(new SanEntry { Type = type, Value = trimmed });
            }

            // AnyCA passes SANs keyed by type name — the real gateway uses "dnsname",
            // "rfc822name", "ipaddress"; MapSanType normalizes the spelling variants.
            if (san != null)
            {
                foreach (var kvp in san)
                {
                    string sanType = MapSanType(kvp.Key);
                    if (kvp.Value == null) continue;

                    foreach (string value in kvp.Value)
                        Add(sanType, value);
                }
            }

            int fromGateway = result.Count;

            // Union in whatever the CSR asked for. Non-throwing: a malformed or unparseable
            // CSR yields an empty list and leaves the gateway-supplied set untouched.
            foreach (var csrSan in ExtractSanEntriesFromCsr(csr))
                Add(csrSan.Type, csrSan.Value);

            int fromCsrOnly = result.Count - fromGateway;

            if (result.Count == 0)
            {
                _logger.LogDebug(
                    "No SANs supplied by the gateway and none found in the CSR — submitting the order with domainName only.");
                return null;
            }

            // The blind spot that hid the original defect was that nothing logged what we
            // resolved. Log the full resolved set and its provenance at Information.
            _logger.LogInformation(
                "Resolved {Total} SAN(s) for submission. FromGatewayRequest={FromGateway}, " +
                "AddedFromCsr={FromCsr}, Sans={Sans}",
                result.Count, fromGateway, fromCsrOnly,
                string.Join("; ", result.Select(s => $"{s.Type}:{s.Value}")));

            if (fromCsrOnly > 0)
            {
                // Worth a Warning, not Debug: it means Command did not hand us names the
                // client actually requested, which is a gateway/template wiring smell even
                // though we recover from it here.
                _logger.LogWarning(
                    "{Count} SAN(s) were present in the CSR but absent from the SAN data supplied by Command; " +
                    "they have been added to the order. Review the enrollment pattern / template SAN configuration.",
                    fromCsrOnly);
            }

            // CERTInext's certificateInformation.additionalDomains is a domain-name field, and
            // non-DNS SANs are submitted into it deliberately rather than discarded: dropping
            // them would issue a certificate silently missing names the subscriber asked for,
            // which is the worse failure.
            //
            // Measured behaviour (SanSubmissionProbeTests, product 844, 2026-08-12): CERTInext
            // does NOT reject these at order placement. It accepts the order and registers the
            // value verbatim as an order domain — an email address, an IP literal and a URI all
            // came back as domainVerification keys. The order then cannot pass domain validation,
            // so it parks pending instead of failing fast. Say that plainly, because "the
            // enrollment did not error but the order will never issue" is the confusing case.
            var nonDns = result.Where(s => !string.Equals(s.Type, "dns", StringComparison.OrdinalIgnoreCase)).ToList();
            if (nonDns.Count > 0)
            {
                _logger.LogWarning(
                    "{Count} requested SAN(s) are not DNS names: {Sans}. CERTInext's additionalDomains " +
                    "field takes domain names, and it accepts these verbatim rather than rejecting them — " +
                    "the order will be created but is not expected to pass domain validation, so it will " +
                    "sit pending rather than issue. They are submitted rather than dropped on purpose: a " +
                    "visibly stuck order is preferable to a certificate issued without names the subscriber " +
                    "requested. Remove them from the CSR or the enrollment pattern if the order should proceed.",
                    nonDns.Count, string.Join("; ", nonDns.Select(s => $"{s.Type}:{s.Value}")));
            }

            return result;
        }

        private static string MapSanType(string anyCAType)
        {
            switch (anyCAType?.ToLowerInvariant())
            {
                // "dnsname" is what the AnyCA REST Gateway actually sends; "dns"/"dnsnames"
                // are kept for callers and older hosts that use the shorter spelling.
                case "dns":
                case "dnsname":
                case "dnsnames": return "dns";
                case "ip":
                case "ipaddress":
                case "ipaddresses": return "ip";
                case "email":
                case "rfc822":
                case "rfc822name": return "email";
                case "uri":
                case "uniformresourceidentifier": return "uri";
                default: return anyCAType?.ToLowerInvariant() ?? "dns";
            }
        }

        /// <summary>
        /// Extracts the subjectAltName entries from a PEM-encoded PKCS#10 CSR.
        ///
        /// Implemented with BouncyCastle (per the project's crypto policy: all certificate
        /// and key handling goes through BouncyCastle, never BCL System.Security.Cryptography).
        /// Never throws — an absent, truncated, or otherwise unparseable CSR returns an empty
        /// list so enrollment continues on the gateway-supplied SAN data alone.
        /// </summary>
        private static List<SanEntry> ExtractSanEntriesFromCsr(string csrPem)
        {
            var result = new List<SanEntry>();
            if (string.IsNullOrWhiteSpace(csrPem))
                return result;

            try
            {
                string b64 = csrPem
                    .Replace("-----BEGIN CERTIFICATE REQUEST-----", string.Empty)
                    .Replace("-----END CERTIFICATE REQUEST-----", string.Empty)
                    .Replace("-----BEGIN NEW CERTIFICATE REQUEST-----", string.Empty)
                    .Replace("-----END NEW CERTIFICATE REQUEST-----", string.Empty)
                    .Replace("\r", string.Empty)
                    .Replace("\n", string.Empty)
                    .Trim();

                if (string.IsNullOrWhiteSpace(b64))
                    return result;

                var csr = new Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest(Convert.FromBase64String(b64));

                // SANs live in the PKCS#9 extensionRequest attribute, not the CSR body.
                var extensions = csr.GetRequestedExtensions();
                var sanExtension = extensions?.GetExtension(
                    Org.BouncyCastle.Asn1.X509.X509Extensions.SubjectAlternativeName);
                if (sanExtension == null)
                    return result;

                var names = Org.BouncyCastle.Asn1.X509.GeneralNames.GetInstance(sanExtension.GetParsedValue());
                foreach (var generalName in names.GetNames())
                {
                    string value = GeneralNameToValue(generalName);
                    if (!string.IsNullOrWhiteSpace(value))
                        result.Add(new SanEntry { Type = SanTypeFromGeneralNameTag(generalName.TagNo), Value = value });
                }
            }
            catch (Exception ex)
            {
                // Enrollment must not fail because we could not read the CSR's SANs — the
                // gateway-supplied set still applies, and CERTInext validates the CSR itself.
                // Debug so an operator diagnosing a missing SAN can see the parse was skipped.
                LogHandler.GetClassLogger(typeof(CERTInextCAPlugin))
                    .LogDebug(ex, "ExtractSanEntriesFromCsr suppressed CSR parse failure");
            }

            return result;
        }

        /// <summary>Maps an ASN.1 GeneralName tag to the SAN type string used by this plugin.</summary>
        private static string SanTypeFromGeneralNameTag(int tagNo)
        {
            switch (tagNo)
            {
                case Org.BouncyCastle.Asn1.X509.GeneralName.DnsName: return "dns";
                case Org.BouncyCastle.Asn1.X509.GeneralName.Rfc822Name: return "email";
                case Org.BouncyCastle.Asn1.X509.GeneralName.UniformResourceIdentifier: return "uri";
                case Org.BouncyCastle.Asn1.X509.GeneralName.IPAddress: return "ip";
                case Org.BouncyCastle.Asn1.X509.GeneralName.DirectoryName: return "directoryname";
                case Org.BouncyCastle.Asn1.X509.GeneralName.RegisteredID: return "registeredid";
                case Org.BouncyCastle.Asn1.X509.GeneralName.OtherName: return "othername";
                default: return $"generalname-{tagNo}";
            }
        }

        /// <summary>
        /// Renders a GeneralName's value as the text CERTInext would need to see. Returns null
        /// for a name whose value cannot be rendered meaningfully, so it is skipped rather than
        /// submitted as ASN.1 debris.
        /// </summary>
        private static string GeneralNameToValue(Org.BouncyCastle.Asn1.X509.GeneralName generalName)
        {
            switch (generalName.TagNo)
            {
                case Org.BouncyCastle.Asn1.X509.GeneralName.DnsName:
                case Org.BouncyCastle.Asn1.X509.GeneralName.Rfc822Name:
                case Org.BouncyCastle.Asn1.X509.GeneralName.UniformResourceIdentifier:
                    return Org.BouncyCastle.Asn1.DerIA5String.GetInstance(generalName.Name).GetString();

                case Org.BouncyCastle.Asn1.X509.GeneralName.IPAddress:
                    // Octet string → dotted-quad / RFC 5952 text, so what we submit and log is
                    // the address the subscriber asked for rather than its hex encoding.
                    byte[] octets = Org.BouncyCastle.Asn1.Asn1OctetString.GetInstance(generalName.Name).GetOctets();
                    return octets.Length == 4 || octets.Length == 16
                        ? new System.Net.IPAddress(octets).ToString()
                        : null;

                default:
                    return generalName.Name?.ToString();
            }
        }

        private static string GetStringValue(
            Dictionary<string, object> dict, string key, string defaultValue = "")
        {
            if (dict.TryGetValue(key, out object val) && val != null)
                return val.ToString()!;
            return defaultValue;
        }

        /// <summary>
        /// Extracts the X.509 serial number from a PEM-encoded certificate for inclusion
        /// in audit log entries.  Returns "(parse-error)" rather than throwing, so that a
        /// logging failure never suppresses an audit record.
        ///
        /// Implemented with BouncyCastle (per the project's crypto policy: all certificate
        /// and key handling goes through BouncyCastle, never BCL System.Security.Cryptography).
        /// </summary>
        private static string ExtractSerialFromPem(string pem)
        {
            try
            {
                // Strip PEM headers and decode the DER bytes
                string b64 = pem
                    .Replace("-----BEGIN CERTIFICATE-----", string.Empty)
                    .Replace("-----END CERTIFICATE-----", string.Empty)
                    .Replace("\r", string.Empty)
                    .Replace("\n", string.Empty)
                    .Trim();

                if (string.IsNullOrWhiteSpace(b64))
                    return "(empty-pem)";

                byte[] der = Convert.FromBase64String(b64);
                var parser = new Org.BouncyCastle.X509.X509CertificateParser();
                var cert = parser.ReadCertificate(der);
                if (cert == null)
                    return "(parse-error)";
                // Match X509Certificate2.SerialNumber's format precisely: uppercase hex,
                // byte-per-byte, *preserving* leading-zero bytes (e.g. serial bytes
                // 0A 12 34 56 → "0A123456", not "A123456").  BouncyCastle's
                // BigInteger.ToString(16) drops the leading-zero nibble, which would
                // break audit-log correlation against Command's stored serial.  Convert
                // the unsigned-magnitude byte array to hex directly instead.
                byte[] serialBytes = cert.SerialNumber.ToByteArrayUnsigned();
                return Convert.ToHexString(serialBytes).ToUpperInvariant();
            }
            catch (Exception ex)
            {
                // SOC2 CC7.2: never let audit-log generation throw, but log the suppression
                // at Debug so an auditor diagnosing missing serial numbers can see the cause.
                LogHandler.GetClassLogger(typeof(CERTInextCAPlugin))
                    .LogDebug(ex, "ExtractSerialFromPem suppressed parse failure");
                return "(parse-error)";
            }
        }
    }
}
