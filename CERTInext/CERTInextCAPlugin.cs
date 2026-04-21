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

namespace Keyfactor.Extensions.CAPlugin.CERTInext
{
    /// <summary>
    /// Keyfactor AnyCA REST Gateway plugin for CERTInext (eMudhra).
    /// Implements <see cref="IAnyCAPlugin"/> to route Keyfactor Command certificate
    /// lifecycle operations through the CERTInext REST API.
    /// </summary>
    public class CERTInextCAPlugin : IAnyCAPlugin
    {
        private readonly ILogger _logger = LogHandler.GetClassLogger<CERTInextCAPlugin>();

        private CERTInextConfig _config;
        private ICERTInextClient _client;
        private ICertificateDataReader _certificateDataReader;

        // ---------------------------------------------------------------------------
        // Constructors
        // ---------------------------------------------------------------------------

        /// <summary>Production constructor — called by the gateway framework via reflection.</summary>
        public CERTInextCAPlugin() { }

        /// <summary>
        /// Test-injection constructor — pass a mock <see cref="ICERTInextClient"/>
        /// to avoid real network calls in unit tests.  A default configuration is
        /// supplied so that methods that read <c>_config</c> do not null-fault when
        /// <see cref="Initialize"/> has not been called.
        /// </summary>
        public CERTInextCAPlugin(ICERTInextClient client)
        {
            _client = client;
            _config = new CERTInextConfig();
        }

        /// <summary>
        /// Test-injection constructor — pass both a mock <see cref="ICERTInextClient"/>
        /// and a mock <see cref="ICertificateDataReader"/> for tests that exercise
        /// RenewOrReissue logic that reads prior certificate data from Command's database.
        /// </summary>
        public CERTInextCAPlugin(ICERTInextClient client, ICertificateDataReader certDataReader)
        {
            _client = client;
            _certificateDataReader = certDataReader;
            _config = new CERTInextConfig();
        }

        /// <summary>
        /// Test-injection constructor — pass both a mock <see cref="ICERTInextClient"/>
        /// and a specific <see cref="CERTInextConfig"/> for tests that need to override
        /// configuration fields such as <c>IgnoreExpired</c>.
        /// </summary>
        public CERTInextCAPlugin(ICERTInextClient client, CERTInextConfig config)
        {
            _client = client;
            _config = config ?? new CERTInextConfig();
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
            _logger.MethodEntry(LogLevel.Trace);

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
                "PageSize={PageSize}, IgnoreExpired={IgnoreExpired}",
                _config.ApiUrl, _config.AuthMode, _config.Enabled,
                hasApiKey, hasUsername,
                hasPassword, hasClientId,
                hasClientSecret, hasTokenUrl,
                _config.PageSize, _config.IgnoreExpired);
            _logger.MethodExit(LogLevel.Trace);
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
            _logger.MethodEntry(LogLevel.Trace);

            try
            {
                var profiles = _client.GetProfilesAsync().GetAwaiter().GetResult();
                var ids = profiles
                    .Where(p => p.Active)
                    .Select(p => p.Name ?? p.Id)
                    .ToList();

                _logger.LogInformation("Retrieved {Count} active certificate profiles from CERTInext.", ids.Count);
                return ids;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unable to retrieve certificate profiles from CERTInext.");
                return new List<string>();
            }
            finally
            {
                _logger.MethodExit(LogLevel.Trace);
            }
        }

        // ---------------------------------------------------------------------------
        // IAnyCAPlugin — Health and validation
        // ---------------------------------------------------------------------------

        /// <inheritdoc/>
        public async Task Ping()
        {
            _logger.MethodEntry(LogLevel.Trace);

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
                _logger.MethodExit(LogLevel.Trace);
            }
        }

        /// <inheritdoc/>
        public async Task ValidateCAConnectionInfo(Dictionary<string, object> connectionInfo)
        {
            _logger.MethodEntry(LogLevel.Trace);

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
                _logger.MethodExit(LogLevel.Trace);
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
            try
            {
                // Build a transient config from the supplied connectionInfo so we don't
                // rely on the already-initialized _client (which may hold stale creds)
                string rawConfig = JsonSerializer.Serialize(connectionInfo);
                var tempConfig = JsonSerializer.Deserialize<CERTInextConfig>(rawConfig);
                var tempClient = new CERTInextClient(tempConfig);
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

            _logger.LogInformation(
                "CA connection validation succeeded. ApiUrl={ApiUrl}, AuthMode={AuthMode}",
                attemptedApiUrl, attemptedAuthMode);
            _logger.MethodExit(LogLevel.Trace);
        }

        /// <inheritdoc/>
        public async Task ValidateProductInfo(EnrollmentProductInfo productInfo, Dictionary<string, object> connectionInfo)
        {
            _logger.MethodEntry(LogLevel.Trace);

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

            _logger.LogInformation("Product/profile validation succeeded. ProfileId={ProfileId}", profileId);
            _logger.MethodExit(LogLevel.Trace);
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
            _logger.MethodEntry(LogLevel.Trace);

            var ep = new EnrollmentParams(productInfo);

            // SOX / SOC2 CC7.3: log the enrollment attempt with full identifying context
            // so the event is independently auditable before any API call is made.
            string sanSummary = san != null && san.Count > 0
                ? string.Join("; ", san.SelectMany(kvp => (kvp.Value ?? Array.Empty<string>())
                    .Select(v => $"{kvp.Key}:{v}")))
                : "(none)";

            _logger.LogInformation(
                "Enrollment attempt started. " +
                "EnrollmentType={EnrollmentType}, Subject={Subject}, " +
                "ProfileId={ProfileId}, SANs={SANs}, " +
                "RequesterName={RequesterName}, RequesterEmail={RequesterEmail}",
                enrollmentType, subject,
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
            _logger.MethodExit(LogLevel.Trace);
            return result;
        }

        // ---------------------------------------------------------------------------
        // IAnyCAPlugin — Retrieval
        // ---------------------------------------------------------------------------

        /// <inheritdoc/>
        public async Task<AnyCAPluginCertificate> GetSingleRecord(string caRequestID)
        {
            _logger.MethodEntry(LogLevel.Trace);
            _logger.LogInformation("GetSingleRecord started. CARequestID={Id}", caRequestID);

            try
            {
                var cert = await _client.GetCertificateAsync(caRequestID);
                var record = MapToAnyCAPluginCertificate(cert);

                // SOC2 CC7.3: certificate retrieval is a security-relevant read operation;
                // must be logged at Information so it is captured in production.
                _logger.LogInformation(
                    "GetSingleRecord complete. CARequestID={Id}, Status={Status}, SerialNumber={Serial}",
                    caRequestID, cert.Status, cert.SerialNumber ?? "(none)");
                _logger.MethodExit(LogLevel.Trace);
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
            _logger.MethodEntry(LogLevel.Trace);

            string reasonString = StatusMapper.ToRevocationReason(revocationReason);

            // SOX: log the revocation attempt before any state change so the intent is
            // recorded even if the API call subsequently fails.
            _logger.LogInformation(
                "Revocation attempt started. " +
                "CARequestID={Id}, HexSerialNumber={Serial}, " +
                "ReasonCode={ReasonCode}, ReasonString={ReasonString}",
                caRequestID, hexSerialNumber, revocationReason, reasonString);

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
            _logger.MethodExit(LogLevel.Trace);
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
            _logger.MethodEntry(LogLevel.Trace);

            DateTime? issuedAfter = fullSync ? (DateTime?)null : lastSync;

            _logger.LogInformation(
                "Starting CERTInext synchronization. FullSync={FullSync}, IssuedAfter={IssuedAfter}",
                fullSync, issuedAfter?.ToString("O") ?? "none");

            int synced = 0;
            int skipped = 0;
            int errors = 0;

            await foreach (var cert in _client.ListCertificatesAsync(
                issuedAfter, _config.PageSize, cancelToken))
            {
                cancelToken.ThrowIfCancellationRequested();

                try
                {
                    // Skip expired certificates when IgnoreExpired is configured
                    if (_config.IgnoreExpired
                        && cert.ExpiresAt.HasValue
                        && cert.ExpiresAt.Value < DateTime.UtcNow)
                    {
                        _logger.LogTrace(
                            "Skipping expired certificate '{Id}' (expires {ExpiresAt:u}).",
                            cert.Id, cert.ExpiresAt.Value);
                        skipped++;
                        continue;
                    }

                    // Skip failed/rejected/cancelled certificates — they have no cert body
                    int status = StatusMapper.ToRequestDisposition(cert.Status);
                    if (status == (int)EndEntityStatus.FAILED)
                    {
                        _logger.LogTrace(
                            "Skipping certificate '{Id}' with terminal failure status '{Status}'.",
                            cert.Id, cert.Status);
                        skipped++;
                        continue;
                    }

                    var record = MapToAnyCAPluginCertificate(cert);
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
                }
            }

            _logger.LogInformation(
                "CERTInext synchronization complete. Synced={Synced}, Skipped={Skipped}, Errors={Errors}",
                synced, skipped, errors);
            _logger.MethodExit(LogLevel.Trace);
        }

        // ---------------------------------------------------------------------------
        // Private helpers
        // ---------------------------------------------------------------------------

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
            var enrollReq = new EnrollCertificateRequest
            {
                ProfileId = ep.ProfileId,
                Csr = csr,
                ValidityDays = ep.ValidityDays > 0 ? ep.ValidityDays : (int?)null,
                Subject = subject,
                Sans = BuildSanList(san),
                RequesterName = string.IsNullOrWhiteSpace(ep.RequesterName) ? null : ep.RequesterName,
                RequesterEmail = string.IsNullOrWhiteSpace(ep.RequesterEmail) ? null : ep.RequesterEmail,
                KeyType = string.IsNullOrWhiteSpace(ep.KeyType) ? null : ep.KeyType,
                Comment = "Issued via Keyfactor Command AnyCA REST Gateway."
            };

            var enrollResp = await _client.EnrollCertificateAsync(enrollReq);

            return BuildEnrollmentResult(enrollResp, ep.AutoApprove);
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

            // Determine whether this is within the renewal window
            bool useRenewalApi = false;
            try
            {
                DateTime? expiry = _certificateDataReader.GetExpirationDateByRequestId(priorCaRequestId);
                if (expiry.HasValue)
                {
                    DateTime renewalCutoff = DateTime.UtcNow.AddDays(-ep.RenewalWindowDays);
                    useRenewalApi = expiry.Value > renewalCutoff;
                    // SOX CC6.2 / SOC2 CC7.2: the renewal window evaluation is a security-relevant
                    // policy decision (determines whether an existing CA record is reused).  Logged
                    // at Information so it survives production log filters and is not suppressible
                    // by log-level configuration.
                    _logger.LogInformation(
                        "Renewal window evaluation complete. " +
                        "PriorCARequestID={PriorId}, CertExpiry={Expiry:O}, " +
                        "RenewalCutoff={Cutoff:O}, RenewalWindowDays={Window}, UseRenewalApi={Use}",
                        priorCaRequestId, expiry.Value, renewalCutoff, ep.RenewalWindowDays, useRenewalApi);
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
        /// Converts the multi-valued SAN dictionary from the AnyCA gateway into the
        /// <see cref="SanEntry"/> list expected by the CERTInext API.
        /// </summary>
        private static List<SanEntry> BuildSanList(Dictionary<string, string[]> san)
        {
            if (san == null || san.Count == 0)
                return null;

            var result = new List<SanEntry>();

            // AnyCA passes SANs keyed by type name (e.g. "Dns", "Ip", "Email", "Uri")
            foreach (var kvp in san)
            {
                string sanType = MapSanType(kvp.Key);
                if (kvp.Value == null) continue;

                foreach (string value in kvp.Value)
                {
                    if (!string.IsNullOrWhiteSpace(value))
                        result.Add(new SanEntry { Type = sanType, Value = value.Trim() });
                }
            }

            return result.Count > 0 ? result : null;
        }

        private static string MapSanType(string anyCAType)
        {
            switch (anyCAType?.ToLowerInvariant())
            {
                case "dns": return "dns";
                case "ip":
                case "ipaddress": return "ip";
                case "email":
                case "rfc822": return "email";
                case "uri": return "uri";
                default: return anyCAType?.ToLowerInvariant() ?? "dns";
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
                using var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(der);
                return cert.SerialNumber;
            }
            catch
            {
                return "(parse-error)";
            }
        }
    }
}
