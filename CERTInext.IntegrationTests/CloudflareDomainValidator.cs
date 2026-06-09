// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.AnyGateway.Extensions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// <see cref="IDomainValidator"/> that publishes and removes DNS TXT records via
    /// the Cloudflare v4 API.  Intended for integration tests against a real domain.
    ///
    /// Credentials are read from the <see cref="IntegrationTestFixture"/>:
    /// <c>CERTINEXT_CF_API_TOKEN</c> and <c>CERTINEXT_CF_ZONE_ID</c>.
    /// </summary>
    internal sealed class CloudflareDomainValidator : IDomainValidator
    {
        private const string CfApiBase = "https://api.cloudflare.com/client/v4";

        private readonly string _apiToken;
        private readonly string _zoneId;
        private readonly HttpClient _http;

        // Maps staging hostname → Cloudflare record ID so CleanupValidation can delete it
        private readonly ConcurrentDictionary<string, string> _stagedRecordIds = new();

        public CloudflareDomainValidator(string apiToken, string zoneId)
        {
            _apiToken = apiToken ?? throw new ArgumentNullException(nameof(apiToken));
            _zoneId   = zoneId   ?? throw new ArgumentNullException(nameof(zoneId));

            _http = new HttpClient();
            _http.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", _apiToken);
        }

        public void Initialize(IDomainValidatorConfigProvider configProvider) { }

        public async Task<DomainValidationResult> StageValidation(string key, string value, CancellationToken cancellationToken)
        {
            var payload = new
            {
                type    = "TXT",
                name    = key,
                content = value,
                ttl     = 60
            };

            var response = await _http.PostAsJsonAsync(
                $"{CfApiBase}/zones/{_zoneId}/dns_records",
                payload,
                cancellationToken);

            string body = await response.Content.ReadAsStringAsync(cancellationToken);

            if (!response.IsSuccessStatusCode)
                return new DomainValidationResult
                {
                    Success      = false,
                    ErrorMessage = $"Cloudflare API error {(int)response.StatusCode}: {body}"
                };

            using var doc  = JsonDocument.Parse(body);
            bool success   = doc.RootElement.GetProperty("success").GetBoolean();
            string recordId = success
                ? doc.RootElement.GetProperty("result").GetProperty("id").GetString()
                : null;

            if (!success || string.IsNullOrEmpty(recordId))
                return new DomainValidationResult
                {
                    Success      = false,
                    ErrorMessage = $"Cloudflare record creation failed: {body}"
                };

            _stagedRecordIds[key] = recordId;

            return new DomainValidationResult { Success = true };
        }

        public async Task<DomainValidationResult> CleanupValidation(string key, CancellationToken cancellationToken)
        {
            if (!_stagedRecordIds.TryRemove(key, out string recordId))
                return new DomainValidationResult { Success = true }; // nothing to clean up

            var response = await _http.DeleteAsync(
                $"{CfApiBase}/zones/{_zoneId}/dns_records/{recordId}",
                cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                string body = await response.Content.ReadAsStringAsync(cancellationToken);
                return new DomainValidationResult
                {
                    Success      = false,
                    ErrorMessage = $"Cloudflare delete error {(int)response.StatusCode}: {body}"
                };
            }

            return new DomainValidationResult { Success = true };
        }

        public Task ValidateConfiguration(Dictionary<string, object> configuration) => Task.CompletedTask;
        public Dictionary<string, Keyfactor.AnyGateway.Extensions.PropertyConfigInfo> GetDomainValidatorAnnotations() => new();
        public string GetValidationType() => "dns-01";
    }

    internal sealed class CloudflareDomainValidatorFactory : IDomainValidatorFactory
    {
        private readonly IDomainValidator _validator;

        public CloudflareDomainValidatorFactory(string apiToken, string zoneId)
        {
            _validator = new CloudflareDomainValidator(apiToken, zoneId);
        }

        public IDomainValidator ResolveDomainValidator(string domain, string validationType) => _validator;
    }
}
