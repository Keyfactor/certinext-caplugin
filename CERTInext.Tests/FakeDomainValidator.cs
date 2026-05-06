// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.AnyGateway.Extensions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// In-memory stub that records staged and cleaned-up DNS TXT entries without
    /// making real DNS calls.  Configurable success/failure via init properties.
    /// </summary>
    internal sealed class FakeDomainValidator : IDomainValidator
    {
        /// <summary>All (key, value) pairs passed to <see cref="StageValidation"/>.</summary>
        public List<(string key, string value)> StagedRecords { get; } = new();

        /// <summary>All keys passed to <see cref="CleanupValidation"/>.</summary>
        public List<string> CleanedUpKeys { get; } = new();

        /// <summary>When false, <see cref="StageValidation"/> returns a failure result.</summary>
        public bool StageSucceeds { get; init; } = true;

        /// <summary>Error message returned when <see cref="StageSucceeds"/> is false.</summary>
        public string StageError { get; init; } = "Stage failed (test stub)";

        public void Initialize(IDomainValidatorConfigProvider configProvider) { }

        public Task<DomainValidationResult> StageValidation(string key, string value, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            StagedRecords.Add((key, value));
            return Task.FromResult(new DomainValidationResult
            {
                Success      = StageSucceeds,
                ErrorMessage = StageSucceeds ? null : StageError
            });
        }

        public Task<DomainValidationResult> CleanupValidation(string key, CancellationToken cancellationToken)
        {
            CleanedUpKeys.Add(key);
            return Task.FromResult(new DomainValidationResult { Success = true });
        }

        public Task ValidateConfiguration(Dictionary<string, object> configuration) => Task.CompletedTask;
        public Dictionary<string, Keyfactor.AnyGateway.Extensions.PropertyConfigInfo> GetDomainValidatorAnnotations() => new();
        public string GetValidationType() => "dns-01";
    }

    /// <summary>
    /// Factory that returns a single pre-configured <see cref="IDomainValidator"/> for every
    /// domain.  Pass <c>null</c> as the validator to simulate "no DNS provider configured".
    /// </summary>
    internal sealed class FakeDomainValidatorFactory : IDomainValidatorFactory
    {
        private readonly IDomainValidator _validator;

        public FakeDomainValidatorFactory(IDomainValidator validator = null) => _validator = validator;

        public IDomainValidator ResolveDomainValidator(string domain, string validationType) => _validator;
    }
}
