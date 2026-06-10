// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.AnyGateway.Extensions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// No-op DNS validator used when Cloudflare credentials are not available.
    /// Records are not actually published; DCV verification by CERTInext may or may
    /// not succeed depending on whether the sandbox enforces real DNS lookups.
    /// </summary>
    internal sealed class StubDomainValidator : IDomainValidator
    {
        public void Initialize(IDomainValidatorConfigProvider configProvider) { }

        public Task<DomainValidationResult> StageValidation(string key, string value, CancellationToken cancellationToken) =>
            Task.FromResult(new DomainValidationResult { Success = true });

        public Task<DomainValidationResult> CleanupValidation(string key, CancellationToken cancellationToken) =>
            Task.FromResult(new DomainValidationResult { Success = true });

        public Task ValidateConfiguration(Dictionary<string, object> configuration) => Task.CompletedTask;
        public Dictionary<string, Keyfactor.AnyGateway.Extensions.PropertyConfigInfo> GetDomainValidatorAnnotations() => new();
        public string GetValidationType() => "dns-01";
    }

    internal sealed class StubDomainValidatorFactory : IDomainValidatorFactory
    {
        private readonly IDomainValidator _validator = new StubDomainValidator();
        public IDomainValidator ResolveDomainValidator(string domain, string validationType) => _validator;
    }
}
