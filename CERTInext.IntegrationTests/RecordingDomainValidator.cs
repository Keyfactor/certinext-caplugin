// Copyright 2026 Keyfactor
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Keyfactor.AnyGateway.Extensions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// <see cref="IDomainValidator"/> spy that wraps a real (Cloudflare or stub) validator
    /// and records every <c>StageValidation</c>/<c>CleanupValidation</c> call, including the
    /// FQDN and staged value, so DCV-on tests can assert whether the plugin actually staged
    /// a TXT record rather than just asserting that Enroll did not throw (gap G5, issues/0020).
    /// </summary>
    internal sealed class RecordingDomainValidator : IDomainValidator
    {
        private readonly IDomainValidator _inner;
        private readonly ConcurrentQueue<(string Fqdn, string Value)> _staged = new();
        private readonly ConcurrentQueue<string> _cleanedUp = new();

        public RecordingDomainValidator(IDomainValidator inner)
        {
            _inner = inner;
        }

        public IReadOnlyList<(string Fqdn, string Value)> StagedCalls => _staged.ToList();
        public IReadOnlyList<string> CleanedUpFqdns => _cleanedUp.ToList();

        public void Initialize(IDomainValidatorConfigProvider configProvider) => _inner.Initialize(configProvider);

        public async Task<DomainValidationResult> StageValidation(string key, string value, CancellationToken cancellationToken)
        {
            _staged.Enqueue((key, value));
            return await _inner.StageValidation(key, value, cancellationToken);
        }

        public async Task<DomainValidationResult> CleanupValidation(string key, CancellationToken cancellationToken)
        {
            _cleanedUp.Enqueue(key);
            return await _inner.CleanupValidation(key, cancellationToken);
        }

        public Task ValidateConfiguration(Dictionary<string, object> configuration) => _inner.ValidateConfiguration(configuration);
        public Dictionary<string, PropertyConfigInfo> GetDomainValidatorAnnotations() => _inner.GetDomainValidatorAnnotations();
        public string GetValidationType() => _inner.GetValidationType();
    }

    /// <summary>
    /// <see cref="IDomainValidatorFactory"/> that wraps another factory and hands out
    /// <see cref="RecordingDomainValidator"/> spies so tests can inspect what the plugin
    /// actually did with the DNS provider, keyed by (domain, validationType). Does not own
    /// disposal of the wrapped factory — callers that build a disposable inner factory
    /// (e.g. <c>CloudflareDomainValidatorFactory</c>) remain responsible for disposing it.
    /// </summary>
    internal sealed class RecordingDomainValidatorFactory : IDomainValidatorFactory
    {
        private readonly IDomainValidatorFactory _inner;
        private readonly ConcurrentDictionary<string, RecordingDomainValidator> _wrapped = new();

        public RecordingDomainValidatorFactory(IDomainValidatorFactory inner)
        {
            _inner = inner;
        }

        public IDomainValidator ResolveDomainValidator(string domain, string validationType)
        {
            string cacheKey = $"{domain}|{validationType}";
            return _wrapped.GetOrAdd(cacheKey, _ => new RecordingDomainValidator(_inner.ResolveDomainValidator(domain, validationType)));
        }

        /// <summary>All StageValidation calls recorded across every domain resolved so far.</summary>
        public IReadOnlyList<(string Fqdn, string Value)> StagedCalls =>
            _wrapped.Values.SelectMany(v => v.StagedCalls).ToList();

        /// <summary>All CleanupValidation calls recorded across every domain resolved so far.</summary>
        public IReadOnlyList<string> CleanedUpFqdns =>
            _wrapped.Values.SelectMany(v => v.CleanedUpFqdns).ToList();
    }
}
