// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0

using System;
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

        /// <summary>All CancellationTokens passed to <see cref="CleanupValidation"/>.</summary>
        public List<CancellationToken> CleanupTokens { get; } = new();

        /// <summary>When false, <see cref="StageValidation"/> returns a failure result.</summary>
        public bool StageSucceeds { get; init; } = true;

        /// <summary>
        /// When set, overrides <see cref="StageSucceeds"/> on a per-key basis — e.g.
        /// <c>key => key.Contains("bad", StringComparison.OrdinalIgnoreCase)</c> to fail only a
        /// specific hostname in a multi-domain test while the others still stage successfully.
        /// </summary>
        public Func<string, bool> ShouldFail { get; init; }

        /// <summary>Error message returned when a StageValidation call fails.</summary>
        public string StageError { get; init; } = "Stage failed (test stub)";

        public void Initialize(IDomainValidatorConfigProvider configProvider) { }

        public Task<DomainValidationResult> StageValidation(string key, string value, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            bool fail = ShouldFail?.Invoke(key) ?? !StageSucceeds;
            if (!fail)
                StagedRecords.Add((key, value));

            return Task.FromResult(new DomainValidationResult
            {
                Success      = !fail,
                ErrorMessage = fail ? StageError : null
            });
        }

        /// <summary>
        /// Artificial delay applied inside <see cref="CleanupValidation"/> before completing — lets
        /// tests distinguish "cleanup calls run concurrently" (wall time ~= one delay) from
        /// "cleanup calls run sequentially" (wall time ~= N x delay).
        /// </summary>
        public TimeSpan CleanupDelay { get; init; } = TimeSpan.Zero;

        // Cleanup calls can genuinely run concurrently (that's what CleanupDelay exists to prove),
        // so the two List<T> fields below need a lock — unlike StagedRecords above, which only ever
        // sees synchronously-completing calls in practice.
        private readonly object _cleanupLock = new();

        public async Task<DomainValidationResult> CleanupValidation(string key, CancellationToken cancellationToken)
        {
            if (CleanupDelay > TimeSpan.Zero)
                await Task.Delay(CleanupDelay, cancellationToken);
            lock (_cleanupLock)
            {
                CleanedUpKeys.Add(key);
                CleanupTokens.Add(cancellationToken);
            }
            return new DomainValidationResult { Success = true };
        }

        public Task ValidateConfiguration(Dictionary<string, object> configuration) => Task.CompletedTask;
        public Dictionary<string, Keyfactor.AnyGateway.Extensions.PropertyConfigInfo> GetDomainValidatorAnnotations() => new();
        public string GetValidationType() => "dns-01";
    }

    /// <summary>
    /// Factory that returns a single pre-configured <see cref="IDomainValidator"/> for every
    /// domain, or only for <paramref name="resolvableDomain"/> if set. Pass <c>null</c> as the
    /// validator to simulate "no DNS provider configured".
    /// </summary>
    internal sealed class FakeDomainValidatorFactory : IDomainValidatorFactory
    {
        private readonly IDomainValidator _validator;
        private readonly string _resolvableDomain;

        public FakeDomainValidatorFactory(IDomainValidator validator = null, string resolvableDomain = null)
        {
            _validator = validator;
            _resolvableDomain = resolvableDomain;
        }

        public IDomainValidator ResolveDomainValidator(string domain, string validationType) =>
            (_resolvableDomain == null || string.Equals(domain, _resolvableDomain, StringComparison.OrdinalIgnoreCase))
                ? _validator
                : null;

        /// <summary>The validator this factory returns; exposed for assertions in tests.</summary>
        public IDomainValidator PrimaryValidator => _validator;
    }
}
