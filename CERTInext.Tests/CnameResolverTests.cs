// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.Extensions.CAPlugin.CERTInext.Dcv;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Unit tests for <see cref="CnameResolver"/>'s hop-walking algorithm (depth cap + loop
    /// detection). Exercised via the internal delegate-injection constructor against a fake
    /// in-memory CNAME chain map, so no real DNS queries are made.
    /// </summary>
    public class CnameResolverTests
    {
        /// <summary>
        /// Builds a resolver whose single-hop lookup is backed by <paramref name="chain"/>
        /// (source name → CNAME target). Names absent from the map are terminal (no CNAME).
        /// </summary>
        private static CnameResolver ResolverFor(Dictionary<string, string> chain) =>
            new CnameResolver((name, ct) =>
            {
                chain.TryGetValue(name, out var target);
                return Task.FromResult(target);
            });

        [Fact]
        public async Task ResolveTerminalNameAsync_NoCname_ReturnsSameName()
        {
            var resolver = ResolverFor(new Dictionary<string, string>());

            string result = await resolver.ResolveTerminalNameAsync("_dcv-challenge.example.com");

            result.Should().Be("_dcv-challenge.example.com");
        }

        [Fact]
        public async Task ResolveTerminalNameAsync_SingleHop_ReturnsTarget()
        {
            var chain = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["_dcv-challenge.example.com"] = "validate.dns-provider.net"
            };
            var resolver = ResolverFor(chain);

            string result = await resolver.ResolveTerminalNameAsync("_dcv-challenge.example.com");

            result.Should().Be("validate.dns-provider.net");
        }

        [Fact]
        public async Task ResolveTerminalNameAsync_MultiHopChain_FollowsToTerminalName()
        {
            var chain = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["_dcv-challenge.example.com"] = "hop1.delegated.net",
                ["hop1.delegated.net"] = "hop2.delegated.net",
                ["hop2.delegated.net"] = "terminal.dns-provider.net"
                // terminal.dns-provider.net absent → terminal
            };
            var resolver = ResolverFor(chain);

            string result = await resolver.ResolveTerminalNameAsync("_dcv-challenge.example.com");

            result.Should().Be("terminal.dns-provider.net");
        }

        [Fact]
        public async Task ResolveTerminalNameAsync_TrailingDotAndCase_AreNormalized()
        {
            var chain = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["_dcv-challenge.example.com"] = "Target.Delegated.NET."
            };
            var resolver = ResolverFor(chain);

            string result = await resolver.ResolveTerminalNameAsync("_dcv-challenge.example.com");

            result.Should().Be("Target.Delegated.NET",
                "trailing root dot should be stripped for use as a hostname/lookup key");
        }

        // ---------------------------------------------------------------------------
        // Loop detection
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task ResolveTerminalNameAsync_DirectLoop_ThrowsCleanly()
        {
            var chain = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["a.example.com"] = "b.example.com",
                ["b.example.com"] = "a.example.com" // cycles back
            };
            var resolver = ResolverFor(chain);

            Func<Task> act = () => resolver.ResolveTerminalNameAsync("a.example.com");

            await act.Should().ThrowAsync<InvalidOperationException>()
                .WithMessage("*loop detected*");
        }

        [Fact]
        public async Task ResolveTerminalNameAsync_SelfLoop_ThrowsCleanly()
        {
            var chain = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["a.example.com"] = "a.example.com"
            };
            var resolver = ResolverFor(chain);

            Func<Task> act = () => resolver.ResolveTerminalNameAsync("a.example.com");

            await act.Should().ThrowAsync<InvalidOperationException>()
                .WithMessage("*loop detected*");
        }

        // ---------------------------------------------------------------------------
        // Depth cap
        // ---------------------------------------------------------------------------

        [Fact]
        public async Task ResolveTerminalNameAsync_ChainWithinDepthCap_Succeeds()
        {
            // 9 hops (< MaxCnameDepth=10) then terminal — must succeed.
            var chain = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < 9; i++)
                chain[$"hop{i}.example.com"] = $"hop{i + 1}.example.com";
            // hop9.example.com has no further entry → terminal

            var resolver = ResolverFor(chain);

            string result = await resolver.ResolveTerminalNameAsync("hop0.example.com");

            result.Should().Be("hop9.example.com");
        }

        [Fact]
        public async Task ResolveTerminalNameAsync_ChainExceedingDepthCap_ThrowsCleanly()
        {
            // 11 distinct hops (> MaxCnameDepth=10), no loop — must fail on depth, not hang.
            var chain = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < 11; i++)
                chain[$"hop{i}.example.com"] = $"hop{i + 1}.example.com";

            var resolver = ResolverFor(chain);

            Func<Task> act = () => resolver.ResolveTerminalNameAsync("hop0.example.com");

            await act.Should().ThrowAsync<InvalidOperationException>()
                .WithMessage("*maximum depth*");
        }
    }
}
