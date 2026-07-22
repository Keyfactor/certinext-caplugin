// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using DnsClient;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Dcv
{
    /// <summary>
    /// Resolves the terminal (final) name of a possible CNAME delegation chain.
    ///
    /// Issue 0006: customers commonly delegate a DCV challenge subdomain (e.g.
    /// <c>_emsign-validation.example.com</c>) via CNAME to a dedicated validation zone, to keep
    /// automation credentials out of the production DNS zone. Following that delegation lets the
    /// plugin publish the TXT record — and resolve the DNS provider plugin — against the zone
    /// that actually owns the record, instead of the raw challenge hostname.
    /// </summary>
    internal interface ICnameResolver
    {
        /// <summary>
        /// Follows the CNAME chain starting at <paramref name="name"/> and returns the terminal
        /// name (the last name in the chain that has no further CNAME record). Returns
        /// <paramref name="name"/> unchanged when it has no CNAME record at all.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        /// Thrown when a loop is detected (a name is revisited) or the chain exceeds
        /// <see cref="Constants.Dcv.MaxCnameDepth"/> hops.
        /// </exception>
        Task<string> ResolveTerminalNameAsync(string name, CancellationToken ct = default);
    }

    /// <summary>
    /// Default <see cref="ICnameResolver"/> implementation. Performs bounded, loop-detected
    /// CNAME-chasing by issuing one CNAME-type DNS query per hop via
    /// <see href="https://github.com/MichaCo/DnsClient.NET">DnsClient.NET</see>, which resolves
    /// against the OS-configured resolver(s) correctly cross-platform — including reading
    /// <c>/etc/resolv.conf</c> on Linux, which is how the gateway's Kubernetes pods are
    /// configured — and natively handles TCP fallback for truncated responses and DNS name
    /// compression. A hand-rolled raw-socket DNS client was considered and rejected: it is more
    /// protocol-parsing risk than this feature needs, and .NET's own
    /// <c>NetworkInterface</c>-based DNS-server discovery is unreliable on Linux containers.
    ///
    /// The hop-walking algorithm (depth cap + loop detection) is factored out from the actual
    /// DNS query via the internal delegate constructor so it can be unit-tested deterministically
    /// against a fake single-hop lookup function, without making real DNS queries.
    /// </summary>
    internal sealed class CnameResolver : ICnameResolver
    {
        private readonly Func<string, CancellationToken, Task<string>> _lookupOneHop;

        /// <summary>Production constructor — resolves hops via real DNS CNAME queries.</summary>
        public CnameResolver() : this(QueryCnameOneHopAsync)
        {
        }

        /// <summary>
        /// Test-injection constructor: supply a fake single-hop lookup function (e.g. backed by
        /// an in-memory CNAME chain map) so the depth-cap/loop-detection logic below can be
        /// exercised without any real network I/O.
        /// </summary>
        internal CnameResolver(Func<string, CancellationToken, Task<string>> lookupOneHop)
        {
            _lookupOneHop = lookupOneHop ?? throw new ArgumentNullException(nameof(lookupOneHop));
        }

        /// <inheritdoc/>
        public async Task<string> ResolveTerminalNameAsync(string name, CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Name must not be null or empty.", nameof(name));

            string current = NormalizeName(name);
            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            for (int hop = 0; hop < Constants.Dcv.MaxCnameDepth; hop++)
            {
                if (!visited.Add(current))
                    throw new InvalidOperationException(
                        $"CNAME loop detected while resolving '{name}' — '{current}' was already visited " +
                        $"after {hop} hop(s). Check the delegated zone for a circular CNAME chain.");

                ct.ThrowIfCancellationRequested();
                string target = await _lookupOneHop(current, ct).ConfigureAwait(false);

                if (string.IsNullOrWhiteSpace(target))
                    return current; // no further CNAME — this name is terminal

                current = NormalizeName(target);
            }

            throw new InvalidOperationException(
                $"CNAME chain for '{name}' exceeded the maximum depth of {Constants.Dcv.MaxCnameDepth} hop(s).");
        }

        private static string NormalizeName(string name) => name.Trim().TrimEnd('.');

        // -----------------------------------------------------------------------
        // Real DNS CNAME lookup (single hop) — via DnsClient.NET.
        // -----------------------------------------------------------------------

        // A single shared LookupClient is safe for concurrent use. Its default constructor
        // discovers the OS-configured resolver(s) the same way `dig`/`nslookup` would (reading
        // /etc/resolv.conf on Linux, the Windows resolver configuration on Windows, etc.),
        // which is what the gateway's Kubernetes pods rely on — unlike
        // NetworkInterface.GetAllNetworkInterfaces()...DnsAddresses, which is unreliable/empty
        // on Linux containers.
        private static readonly LookupClient SharedLookupClient = new LookupClient();

        /// <summary>
        /// Queries the CNAME record for <paramref name="name"/> against the OS-configured DNS
        /// resolver(s). Returns the CNAME target, or <c>null</c> when the name has no CNAME
        /// record (i.e. it is terminal).
        /// </summary>
        private static async Task<string> QueryCnameOneHopAsync(string name, CancellationToken ct)
        {
            IDnsQueryResponse response;
            try
            {
                response = await SharedLookupClient.QueryAsync(name, QueryType.CNAME, cancellationToken: ct)
                    .ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                throw new InvalidOperationException($"Unable to resolve DNS records for '{name}'.", ex);
            }

            if (response.HasError)
            {
                // NXDOMAIN / "no records" are not failures here — they just mean this name has
                // no CNAME record, so it's terminal.
                return null;
            }

            var cnameRecord = response.Answers.CnameRecords().FirstOrDefault();
            return cnameRecord?.CanonicalName?.Value;
        }
    }
}
