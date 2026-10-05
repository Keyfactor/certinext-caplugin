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

using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Issue 0044 triage probe: why did <c>V2ReportProbeTests.Probe4</c> fail inside the V1
    /// <see cref="CERTInextClient.ListOrdersAsync"/> with "unrecognised error body for operation
    /// 'list orders page 1'"?
    ///
    /// Read-only. Makes exactly two V1 <c>GetOrderReport</c> page-1 list calls (pageSize 5,
    /// enumeration stopped after page 1) with the same access-key config the
    /// <see cref="IntegrationTestFixture"/> builds, differing only in <c>ApiUrl</c>:
    /// <list type="number">
    ///   <item>Control: the V1 URL read straight from <c>~/.env_certinext</c> (immune to shell env).</item>
    ///   <item>Repro: the V2 base URL from <c>~/.env_certinext_v2</c>, which is what the fixture's
    ///   <c>ApiUrl</c> becomes when that file is sourced into the shell (issue 0017).</item>
    /// </list>
    /// It also shows, offline, which <c>ApiUrl</c> the fixture resolves under each env overlay.
    /// Since the 0017 fix the shell overlay makes the fixture fail fast with an actionable message
    /// (printed as <c>FAIL-FAST: ...</c>), and an earlier <see cref="V2EnvHelper.LoadAndPromote"/>
    /// no longer changes the fixture's <c>ApiUrl</c>. The repro call still hits the V2 base URL
    /// directly (bypassing the fixture) to capture the raw error body.
    ///
    /// The response body is captured from the client's own non-success log line (already
    /// redacted via <c>ApplyLoggingRedaction</c>) by swapping <see cref="LogHandler.Factory"/>
    /// before the first <see cref="CERTInextClient"/> is constructed. That only works when this
    /// class runs alone in the test process, which is why it takes no class fixture and must be
    /// run with its own filter. It also briefly mutates process env (restored afterwards), so it
    /// sits in a non-parallel collection. Opt-in: <c>CERTINEXT_0044_PROBE=1</c> must be set in
    /// the shell. Both env files are read from disk; don't source either into the shell.
    /// <code>
    ///   CERTINEXT_0044_PROBE=1 dotnet test CERTInext.IntegrationTests/CERTInext.IntegrationTests.csproj -c Release \
    ///     --filter "FullyQualifiedName~ListOrdersErrorBodyProbeTests" \
    ///     --logger "console;verbosity=detailed" > /tmp/0044-probe.log 2>&1
    /// </code>
    /// </summary>
    [Collection(ListOrdersErrorBodyProbeCollection.Name)]
    public class ListOrdersErrorBodyProbeTests
    {
        private const string ProbeFlag = "CERTINEXT_0044_PROBE";
        private const string ApiUrlKey = "CERTINEXT_API_URL";

        private readonly ITestOutputHelper _output;

        public ListOrdersErrorBodyProbeTests(ITestOutputHelper output)
        {
            _output = output;
        }

        private sealed class CapturingLoggerFactory : ILoggerFactory
        {
            public ConcurrentQueue<string> Messages { get; } = new();
            public ILogger CreateLogger(string categoryName) => new CapturingLogger(Messages);
            public void AddProvider(ILoggerProvider provider) { }
            public void Dispose() { }

            private sealed class CapturingLogger : ILogger
            {
                private readonly ConcurrentQueue<string> _messages;
                public CapturingLogger(ConcurrentQueue<string> messages) => _messages = messages;
                public IDisposable BeginScope<TState>(TState state) => null;
                public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;
                public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
                    Func<TState, Exception, string> formatter)
                    => _messages.Enqueue($"[{logLevel}] {formatter(state, exception)}");
            }
        }

        [SkippableFact]
        public async Task ListOrdersPage1_V1UrlVsV2BaseUrl_CapturesErrorBody()
        {
            Skip.If(string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(ProbeFlag)),
                $"{ProbeFlag} not set — skipping issue 0044 ListOrders error-body probe.");

            string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var (v1File, _) = V2EnvHelper.LoadEnvFile(Path.Combine(home, ".env_certinext"));
            var (v2File, _) = V2EnvHelper.LoadEnvFile(Path.Combine(home, ".env_certinext_v2"));
            string v1Url = V2EnvHelper.GetEnv(v1File, ApiUrlKey);
            string v2Url = V2EnvHelper.GetEnv(v2File, ApiUrlKey);
            Skip.If(string.IsNullOrWhiteSpace(v1Url) || string.IsNullOrWhiteSpace(v2Url),
                "Need CERTINEXT_API_URL in both ~/.env_certinext and ~/.env_certinext_v2.");

            string shellApiUrl = Environment.GetEnvironmentVariable(ApiUrlKey);
            _output.WriteLine("=== Issue 0044: V1 ListOrdersAsync page 1 ===");
            _output.WriteLine($"V1 file ApiUrl       = {v1Url}");
            _output.WriteLine($"V2 file ApiUrl       = {v2Url}");
            _output.WriteLine($"Shell {ApiUrlKey} = {shellApiUrl ?? "(unset)"}");

            var capture = new CapturingLoggerFactory();
            string pollutedResolved;
            string promotedResolved;
            try
            {
                // Must happen before any CERTInextClient exists: its Logger is static readonly.
                LogHandler.Factory = capture;

                // Offline: which ApiUrl the fixture resolves under the current shell env.
                var fixture = new IntegrationTestFixture();
                Skip.IfNot(fixture.IsConfigured, "V1 fixture not configured (~/.env_certinext).");
                _output.WriteLine($"Fixture ApiUrl (current shell env) = {fixture.Config.ApiUrl}");

                // Live call 1 (control): V1 URL from the file.
                await RunListOrdersPage1Async("control: V1 file URL", fixture.Config, v1Url, capture);

                // Live call 2 (repro): V2 base URL, as the fixture sees it under the 0017 overlay.
                await RunListOrdersPage1Async("repro: V2 base URL", fixture.Config, v2Url, capture);

                // Offline: fixture ApiUrl when the shell has sourced ~/.env_certinext_v2 (0017).
                pollutedResolved = ResolveFixtureApiUrlWith(() => Environment.SetEnvironmentVariable(ApiUrlKey, v2Url));

                // Offline: fixture ApiUrl when another V2 test class's constructor already ran
                // V2EnvHelper.LoadAndPromote() earlier in the same test process.
                promotedResolved = ResolveFixtureApiUrlWith(() => V2EnvHelper.LoadAndPromote());
            }
            finally
            {
                // Factory is write-only; reset to the unconfigured default (same as the unit tests).
                LogHandler.Factory = Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance;
            }

            _output.WriteLine($"Fixture ApiUrl after shell sources ~/.env_certinext_v2      = {pollutedResolved}");
            _output.WriteLine($"Fixture ApiUrl after an earlier V2EnvHelper.LoadAndPromote() = {promotedResolved}");
        }

        private async Task RunListOrdersPage1Async(
            string label, CERTInextConfig template, string apiUrl, CapturingLoggerFactory capture)
        {
            _output.WriteLine($"--- {label}: POST {apiUrl.TrimEnd('/')}/{Constants.Api.GetOrderReportPath} (page 1, pageSize 5) ---");
            while (capture.Messages.TryDequeue(out _)) { }

            using var client = new CERTInextClient(WithApiUrl(template, apiUrl));
            int count = 0;
            try
            {
                await foreach (var entry in client.ListOrdersAsync(pageSize: 5))
                {
                    count++;
                    if (count >= 5) break; // page 1 only
                }
                _output.WriteLine($"RESULT: success, {count} order(s) on page 1.");
            }
            catch (Exception ex)
            {
                _output.WriteLine($"RESULT: {ex.GetType().Name}: {ex.Message}");
            }

            var lines = capture.Messages.Where(m =>
                    m.Contains(Constants.Api.GetOrderReportPath, StringComparison.Ordinal) ||
                    m.Contains("list orders", StringComparison.Ordinal))
                .ToList();
            foreach (string line in lines)
                _output.WriteLine($"LOG {line}");
            if (lines.Count == 0)
                _output.WriteLine("NOTE: no client log lines captured. CERTInextClient's static logger was " +
                                   "bound before this probe ran; run this class alone.");
        }

        /// <summary>
        /// Builds a fresh fixture after <paramref name="mutateEnv"/> and reports its ApiUrl. Since
        /// the 0017 fix, the shell-overlay case makes the fixture fail fast instead of resolving the
        /// V2 URL (reported as <c>FAIL-FAST: ...</c>), and <see cref="V2EnvHelper.LoadAndPromote"/>
        /// no longer promotes <c>CERTINEXT_API_URL</c>, so the in-process case resolves the V1 URL.
        /// </summary>
        private static string ResolveFixtureApiUrlWith(Action mutateEnv)
        {
            var snapshot = new System.Collections.Generic.Dictionary<string, string>(StringComparer.Ordinal);
            foreach (System.Collections.DictionaryEntry de in Environment.GetEnvironmentVariables())
                snapshot[(string)de.Key] = (string)de.Value;
            try
            {
                mutateEnv();
                return new IntegrationTestFixture().Config?.ApiUrl ?? "(not configured)";
            }
            catch (InvalidOperationException ex)
            {
                return $"FAIL-FAST: {ex.Message}";
            }
            finally
            {
                var current = Environment.GetEnvironmentVariables().Keys.Cast<string>().ToList();
                foreach (string key in current.Where(k => !snapshot.ContainsKey(k)))
                    Environment.SetEnvironmentVariable(key, null);
                foreach (var kv in snapshot)
                    Environment.SetEnvironmentVariable(kv.Key, kv.Value);
            }
        }

        private static CERTInextConfig WithApiUrl(CERTInextConfig c, string apiUrl) => new CERTInextConfig
        {
            ApiUrl = apiUrl.TrimEnd('/') + "/",
            AuthMode = c.AuthMode,
            ApiKey = c.ApiKey,
            AccountNumber = c.AccountNumber,
            GroupNumber = c.GroupNumber,
            OrganizationNumber = c.OrganizationNumber,
            RequestorName = c.RequestorName,
            RequestorEmail = c.RequestorEmail,
            RequestorIsdCode = c.RequestorIsdCode,
            RequestorMobileNumber = c.RequestorMobileNumber,
            SignerPlace = c.SignerPlace,
            SignerIp = c.SignerIp,
            DefaultProductCode = c.DefaultProductCode,
            PageSize = c.PageSize
        };
    }

    /// <summary>
    /// Runs <see cref="ListOrdersErrorBodyProbeTests"/> on its own, never alongside other
    /// classes, because it swaps <see cref="LogHandler.Factory"/> and mutates process env.
    /// </summary>
    [CollectionDefinition(Name, DisableParallelization = true)]
    public sealed class ListOrdersErrorBodyProbeCollection
    {
        public const string Name = "ListOrdersErrorBodyProbe-NoParallel";
    }
}
