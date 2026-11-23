// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using Microsoft.Extensions.Logging;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Routes plugin/client logs (<c>LogHandler.Factory</c>) to a test's xUnit output so a live run
    /// shows why the plugin took a path, e.g. the V2 DCV early exits or a CA rejection at Submit CSR.
    /// Minimum level is Debug, or <c>CERTINEXT_TEST_LOG_LEVEL</c> (e.g. <c>Trace</c> to include the
    /// redacted request/response payloads). Plugin logs keep their default redaction
    /// (<c>LogSensitiveRequestData</c> off). Must be called before the plugin is constructed — its
    /// logger is created in a field initializer.
    /// </summary>
    internal static class TestOutputLogging
    {
        /// <summary>Points the plugin's log factory at <paramref name="output"/>; returns the restore action.</summary>
        public static Action RouteTo(ITestOutputHelper output)
        {
            var min = Enum.TryParse(Environment.GetEnvironmentVariable("CERTINEXT_TEST_LOG_LEVEL"), true, out LogLevel parsed)
                ? parsed
                : LogLevel.Debug;
            Keyfactor.Logging.LogHandler.Factory = new Factory(output, min);
            return () => Keyfactor.Logging.LogHandler.Factory =
                Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance;
        }

        private sealed class Factory : ILoggerFactory
        {
            private readonly ITestOutputHelper _out;
            private readonly LogLevel _min;
            public Factory(ITestOutputHelper output, LogLevel min) { _out = output; _min = min; }
            public ILogger CreateLogger(string categoryName) => new Logger(_out, categoryName, _min);
            public void AddProvider(ILoggerProvider provider) { }
            public void Dispose() { }
        }

        private sealed class Logger : ILogger
        {
            private readonly ITestOutputHelper _out;
            private readonly string _category;
            private readonly LogLevel _min;
            public Logger(ITestOutputHelper output, string category, LogLevel min)
            {
                _out = output;
                _category = category.Substring(category.LastIndexOf('.') + 1);
                _min = min;
            }
            public IDisposable BeginScope<TState>(TState state) => null;
            public bool IsEnabled(LogLevel logLevel) => logLevel >= _min;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
                Func<TState, Exception, string> formatter)
            {
                if (!IsEnabled(logLevel)) return;
                try
                {
                    _out.WriteLine($"[{logLevel}] {_category}: {formatter(state, exception)}" +
                                   (exception == null ? string.Empty : $" | {exception.GetType().Name}: {exception.Message}"));
                }
                catch (InvalidOperationException)
                {
                    // ITestOutputHelper throws once the test has finished (background continuations).
                }
            }
        }
    }
}
