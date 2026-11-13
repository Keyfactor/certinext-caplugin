// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Concurrent;
using System.Linq;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Captures every log line (level + rendered message) written by a <c>CERTInextCAPlugin</c>
    /// constructed while the capture is active, by swapping <see cref="LogHandler.Factory"/>.
    /// The plugin resolves its class logger at construction time, so BUILD THE PLUGIN INSIDE the
    /// capture scope. Process-global state: every test class that uses it must carry
    /// <c>[Collection(LoggingStateCollection.Name)]</c>.
    /// </summary>
    internal sealed class PluginLogCapture : IDisposable
    {
        private sealed class Provider : ILoggerProvider
        {
            public ConcurrentQueue<(LogLevel Level, string Message)> Entries { get; } = new();
            public ILogger CreateLogger(string categoryName) => new Capturing(Entries);
            public void Dispose() { }

            private sealed class Capturing : ILogger
            {
                private readonly ConcurrentQueue<(LogLevel, string)> _entries;
                public Capturing(ConcurrentQueue<(LogLevel, string)> entries) => _entries = entries;
                public IDisposable BeginScope<TState>(TState state) => null;
                public bool IsEnabled(LogLevel logLevel) => true;
                public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
                    Func<TState, Exception, string> formatter)
                    => _entries.Enqueue((logLevel, formatter(state, exception)));
            }
        }

        private readonly Provider _provider = new();
        private readonly ILoggerFactory _factory;

        public PluginLogCapture()
        {
            _factory = LoggerFactory.Create(b => b.AddProvider(_provider).SetMinimumLevel(LogLevel.Trace));
            LogHandler.Factory = _factory;
        }

        public (LogLevel Level, string Message)[] Entries => _provider.Entries.ToArray();

        /// <summary>Lines at exactly <paramref name="level"/> whose message contains <paramref name="marker"/>.</summary>
        public string[] Lines(LogLevel level, string marker) => Entries
            .Where(e => e.Level == level && e.Message.Contains(marker))
            .Select(e => e.Message).ToArray();

        public void Dispose()
        {
            LogHandler.Factory = NullLoggerFactory.Instance;
            _factory.Dispose();
        }
    }
}
