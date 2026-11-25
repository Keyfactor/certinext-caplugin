// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Pins the "CERTInext CA plugin version" line <see cref="CERTInextCAPlugin.Initialize"/> logs, so a
    /// customer log names the build that wrote it. Swaps <see cref="LogHandler.Factory"/> the same way as
    /// <see cref="CERTInextCAPluginAuditLoggingTests"/>, so it runs in the shared logging collection.
    /// </summary>
    [Collection(LoggingStateCollection.Name)]
    public class PluginVersionLoggingTests
    {
        private sealed class CapturingLoggerProvider : ILoggerProvider
        {
            public ConcurrentQueue<string> Messages { get; } = new();
            public ILogger CreateLogger(string categoryName) => new CapturingLogger(Messages);
            public void Dispose() { }

            private sealed class CapturingLogger : ILogger
            {
                private readonly ConcurrentQueue<string> _messages;
                public CapturingLogger(ConcurrentQueue<string> messages) => _messages = messages;
                public IDisposable BeginScope<TState>(TState state) => null;
                public bool IsEnabled(LogLevel logLevel) => true;
                public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
                    Func<TState, Exception, string> formatter)
                    => _messages.Enqueue(formatter(state, exception));
            }
        }

        [Fact]
        public void PluginVersion_IsTheAssemblyInformationalVersion()
        {
            string expected = typeof(CERTInextCAPlugin).Assembly
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;

            expected.Should().NotBeNullOrWhiteSpace("the SDK stamps an informational version on every build");
            CERTInextCAPlugin.PluginVersion.Should().Be(expected);
            CERTInextCAPlugin.PluginTargetFramework.Should().StartWith(".NETCoreApp,Version=v");
        }

        [Fact]
        public void Initialize_LogsVersion_EvenWhenConfigValidationThrows()
        {
            var provider = new CapturingLoggerProvider();
            var factory = LoggerFactory.Create(b => b.AddProvider(provider).SetMinimumLevel(LogLevel.Trace));
            try
            {
                LogHandler.Factory = factory;

                var configProvider = new Mock<IAnyCAPluginConfigProvider>(MockBehavior.Strict);
                // Cleartext, non-loopback ApiUrl: Initialize rejects it.
                configProvider.Setup(p => p.CAConnectionData)
                    .Returns(new Dictionary<string, object> { ["ApiUrl"] = "http://ca.example.com" });

                // Constructed AFTER the factory swap so its _logger field resolves through it.
                var plugin = new CERTInextCAPlugin();
                Action act = () => plugin.Initialize(configProvider.Object, new Mock<ICertificateDataReader>().Object);

                act.Should().Throw<InvalidOperationException>();
            }
            finally
            {
                LogHandler.Factory = Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance;
                factory.Dispose();
            }

            string line = provider.Messages.FirstOrDefault(m => m.StartsWith("CERTInext CA plugin version "));
            line.Should().NotBeNull("Initialize logs the version before it validates the config");
            line.Should().Contain(CERTInextCAPlugin.PluginVersion);
            line.Should().Contain($"DcvSupport={CERTInextCAPlugin.PluginDcvSupport}");
            line.Should().Contain($"TargetFramework={CERTInextCAPlugin.PluginTargetFramework}");
        }
    }
}
