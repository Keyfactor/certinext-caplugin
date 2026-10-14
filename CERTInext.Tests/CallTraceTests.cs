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
using System.Linq;
using System.Threading.Tasks;
using FluentAssertions;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.Extensions.CAPlugin.CERTInext.Models;
using Keyfactor.Logging;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// The call-trace scope (<see cref="CallTrace.TraceCall"/>) writes <c>Calling X</c> and
    /// <c>returned from X</c> at Trace around every instrumented function. It must write the return
    /// line on every exit path (including a throw) and stay silent when Trace is disabled.
    /// In <see cref="LoggingStateCollection"/> because the plugin-level name checks swap
    /// <c>LogHandler.Factory</c>.
    /// </summary>
    [Collection(LoggingStateCollection.Name)]
    public class CallTraceTests
    {
        private sealed class RecordingLogger : ILogger
        {
            private readonly LogLevel _min;
            public RecordingLogger(LogLevel min) => _min = min;
            public ConcurrentQueue<(LogLevel Level, string Message)> Entries { get; } = new();
            public IDisposable BeginScope<TState>(TState state) => null;
            public bool IsEnabled(LogLevel logLevel) => logLevel >= _min;
            // Records without re-checking IsEnabled, so any line seen here was written despite the gate.
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
                Func<TState, Exception, string> formatter)
                => Entries.Enqueue((logLevel, formatter(state, exception)));
        }

        private sealed class RecordingProvider : ILoggerProvider
        {
            public ConcurrentQueue<string> Messages { get; } = new();
            public ILogger CreateLogger(string categoryName) => new ProviderLogger(Messages);
            public void Dispose() { }

            private sealed class ProviderLogger : ILogger
            {
                private readonly ConcurrentQueue<string> _messages;
                public ProviderLogger(ConcurrentQueue<string> messages) => _messages = messages;
                public IDisposable BeginScope<TState>(TState state) => null;
                public bool IsEnabled(LogLevel logLevel) => true;
                public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception,
                    Func<TState, Exception, string> formatter) => _messages.Enqueue(formatter(state, exception));
            }
        }

        private static void SampleMethod(ILogger logger)
        {
            using var callTrace = logger.TraceCall();
        }

        private static void ThrowingMethod(ILogger logger)
        {
            using var callTrace = logger.TraceCall();
            throw new InvalidOperationException("boom");
        }

        [Fact]
        public void TraceCall_WritesCallingThenReturnedFrom_WithMethodName()
        {
            var logger = new RecordingLogger(LogLevel.Trace);

            SampleMethod(logger);

            logger.Entries.ToArray().Should().Equal(
                (LogLevel.Trace, "Calling SampleMethod"),
                (LogLevel.Trace, "returned from SampleMethod"));
        }

        [Fact]
        public void TraceCall_BodyThrows_StillWritesReturnedFrom()
        {
            var logger = new RecordingLogger(LogLevel.Trace);

            Action act = () => ThrowingMethod(logger);

            act.Should().Throw<InvalidOperationException>().WithMessage("boom");
            logger.Entries.ToArray().Should().Equal(
                (LogLevel.Trace, "Calling ThrowingMethod"),
                (LogLevel.Trace, "returned from ThrowingMethod"));
        }

        [Theory]
        [InlineData(LogLevel.Debug)]
        [InlineData(LogLevel.Information)]
        [InlineData(LogLevel.Warning)]
        [InlineData(LogLevel.None)]
        public void TraceCall_TraceDisabled_WritesNothing(LogLevel minimum)
        {
            var logger = new RecordingLogger(minimum);

            SampleMethod(logger);
            Action act = () => ThrowingMethod(logger);
            act.Should().Throw<InvalidOperationException>();

            logger.Entries.Should().BeEmpty();
        }

        [Fact]
        public async Task Plugin_ConstructorAndAsyncMethod_EmitSourceNames()
        {
            // Name evidence for the two shapes CallerMemberName treats specially or not: a constructor
            // (passes nameof explicitly, otherwise it would emit ".ctor") and an async method.
            var provider = new RecordingProvider();
            var factory = LoggerFactory.Create(b => b.AddProvider(provider).SetMinimumLevel(LogLevel.Trace));
            try
            {
                LogHandler.Factory = factory;
                var client = new Mock<ICERTInextClient>(MockBehavior.Loose);
                var plugin = new CERTInextCAPlugin(client.Object, new CERTInextConfig());

                await plugin.Ping();

                var trace = provider.Messages
                    .Where(m => m.StartsWith("Calling ") || m.StartsWith("returned from "))
                    .ToArray();
                trace.Should().ContainInOrder("Calling CERTInextCAPlugin", "returned from CERTInextCAPlugin");
                trace.Should().ContainInOrder("Calling Ping", "returned from Ping");
                trace.Should().NotContain(m => m.Contains(".ctor"));
            }
            finally
            {
                LogHandler.Factory = Microsoft.Extensions.Logging.Abstractions.NullLoggerFactory.Instance;
                factory.Dispose();
            }
        }
    }
}
