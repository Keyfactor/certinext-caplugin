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
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Models
{
    /// <summary>
    /// Call-trace scope: writes <c>Calling &lt;method&gt;</c> at Trace when created and
    /// <c>returned from &lt;method&gt;</c> at Trace when disposed, so the log shows exactly when each
    /// function started and returned (including when it throws, because <c>using</c> disposes on
    /// every exit path).
    ///
    /// Usage — first statement of the body:
    /// <c>using var callTrace = _logger.TraceCall();</c>
    /// The method name comes from <see cref="CallerMemberNameAttribute"/>. Constructors would emit
    /// <c>.ctor</c>, so they pass the class name explicitly: <c>_logger.TraceCall(nameof(MyClass))</c>.
    ///
    /// Names only — never pass arguments, return values or payloads through here.
    /// </summary>
    internal static class CallTrace
    {
        private static readonly IDisposable NoOp = new NoOpScope();

        internal static IDisposable TraceCall(this ILogger logger, [CallerMemberName] string method = "")
        {
            // Disabled-Trace fast path: no allocation, no output.
            if (logger == null || !logger.IsEnabled(LogLevel.Trace)) return NoOp;

            logger.LogTrace("Calling {Method}", method);
            return new Scope(logger, method);
        }

        private sealed class Scope : IDisposable
        {
            private readonly ILogger _logger;
            private readonly string _method;
            private int _disposed;

            internal Scope(ILogger logger, string method)
            {
                _logger = logger;
                _method = method;
            }

            public void Dispose()
            {
                // Write the return line once, even if Dispose is called more than once.
                if (System.Threading.Interlocked.Exchange(ref _disposed, 1) == 0)
                {
                    _logger.LogTrace("returned from {Method}", _method);
                }
            }
        }

        private sealed class NoOpScope : IDisposable
        {
            public void Dispose() { }
        }
    }
}
