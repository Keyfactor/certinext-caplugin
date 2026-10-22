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

using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// The single xUnit collection for every test that mutates or asserts on process-global logger
    /// state: the static <c>CERTInextClient.OverrideLoggerForTests</c> logger and
    /// <c>LogHandler.Factory</c> (finding #15).
    ///
    /// <c>DisableParallelization = true</c> makes xUnit run this collection by itself, after the
    /// parallel collections have finished, so no other test (in this collection or outside it) can
    /// log into a swapped logger while a capture is active. Without it, captured-log assertions
    /// (must-not-contain, exact counts) could pick up entries from unrelated tests and flake.
    ///
    /// Any new test class that swaps either logger, or asserts on captured log lines, MUST carry
    /// <c>[Collection(LoggingStateCollection.Name)]</c>.
    /// </summary>
    [CollectionDefinition(Name, DisableParallelization = true)]
    public sealed class LoggingStateCollection
    {
        public const string Name = "GlobalLoggerState-NoParallel";
    }
}
