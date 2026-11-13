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

using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Read-only guard (issue 0090, V1 sync hold-back): GetOrderReport's per-row <c>orderDate</c>
    /// must stay "yyyy-MM-dd HH:mm:ss" (whole seconds, no zone marker; read as UTC, verified
    /// 2026-10-15 against plugin and gateway UTC log timestamps). The sync hold-back measures an
    /// order's age from it. No orders are created.
    /// </summary>
    public class OrderDateFormatProbeTests : IClassFixture<IntegrationTestFixture>
    {
        private readonly IntegrationTestFixture _fixture;
        private readonly ITestOutputHelper _output;

        public OrderDateFormatProbeTests(IntegrationTestFixture fixture, ITestOutputHelper output)
        {
            _fixture = fixture;
            _output = output;
        }

        [SkippableFact]
        public async Task GetOrderReport_OrderDate_IsSecondPrecisionWithoutZoneMarker()
        {
            IntegrationSkip.IfNotConfigured(_fixture);

            var shapes = new Dictionary<string, int>();
            int total = 0;
            await foreach (var entry in _fixture.Client.ListOrdersAsync(
                orderDateFrom: null, pageSize: 100, ct: CancellationToken.None))
            {
                total++;
                // Digits masked so the output records the wire shape, not the data.
                string shape = Regex.Replace(entry.OrderDate ?? "(null)", @"\d", "9");
                shapes[shape] = shapes.TryGetValue(shape, out var n) ? n + 1 : 1;
                if (total >= 300) break;
            }

            _output.WriteLine($"rows={total}");
            foreach (var kv in shapes.OrderByDescending(k => k.Value))
                _output.WriteLine($"orderDate shape '{kv.Key}' x{kv.Value}");

            Skip.If(total == 0, "account has no orders");
            Assert.All(shapes.Keys, k => Assert.Equal("9999-99-99 99:99:99", k));
        }
    }
}
