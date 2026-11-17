// Copyright 2026 Keyfactor
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
using FluentAssertions;
using Keyfactor.AnyGateway.Extensions;
using Keyfactor.Extensions.CAPlugin.CERTInext.API;
using Keyfactor.Extensions.CAPlugin.CERTInext.API.V2;
using Keyfactor.Extensions.CAPlugin.CERTInext.Client;
using Keyfactor.PKI.Enums.EJBCA;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// <c>EnrollmentCallBudgetSeconds</c>: the in-call pickup wait is bounded by a deadline measured from
    /// <c>Enroll()</c> entry, so time spent creating or reissuing the order counts against it and the call
    /// returns before Command's workflow step timeout (60 s by default). Driven on a manual clock: the
    /// plugin's pickup waits advance it instead of sleeping, and each CA call advances it by its latency.
    /// </summary>
    [Collection(LoggingStateCollection.Name)]
    public class EnrollmentDeadlineTests
    {
        private const string OrderId = "ord_deadline_001";
        private static readonly TimeSpan PollLatency = TimeSpan.FromSeconds(0.5);

        private sealed class ManualClock : TimeProvider
        {
            private long _ticks;
            public override long TimestampFrequency => TimeSpan.TicksPerSecond;
            public override long GetTimestamp() => Interlocked.Read(ref _ticks);
            public void Advance(TimeSpan by) => Interlocked.Add(ref _ticks, by.Ticks);
        }

        private sealed class Harness
        {
            public ManualClock Clock { get; } = new ManualClock();
            public List<TimeSpan> Waits { get; } = new List<TimeSpan>();

            public CERTInextCAPlugin Wire(CERTInextCAPlugin plugin)
            {
                plugin.Clock = Clock;
                plugin.PickupDelayAsync = (d, ct) =>
                {
                    Waits.Add(d);
                    Clock.Advance(d);
                    return Task.CompletedTask;
                };
                return plugin;
            }
        }

        // ---------------------------------------------------------------------------
        // TryGetWait
        // ---------------------------------------------------------------------------

        [Fact]
        public void TryGetWait_NoDeadline_KeepsDesiredWait()
        {
            EnrollmentDeadline.TryGetWait(null, TimeSpan.FromSeconds(10), out var wait).Should().BeTrue();
            wait.Should().Be(TimeSpan.FromSeconds(10));
        }

        [Theory]
        [InlineData(0, 10, true, 10)]   // plenty left
        [InlineData(42, 10, true, 5)]   // 8 s left: wait shortened to leave the 3 s poll margin
        [InlineData(47, 10, false, 0)]  // 3 s left: no room for a poll
        [InlineData(49, 5, false, 0)]
        public void TryGetWait_ShortensOrRefuses_ByRemainingBudget(int elapsed, int desired, bool expectOk, int expectedWait)
        {
            var clock = new ManualClock();
            var deadline = new EnrollmentDeadline(clock, TimeSpan.FromSeconds(50));
            clock.Advance(TimeSpan.FromSeconds(elapsed));

            EnrollmentDeadline.TryGetWait(deadline, TimeSpan.FromSeconds(desired), out var wait).Should().Be(expectOk);
            if (expectOk)
                wait.Should().Be(TimeSpan.FromSeconds(expectedWait));
        }

        [Theory]
        [InlineData(50, 50)]
        [InlineData(0, 0)]
        [InlineData(-5, 50)]
        [InlineData(120, 90)]
        [InlineData(75, 75)]
        public void EffectiveBudget_ZeroDisables_NegativeDefaults_ClampedBelowHttpTimeout(int configured, int expected)
        {
            new CERTInextConfig { EnrollmentCallBudgetSeconds = configured }
                .GetEffectiveEnrollmentCallBudgetSeconds().Should().Be(expected);
        }

        [Fact]
        public void DefaultConfig_HasFiftySecondBudget()
        {
            new CERTInextConfig().GetEffectiveEnrollmentCallBudgetSeconds().Should().Be(50);
        }

        // ---------------------------------------------------------------------------
        // V2
        // ---------------------------------------------------------------------------

        private static CERTInextConfig V2Config(int retries = 5, int delay = 10, int? budget = null)
        {
            var config = new CERTInextConfig
            {
                UseV2Api = true, ApiUrl = "https://v2.certinext.io", OAuthClientId = "id", OAuthClientSecret = "s",
                AccountNumber = "12345", RequestorName = "Test User", RequestorEmail = "test@example.com",
                SignerPlace = "New York", PickupRetries = retries, PickupDelayInSeconds = delay
            };
            if (budget.HasValue)
                config.EnrollmentCallBudgetSeconds = budget.Value;
            return config;
        }

        /// <summary>
        /// A V2 DV order that stays pending: the create takes <paramref name="createLatency"/>, and every
        /// Track Order call takes <see cref="PollLatency"/>.
        /// </summary>
        private static Mock<ICERTInextClient> PendingV2Order(Harness h, TimeSpan createLatency)
        {
            var mock = new Mock<ICERTInextClient>();
            mock.Setup(c => c.GetProductDetailsV2Async(It.IsAny<CancellationToken>()))
                .ReturnsAsync(new List<ProductDetail> { new ProductDetail { ProductCode = "842", ProductTypeId = "13", Active = true } });
            mock.Setup(c => c.PlaceOrderV2Async(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<V2CreateSslOrderRequest>(), It.IsAny<CancellationToken>()))
                .Callback(() => h.Clock.Advance(createLatency))
                .ReturnsAsync(new V2CreateOrderResponse { OrderId = OrderId, Status = "pending-dcv" });
            mock.Setup(c => c.TrackOrderV2Async(It.IsAny<string>(), OrderId, It.IsAny<CancellationToken>()))
                .Callback(() => h.Clock.Advance(PollLatency))
                .ReturnsAsync(new V2OrderStatusResponse { OrderId = OrderId, Status = "pending-dcv" });
            return mock;
        }

        private static Task<EnrollmentResult> EnrollV2(CERTInextCAPlugin plugin) =>
            plugin.Enroll(
                MockCertificateData.FakeCsrPem, "CN=example.com",
                new Dictionary<string, string[]> { ["dns"] = new[] { "example.com" } },
                new EnrollmentProductInfo
                {
                    ProductID = "DV SSL",
                    ProductParameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["ProductCode"] = "842", ["ProductFamily"] = "ssl", ["ProductVariant"] = "dv",
                        ["DomainName"] = "example.com"
                    }
                },
                RequestFormat.PKCS10, EnrollmentType.New);

        private static int PickupPolls(Mock<ICERTInextClient> mock, int callsBeforePickup) =>
            mock.Invocations.Count(i => i.Method.Name == nameof(ICERTInextClient.TrackOrderV2Async)) - callsBeforePickup;

        [Fact]
        public async Task V2_CreateUsedMostOfBudget_SkipsPickup_ReturnsPendingInsideBudget()
        {
            using var capture = new PluginLogCapture();
            var h = new Harness();
            var mock = PendingV2Order(h, TimeSpan.FromSeconds(47));
            var plugin = h.Wire(new CERTInextCAPlugin(mock.Object, V2Config()));

            var result = await EnrollV2(plugin);

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            result.CARequestID.Should().Be(OrderId);
            h.Waits.Should().BeEmpty("47 s create + the post-create status check leave no room for a poll");
            h.Clock.GetElapsedTime(0).Should().BeLessThan(TimeSpan.FromSeconds(50));
            capture.Lines(LogLevel.Information, "stopped early").Should().ContainSingle()
                .Which.Should().Contain("of the 50 s EnrollmentCallBudgetSeconds").And.Contain("0 of 5 attempt(s) ran");
        }

        [Fact]
        public async Task V2_SlowReissueLikeCreate_26s_PickupFitsTheRemainingBudget()
        {
            // The live reissue took 25.8 s before the pickup started. The default pickup (5 s + 5 x 10 s)
            // then ran to ~60 s after Enroll started; now it is cut to what's left of the 50 s.
            using var capture = new PluginLogCapture();
            var h = new Harness();
            var mock = PendingV2Order(h, TimeSpan.FromSeconds(26));
            var plugin = h.Wire(new CERTInextCAPlugin(mock.Object, V2Config()));
            int trackBeforePickup = 1; // the post-create status check

            var result = await EnrollV2(plugin);

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            // 26.5 s used: wait 5, poll (0.5), wait 10, poll (at 42.5 s), then 4.5 s (shortened from 10, keeping
            // the 3 s poll margin) and a last poll.
            h.Waits.Should().Equal(TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(4.5));
            PickupPolls(mock, trackBeforePickup).Should().Be(3);
            h.Clock.GetElapsedTime(0).Should().BeLessThanOrEqualTo(TimeSpan.FromSeconds(50));
            capture.Lines(LogLevel.Information, "stopped early").Should().ContainSingle()
                .Which.Should().Contain("3 of 5 attempt(s) ran");
        }

        [Fact]
        public async Task V2_FastCreate_DefaultPickupFitsUntilTheBudgetIsReached()
        {
            var h = new Harness();
            var mock = PendingV2Order(h, TimeSpan.FromSeconds(1));
            var plugin = h.Wire(new CERTInextCAPlugin(mock.Object, V2Config()));

            await EnrollV2(plugin);

            h.Clock.GetElapsedTime(0).Should().BeLessThanOrEqualTo(TimeSpan.FromSeconds(50));
            h.Waits.Sum(w => w.TotalSeconds).Should().BeGreaterThan(40, "a fast create leaves most of the budget for polling");
        }

        [Fact]
        public async Task V2_PickupRetriesZero_Unchanged_NoWaitNoPoll()
        {
            using var capture = new PluginLogCapture();
            var h = new Harness();
            var mock = PendingV2Order(h, TimeSpan.FromSeconds(1));
            var plugin = h.Wire(new CERTInextCAPlugin(mock.Object, V2Config(retries: 0)));

            var result = await EnrollV2(plugin);

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            h.Waits.Should().BeEmpty();
            PickupPolls(mock, 1).Should().Be(0);
            capture.Lines(LogLevel.Information, "PickupRetries<=0").Should().ContainSingle();
            capture.Lines(LogLevel.Information, "stopped early").Should().BeEmpty();
        }

        [Fact]
        public async Task V2_BudgetZero_NoDeadline_KeepsFullCadenceIncludingTrailingDelay()
        {
            var h = new Harness();
            var mock = PendingV2Order(h, TimeSpan.FromSeconds(30));
            var plugin = h.Wire(new CERTInextCAPlugin(mock.Object, V2Config(retries: 3, delay: 10, budget: 0)));

            await EnrollV2(plugin);

            h.Waits.Should().Equal(
                TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));
            PickupPolls(mock, 1).Should().Be(3);
        }

        [Fact]
        public async Task V2_NoDelayAfterLastPoll_UnderDeadline()
        {
            var h = new Harness();
            var mock = PendingV2Order(h, TimeSpan.FromSeconds(1));
            var plugin = h.Wire(new CERTInextCAPlugin(mock.Object, V2Config(retries: 2, delay: 10)));

            await EnrollV2(plugin);

            h.Waits.Should().Equal(TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10));
            PickupPolls(mock, 1).Should().Be(2);
        }

        // ---------------------------------------------------------------------------
        // V1 (new enroll and renew both use PickUpEnrolledCertificateAsync)
        // ---------------------------------------------------------------------------

        private static EnrollmentProductInfo V1ProductInfo(Dictionary<string, string> extras = null)
        {
            var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ProfileId"] = MockCertificateData.ProfileIdTls
            };
            foreach (var kv in extras ?? new Dictionary<string, string>())
                parameters[kv.Key] = kv.Value;
            return new EnrollmentProductInfo { ProductID = MockCertificateData.ProfileIdTls, ProductParameters = parameters };
        }

        [Fact]
        public async Task V1_NewEnroll_SlowOrder_PickupHonoursDeadline()
        {
            using var capture = new PluginLogCapture();
            var h = new Harness();
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            mock.Setup(c => c.EnrollCertificateAsync(It.IsAny<EnrollCertificateRequest>(), It.IsAny<CancellationToken>()))
                .Callback(() => h.Clock.Advance(TimeSpan.FromSeconds(40)))
                .ReturnsAsync(MockCertificateData.PendingEnrollResponse());
            mock.Setup(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .Callback(() => h.Clock.Advance(PollLatency))
                .ReturnsAsync(MockCertificateData.PendingCertRecord());
            var plugin = h.Wire(new CERTInextCAPlugin(mock.Object, new CERTInextConfig { PickupRetries = 5, PickupDelayInSeconds = 10 }));

            var result = await plugin.Enroll(MockCertificateData.FakeCsrPem, "CN=test.example.com", null,
                V1ProductInfo(), RequestFormat.PKCS10, EnrollmentType.New);

            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            // 10 s left: wait 5, poll (0.5), then 1.5 s (shortened), a last poll, and stop.
            h.Waits.Should().Equal(TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(1.5));
            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Exactly(2));
            h.Clock.GetElapsedTime(0).Should().BeLessThanOrEqualTo(TimeSpan.FromSeconds(50));
            capture.Lines(LogLevel.Information, "stopped early").Should().ContainSingle();
        }

        [Fact]
        public async Task V1_Renew_SlowRenewal_SkipsPickupWhenNoPollFits()
        {
            const string prior = "ORD-PRIOR-001";
            var h = new Harness();
            var reader = new Mock<ICertificateDataReader>();
            reader.Setup(r => r.GetRequestIDBySerialNumber(It.IsAny<string>())).ReturnsAsync(prior);
            reader.Setup(r => r.GetExpirationDateByRequestId(prior)).Returns(DateTime.UtcNow.AddDays(30));
            var mock = new Mock<ICERTInextClient>(MockBehavior.Strict);
            mock.Setup(c => c.RenewCertificateAsync(prior, It.IsAny<RenewCertificateRequest>(), It.IsAny<CancellationToken>()))
                .Callback(() => h.Clock.Advance(TimeSpan.FromSeconds(48)))
                .ReturnsAsync(MockCertificateData.PendingEnrollResponse("ORD-RENEW-002"));
            var plugin = h.Wire(new CERTInextCAPlugin(mock.Object, reader.Object,
                new CERTInextConfig { PickupRetries = 5, PickupDelayInSeconds = 10, DcvEnabled = false }));

            var result = await plugin.Enroll(MockCertificateData.FakeCsrPem, "CN=renew.example.com",
                new Dictionary<string, string[]> { ["dns"] = new[] { "renew.example.com" } },
                V1ProductInfo(new Dictionary<string, string> { ["PriorCertSN"] = "AABB", ["RenewalWindowDays"] = "90" }),
                RequestFormat.PKCS10, EnrollmentType.RenewOrReissue);

            result.CARequestID.Should().Be("ORD-RENEW-002");
            result.Status.Should().Be((int)EndEntityStatus.EXTERNALVALIDATION);
            h.Waits.Should().BeEmpty();
            mock.Verify(c => c.GetCertificateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never,
                "the strict mock would also throw: no poll fits in the 2 s left");
        }
    }
}
