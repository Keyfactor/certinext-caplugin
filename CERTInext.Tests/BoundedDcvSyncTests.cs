using System;
using FluentAssertions;
using Xunit;
using static Keyfactor.Extensions.CAPlugin.CERTInext.CERTInextCAPlugin;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Issue 0002 — unit tests for the DCV-during-sync gate (EvaluateDcvSyncEligibility).
    /// Pure decision logic that bounds DCV work per sync pass so a large pending backlog
    /// can't make a pass slow. No DCV machinery / network needed.
    /// </summary>
    public class BoundedDcvSyncTests
    {
        private static readonly DateTime Now = new DateTime(2026, 6, 10, 12, 0, 0, DateTimeKind.Utc);

        // --- Age window ---------------------------------------------------------

        [Fact]
        public void RecentOrder_WithinAgeWindow_IsAttempted()
        {
            var orderDate = Now.AddHours(-1); // 1h old, window 24h
            EvaluateDcvSyncEligibility(orderDate, Now, ageWindowHours: 24, attemptedSoFar: 0, perPassCap: 50)
                .Should().Be(DcvSyncDecision.Attempt);
        }

        [Fact]
        public void OldOrder_BeyondAgeWindow_IsSkippedByAge()
        {
            var orderDate = Now.AddHours(-48); // 48h old, window 24h
            EvaluateDcvSyncEligibility(orderDate, Now, ageWindowHours: 24, attemptedSoFar: 0, perPassCap: 50)
                .Should().Be(DcvSyncDecision.SkipByAge);
        }

        [Fact]
        public void OrderExactlyAtAgeBoundary_IsAttempted()
        {
            var orderDate = Now.AddHours(-24); // exactly 24h, window 24h → still eligible (<=)
            EvaluateDcvSyncEligibility(orderDate, Now, ageWindowHours: 24, attemptedSoFar: 0, perPassCap: 50)
                .Should().Be(DcvSyncDecision.Attempt);
        }

        [Fact]
        public void UnknownOrderDate_IsAttempted_NotStarved()
        {
            EvaluateDcvSyncEligibility(orderDateUtc: null, Now, ageWindowHours: 24, attemptedSoFar: 0, perPassCap: 50)
                .Should().Be(DcvSyncDecision.Attempt);
        }

        [Fact]
        public void AgeWindowDisabled_OldOrderStillAttempted()
        {
            var orderDate = Now.AddDays(-30);
            EvaluateDcvSyncEligibility(orderDate, Now, ageWindowHours: 0, attemptedSoFar: 0, perPassCap: 50)
                .Should().Be(DcvSyncDecision.Attempt);
        }

        // --- Per-pass cap -------------------------------------------------------

        [Fact]
        public void UnderCap_IsAttempted()
        {
            EvaluateDcvSyncEligibility(Now, Now, ageWindowHours: 24, attemptedSoFar: 4, perPassCap: 5)
                .Should().Be(DcvSyncDecision.Attempt);
        }

        [Fact]
        public void AtCap_IsSkippedByCap()
        {
            EvaluateDcvSyncEligibility(Now, Now, ageWindowHours: 24, attemptedSoFar: 5, perPassCap: 5)
                .Should().Be(DcvSyncDecision.SkipByCap);
        }

        [Fact]
        public void CapDisabled_AlwaysAttemptedRegardlessOfCount()
        {
            EvaluateDcvSyncEligibility(Now, Now, ageWindowHours: 24, attemptedSoFar: 10_000, perPassCap: 0)
                .Should().Be(DcvSyncDecision.Attempt);
        }

        // --- Precedence ---------------------------------------------------------

        [Fact]
        public void AgeSkip_TakesPrecedenceOverCap()
        {
            // Old order AND at cap → reported as age skip (age checked first).
            var orderDate = Now.AddHours(-48);
            EvaluateDcvSyncEligibility(orderDate, Now, ageWindowHours: 24, attemptedSoFar: 5, perPassCap: 5)
                .Should().Be(DcvSyncDecision.SkipByAge);
        }

        // --- Simulated pass: a backlog of old + a few recent, with a small cap ---

        [Fact]
        public void SimulatedPass_OnlyRecentOrdersAttempted_AndCapped()
        {
            // 100 old (out-of-window) + 10 recent; cap 5. Mirrors the Synchronize loop's
            // use of the gate: only recent orders are eligible, and at most `cap` are attempted.
            const int ageWindow = 24, cap = 5;
            int attempted = 0, skippedAge = 0, skippedCap = 0;

            for (int i = 0; i < 100; i++) // old backlog
                Tally(EvaluateDcvSyncEligibility(Now.AddHours(-48), Now, ageWindow, attempted, cap),
                    ref attempted, ref skippedAge, ref skippedCap);
            for (int i = 0; i < 10; i++)  // recent
                Tally(EvaluateDcvSyncEligibility(Now.AddMinutes(-5), Now, ageWindow, attempted, cap),
                    ref attempted, ref skippedAge, ref skippedCap);

            attempted.Should().Be(5, "only up to the cap of recent orders are attempted");
            skippedAge.Should().Be(100, "the entire old backlog is skipped by the age window");
            skippedCap.Should().Be(5, "recent orders beyond the cap are deferred to a later pass");
        }

        private static void Tally(DcvSyncDecision d, ref int attempted, ref int skippedAge, ref int skippedCap)
        {
            switch (d)
            {
                case DcvSyncDecision.Attempt: attempted++; break;
                case DcvSyncDecision.SkipByAge: skippedAge++; break;
                case DcvSyncDecision.SkipByCap: skippedCap++; break;
            }
        }
    }
}
