// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;

namespace Keyfactor.Extensions.CAPlugin.CERTInext
{
    /// <summary>
    /// The <c>EnrollmentCallBudgetSeconds</c> deadline for one <c>Enroll()</c> call, measured from
    /// entry. It only gates waiting: the pickup's initial delay and the delays between polls are
    /// shortened or skipped so the call returns before Command's workflow step timeout. Calls already
    /// in flight (create, reissue, Submit CSR) are never cut short.
    /// </summary>
    internal sealed class EnrollmentDeadline
    {
        private readonly TimeProvider _clock;
        private readonly long _startTimestamp;

        public EnrollmentDeadline(TimeProvider clock, TimeSpan budget)
        {
            _clock = clock;
            _startTimestamp = clock.GetTimestamp();
            Budget = budget;
        }

        public TimeSpan Budget { get; }

        public TimeSpan Elapsed => _clock.GetElapsedTime(_startTimestamp);

        public TimeSpan Remaining => Budget - Elapsed;

        /// <summary>
        /// Decides how long the pickup may wait before its next poll. Returns false when the time left
        /// can't fit another poll (<see cref="Constants.Pickup.DeadlinePollMarginSeconds"/>); otherwise
        /// <paramref name="wait"/> is <paramref name="desired"/>, shortened so the poll after it still
        /// starts with the margin in hand. A null deadline never shortens anything.
        /// </summary>
        public static bool TryGetWait(EnrollmentDeadline deadline, TimeSpan desired, out TimeSpan wait)
        {
            wait = desired;
            if (deadline == null)
                return true;

            TimeSpan available = deadline.Remaining - TimeSpan.FromSeconds(Constants.Pickup.DeadlinePollMarginSeconds);
            if (available <= TimeSpan.Zero)
                return false;

            if (available < desired)
                wait = available;
            return true;
        }
    }
}
