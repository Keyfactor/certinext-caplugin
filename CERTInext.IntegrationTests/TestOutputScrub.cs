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
using System.Text.RegularExpressions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    /// <summary>
    /// Scrubs CA-originated text (exception messages, status messages, status strings) before it is
    /// written to <c>ITestOutputHelper</c>, so a CA error that echoes the requestor or POC email from
    /// <c>~/.env_certinext</c> cannot land in test or CI output.
    /// </summary>
    internal static class TestOutputScrub
    {
        private const int MaxLength = 500;

        private static readonly Regex EmailPattern =
            new Regex(@"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", RegexOptions.Compiled);

        /// <summary>Masks anything that looks like an email address, then truncates to 500 chars.</summary>
        public static string Scrub(string s)
        {
            if (s == null) return null;
            s = EmailPattern.Replace(s, "<email>");
            return s.Length > MaxLength ? s.Substring(0, MaxLength) : s;
        }

        /// <summary>
        /// "TypeName: scrubbed message" for <paramref name="ex"/>, followed by the same for each inner
        /// exception (separated by " <- ").
        /// </summary>
        public static string Describe(Exception ex)
        {
            if (ex == null) return null;
            var sb = new System.Text.StringBuilder();
            for (var cur = ex; cur != null; cur = cur.InnerException)
            {
                if (sb.Length > 0) sb.Append(" <- ");
                sb.Append(cur.GetType().Name).Append(": ").Append(Scrub(cur.Message));
            }
            return sb.ToString();
        }
    }
}
