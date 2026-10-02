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
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Models
{
    /// <summary>
    /// Neutralizes control characters before a requester-controlled value is interpolated into a
    /// log message.
    ///
    /// SAN values reach the log from the CSR and from Command's SAN dictionary, i.e. from the
    /// requester. Structured message templates stop format-string abuse but not embedded newlines,
    /// and NLog's text layout does not escape them — so an unsanitized value can forge additional,
    /// well-formed-looking records in the gateway log (CWE-117). That matters here specifically
    /// because these log lines exist to make the submitted SAN set auditable; a forged line could
    /// assert a different SAN set than the one actually sent.
    ///
    /// Shared between <c>CERTInextCAPlugin</c> and <c>Client.CERTInextClient</c> — both sanitize the
    /// same kind of value at their respective log sinks, so this used to be defined twice, byte-
    /// identical, one per class.
    /// </summary>
    internal static class LogSanitizer
    {
        internal static string Strip(string value)
        {
            if (string.IsNullOrEmpty(value)) return value;
            return value
                .Replace("\r", "\\r")
                .Replace("\n", "\\n")
                .Replace("\t", "\\t");
        }

        /// <summary>
        /// Masks the local part of an email address for logging while preserving the domain
        /// (e.g. <c>"j***@example.com"</c>), so an operator can still tell which organization
        /// an order came from without seeing exactly who submitted it. Used by both
        /// <c>CERTInextCAPlugin</c> and <c>Client.CERTInextClient</c> when
        /// <c>LogSensitiveRequestData</c> is off (issue 0040). Values with no <c>@</c> (blank,
        /// malformed, or not actually an email) fall back to a full <c>"***REDACTED***"</c>.
        /// </summary>
        internal static string MaskEmail(string value)
        {
            if (string.IsNullOrEmpty(value)) return value;
            int at = value.IndexOf('@');
            if (at <= 0) return "***REDACTED***";
            string domain = value.Substring(at + 1);
            return value.Substring(0, 1) + "***@" + domain;
        }

        // Email-shaped token inside free text. The lookbehind restricts match starts to token
        // boundaries so scanning stays linear on long runs of local-part characters (error bodies
        // can be up to 64 KB). Already-masked output ("j***@example.com") does not re-match, so
        // masking is idempotent. A trailing '.' is left out of the domain ("a@b.com." -> "a@b.com").
        private static readonly Regex EmailInText = new Regex(
            @"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+",
            RegexOptions.Compiled | RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(1));

        /// <summary>
        /// Prepares CA-supplied error text (<c>meta.errorMessage</c>, legacy <c>message</c>) for a
        /// log line or an exception message. With <paramref name="logSensitiveRequestData"/> on the
        /// text is returned unchanged. Off, email-shaped tokens are masked via <see cref="MaskEmail"/>
        /// (CERTInext may echo a submitted request value in its error text) and CR/LF/tab are
        /// neutralized via <see cref="Strip"/>; everything else (codes, field names, reasons) is kept
        /// word for word. Names and phone numbers in free text are not detected. Null passes through.
        /// Rate-limit detection must be given the raw text, not this output.
        /// </summary>
        internal static string SanitizeCaText(string text, bool logSensitiveRequestData)
        {
            if (logSensitiveRequestData || string.IsNullOrEmpty(text)) return text;
            try
            {
                return Strip(EmailInText.Replace(text, m => MaskEmail(m.Value)));
            }
            catch (RegexMatchTimeoutException)
            {
                return "(CA error text withheld: could not be safely masked)";
            }
        }

        // SAN type spellings (case-insensitive) whose values are email addresses: the gateway's
        // "rfc822name" plus the variants CERTInextCAPlugin.MapSanType normalizes to "email".
        private static readonly HashSet<string> EmailSanTypes =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "email", "rfc822", "rfc822name" };

        // SAN types logged verbatim even with LogSensitiveRequestData off: host names, IP
        // literals and URIs are audit fields, not personal data (issue 0040 follow-up).
        private static readonly HashSet<string> VerbatimSanTypes =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "dns", "dnsname", "dnsnames",
                "ip", "ipaddress", "ipaddresses",
                "uri", "uniformresourceidentifier"
            };

        /// <summary>
        /// Returns a single SAN value as it should appear in a log line (issue 0040 follow-up).
        /// With <paramref name="logSensitiveRequestData"/> on, the value is returned as-is. Off,
        /// an email-type SAN (<c>rfc822name</c> and its spelling variants) is masked with
        /// <see cref="MaskEmail"/>, and so is any value containing <c>@</c> whose type is unknown
        /// or <c>null</c> (untyped host lists). DNS, IP and URI values are always returned as-is.
        /// Does not <see cref="Strip"/>; callers strip the formatted line.
        /// </summary>
        internal static string FormatSanValue(string sanType, string value, bool logSensitiveRequestData)
        {
            if (logSensitiveRequestData || string.IsNullOrEmpty(value)) return value;
            if (sanType != null && EmailSanTypes.Contains(sanType)) return MaskEmail(value);
            if (sanType != null && VerbatimSanTypes.Contains(sanType)) return value;
            return value.IndexOf('@') >= 0 ? MaskEmail(value) : value;
        }

        /// <summary>
        /// Formats typed SAN entries as <c>"type:value; type:value"</c> for a log line, applying
        /// <see cref="FormatSanValue"/> to each value and <see cref="Strip"/> to the result.
        /// Returns <c>"(none)"</c> for a null or empty collection.
        /// </summary>
        internal static string FormatSans(
            IEnumerable<KeyValuePair<string, string>> sans, bool logSensitiveRequestData)
        {
            var parts = sans?
                .Select(s => $"{s.Key}:{FormatSanValue(s.Key, s.Value, logSensitiveRequestData)}")
                .ToList();
            return parts == null || parts.Count == 0 ? "(none)" : Strip(string.Join("; ", parts));
        }

        /// <summary>Gateway SAN dictionary overload of <see cref="FormatSans(IEnumerable{KeyValuePair{string, string}}, bool)"/>.</summary>
        internal static string FormatSans(Dictionary<string, string[]> san, bool logSensitiveRequestData)
            => FormatSans(
                san?.SelectMany(kvp => (kvp.Value ?? Array.Empty<string>())
                    .Select(v => new KeyValuePair<string, string>(kvp.Key, v))),
                logSensitiveRequestData);

        /// <summary>Resolved <see cref="API.SanEntry"/> overload of <see cref="FormatSans(IEnumerable{KeyValuePair{string, string}}, bool)"/>.</summary>
        internal static string FormatSans(IEnumerable<API.SanEntry> sans, bool logSensitiveRequestData)
            => FormatSans(
                sans?.Where(s => s != null).Select(s => new KeyValuePair<string, string>(s.Type, s.Value)),
                logSensitiveRequestData);

        /// <summary>
        /// Formats an untyped list of SAN-derived names (e.g. V1 <c>additionalDomains</c>, or order
        /// domains echoed back by the CA) joined by <paramref name="separator"/>. With no type to go
        /// on, any value containing <c>@</c> is masked when <paramref name="logSensitiveRequestData"/>
        /// is off. The result is <see cref="Strip"/>ped; <c>"(none)"</c> for a null or empty list.
        /// </summary>
        internal static string FormatUntypedSans(
            IEnumerable<string> values, bool logSensitiveRequestData, string separator = "; ")
        {
            var parts = values?.Select(v => FormatSanValue(null, v, logSensitiveRequestData)).ToList();
            return parts == null || parts.Count == 0 ? "(none)" : Strip(string.Join(separator, parts));
        }
    }
}
