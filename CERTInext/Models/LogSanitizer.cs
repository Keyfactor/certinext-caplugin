// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0

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
    }
}
