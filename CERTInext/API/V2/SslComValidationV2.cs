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
using System.Globalization;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.API.V2
{
    // ---------------------------------------------------------------------------
    // V2 SSL.com organization validation
    //
    //   GET  /api/certinext/v2/organizations/{orgNumber}/ca-validations/sslcom
    //   POST /api/certinext/v2/organizations/{orgNumber}/ca-validations/sslcom        (submit)
    //   POST /api/certinext/v2/organizations/{orgNumber}/ca-validations/sslcom/sync   (refresh)
    //
    // The spec documents these endpoints only in prose ("Status per level (OV, EV) with validTill,
    // what is still missing before it can be submitted, and the SSL.com contact"; the responses are
    // untyped `object`). The model below is built from a live read-only sample, so every member is
    // optional, unknown members are kept in ExtensionData, and the per-level question ("is OV/EV
    // validated?") is answered defensively by V2SslComValidation.IsLevelValidated rather than
    // trusted to one field.
    // ---------------------------------------------------------------------------

    /// <summary>Response body of the SSL.com validation GET / sync / submit calls.</summary>
    public class V2SslComValidation
    {
        [JsonPropertyName("ca")]
        public string Ca { get; set; }

        [JsonPropertyName("caName")]
        public string CaName { get; set; }

        [JsonPropertyName("organizationNumber")]
        public string OrganizationNumber { get; set; }

        /// <summary>Overall state, e.g. <c>NOT_SUBMITTED</c>. Undocumented vocabulary.</summary>
        [JsonPropertyName("status")]
        public string Status { get; set; }

        /// <summary>
        /// Per-level state. Seen live as an empty array on a never-submitted organization; the spec
        /// says it carries "status per level (OV, EV) with validTill". Kept as raw JSON because the
        /// element shape is unconfirmed (objects with a level and a status, or bare level strings);
        /// see <see cref="IsLevelValidated"/>.
        /// </summary>
        [JsonPropertyName("levels")]
        public JsonElement Levels { get; set; }

        /// <summary>Levels SSL.com validates for this organization by default (seen live: <c>["OV"]</c>).</summary>
        [JsonPropertyName("defaultLevels")]
        public List<string> DefaultLevels { get; set; }

        [JsonPropertyName("subscriberAgreementAccepted")]
        public bool? SubscriberAgreementAccepted { get; set; }

        [JsonPropertyName("validatedAt")]
        public string ValidatedAt { get; set; }

        [JsonPropertyName("submittedAt")]
        public string SubmittedAt { get; set; }

        [JsonPropertyName("lastSyncedAt")]
        public string LastSyncedAt { get; set; }

        [JsonPropertyName("lastError")]
        public string LastError { get; set; }

        [JsonPropertyName("readiness")]
        public V2SslComReadiness Readiness { get; set; }

        /// <summary>The SSL.com contact. Personal data: never log it unmasked.</summary>
        [JsonPropertyName("contact")]
        public V2SslComContact Contact { get; set; }

        /// <summary>Any member this model doesn't know, so a new field never breaks parsing.</summary>
        [JsonExtensionData]
        public Dictionary<string, JsonElement> ExtensionData { get; set; }

        // Words that, as a status, mean the level is validated. Matched case-insensitively and exactly;
        // anything else (including not-yet-seen words such as "PENDING" or "SUBMITTED") is "not validated".
        private static readonly HashSet<string> ValidatedWords = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "VALIDATED", "VALID", "APPROVED", "ACTIVE", "COMPLETE", "COMPLETED", "ISSUED"
        };

        private static readonly string[] LevelNameKeys = { "level", "name", "type", "levelName", "validationLevel", "id", "code" };
        private static readonly string[] StatusKeys = { "status", "state", "validationStatus" };
        private static readonly string[] ValidTillKeys = { "validTill", "validUntil", "validTo", "expiresAt", "expiry" };
        private static readonly string[] ValidatedFlagKeys = { "validated", "isValidated" };

        /// <summary>
        /// True when SSL.com reports <paramref name="level"/> ("OV" or "EV") as validated. The shape
        /// of <see cref="Levels"/> is unconfirmed, so this accepts what a per-level entry could
        /// reasonably carry and otherwise answers "not validated" (the plugin only warns on that, so
        /// the cost of a false negative is a warning, never a blocked order):
        /// <list type="bullet">
        ///   <item>an array element or a map entry for the level, as an object carrying a status word
        ///   (see <c>ValidatedWords</c>) or a true <c>validated</c> flag, and not past a <c>validTill</c>;
        ///   an entry with no status but a future <c>validTill</c> also counts;</item>
        ///   <item>a bare string element naming the level counts only when the overall
        ///   <see cref="Status"/> is a validated word (the string alone doesn't say what state it is in);</item>
        ///   <item>a top-level member named after the level (<c>OV</c>/<c>EV</c>), same entry rules.</item>
        /// </list>
        /// The overall <see cref="Status"/> and <see cref="ValidatedAt"/> alone are never enough: they
        /// aren't per level.
        /// </summary>
        public bool IsLevelValidated(string level, DateTime? utcNow = null)
        {
            if (string.IsNullOrWhiteSpace(level)) return false;
            DateTime now = utcNow ?? DateTime.UtcNow;

            foreach (var entry in EnumerateLevelEntries(level))
            {
                if (entry.ValueKind == JsonValueKind.String)
                {
                    // A bare level name, or a bare status under a level-keyed member.
                    string text = entry.GetString();
                    if (string.Equals(text?.Trim(), level, StringComparison.OrdinalIgnoreCase))
                    {
                        if (IsValidatedWord(Status)) return true;
                    }
                    else if (IsValidatedWord(text))
                    {
                        return true;
                    }
                    continue;
                }
                if (entry.ValueKind == JsonValueKind.True) return true; // "OV": true
                if (entry.ValueKind != JsonValueKind.Object) continue;

                if (EntryIsValidated(entry, now)) return true;
            }

            return false;
        }

        /// <summary>
        /// True when <paramref name="level"/> appears in <see cref="Levels"/> (or as a top-level
        /// member) in any state, i.e. it has already been requested from SSL.com.
        /// </summary>
        public bool IsLevelListed(string level) =>
            !string.IsNullOrWhiteSpace(level) && EnumerateLevelEntries(level).Any();

        // Entries that talk about `level`: array elements naming it, level-keyed map members, and
        // level-keyed top-level members.
        private IEnumerable<JsonElement> EnumerateLevelEntries(string level)
        {
            if (Levels.ValueKind == JsonValueKind.Array)
            {
                foreach (var e in Levels.EnumerateArray())
                {
                    if (e.ValueKind == JsonValueKind.String)
                    {
                        if (string.Equals(e.GetString()?.Trim(), level, StringComparison.OrdinalIgnoreCase))
                            yield return e;
                    }
                    else if (e.ValueKind == JsonValueKind.Object && ObjectNamesLevel(e, level))
                    {
                        yield return e;
                    }
                }
            }
            else if (Levels.ValueKind == JsonValueKind.Object)
            {
                foreach (var p in Levels.EnumerateObject())
                    if (string.Equals(p.Name, level, StringComparison.OrdinalIgnoreCase))
                        yield return p.Value;
            }

            if (ExtensionData != null)
            {
                foreach (var kv in ExtensionData)
                    if (string.Equals(kv.Key, level, StringComparison.OrdinalIgnoreCase))
                        yield return kv.Value;
            }
        }

        private static bool ObjectNamesLevel(JsonElement obj, string level)
        {
            foreach (var key in LevelNameKeys)
                if (TryGetString(obj, key, out string v) && string.Equals(v?.Trim(), level, StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }

        private static bool EntryIsValidated(JsonElement entry, DateTime now)
        {
            // An expiry in the past overrides any status word.
            bool hasValidTill = false;
            DateTime validTill = default;
            foreach (var key in ValidTillKeys)
            {
                if (TryGetString(entry, key, out string v) && !string.IsNullOrWhiteSpace(v)
                    && DateTime.TryParse(v, CultureInfo.InvariantCulture,
                        DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out validTill))
                {
                    hasValidTill = true;
                    break;
                }
            }
            if (hasValidTill && validTill <= now) return false;

            foreach (var key in ValidatedFlagKeys)
                if (TryGetElement(entry, key, out var flag) && flag.ValueKind == JsonValueKind.True)
                    return true;

            foreach (var key in StatusKeys)
            {
                if (TryGetString(entry, key, out string status))
                    return IsValidatedWord(status);
            }

            // No status field at all: a future expiry is the only per-level evidence.
            return hasValidTill;
        }

        private static bool IsValidatedWord(string value) =>
            !string.IsNullOrWhiteSpace(value) && ValidatedWords.Contains(value.Trim());

        private static bool TryGetElement(JsonElement obj, string name, out JsonElement value)
        {
            foreach (var p in obj.EnumerateObject())
            {
                if (string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase))
                {
                    value = p.Value;
                    return true;
                }
            }
            value = default;
            return false;
        }

        private static bool TryGetString(JsonElement obj, string name, out string value)
        {
            value = null;
            if (!TryGetElement(obj, name, out var el)) return false;
            if (el.ValueKind == JsonValueKind.String) { value = el.GetString(); return true; }
            return false;
        }
    }

    /// <summary>The <c>readiness</c> block: what is still missing before the organization can be submitted.</summary>
    public class V2SslComReadiness
    {
        /// <summary>The organization has what an OV submission needs.</summary>
        [JsonPropertyName("ready")]
        public bool? Ready { get; set; }

        /// <summary>The organization has what an EV submission needs.</summary>
        [JsonPropertyName("evReady")]
        public bool? EvReady { get; set; }

        /// <summary>Field names still missing for OV (blocking).</summary>
        [JsonPropertyName("missing")]
        public List<string> Missing { get; set; }

        /// <summary>Field names still missing for EV (blocking).</summary>
        [JsonPropertyName("evMissing")]
        public List<string> EvMissing { get; set; }

        /// <summary>Field names that are advisable but not blocking.</summary>
        [JsonPropertyName("softMissing")]
        public List<string> SoftMissing { get; set; }

        /// <summary>Echo of the organization's current values; never read or logged by the plugin.</summary>
        [JsonExtensionData]
        public Dictionary<string, JsonElement> ExtensionData { get; set; }
    }

    /// <summary>The SSL.com contact. Personal data.</summary>
    public class V2SslComContact
    {
        [JsonPropertyName("name")]
        public string Name { get; set; }

        [JsonPropertyName("title")]
        public string Title { get; set; }

        [JsonPropertyName("email")]
        public string Email { get; set; }

        [JsonPropertyName("companyNumber")]
        public string CompanyNumber { get; set; }

        [JsonExtensionData]
        public Dictionary<string, JsonElement> ExtensionData { get; set; }
    }

    /// <summary>
    /// Request body of <c>POST .../ca-validations/sslcom</c> (spec prose): <c>levels</c> (["OV"],
    /// ["EV"] or both; empty = the organization's default), <c>subscriberAgreementAccepted</c> (must be
    /// true) and an optional <c>adminEmail</c>. The spec's other fields (<c>organizationPhone</c>,
    /// <c>businessCategoryId</c>, <c>registrationNumber</c>, <c>contactTitle</c>, "only where the
    /// organization lacks them") are deliberately not sent: the plugin only submits when the
    /// readiness block says nothing is missing.
    /// </summary>
    public class V2SslComSubmitRequest
    {
        [JsonPropertyName("levels")]
        public List<string> Levels { get; set; }

        [JsonPropertyName("subscriberAgreementAccepted")]
        public bool SubscriberAgreementAccepted { get; set; }

        [JsonPropertyName("adminEmail")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string AdminEmail { get; set; }
    }
}
