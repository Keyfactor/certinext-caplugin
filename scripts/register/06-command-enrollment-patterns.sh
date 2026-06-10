#!/usr/bin/env bash
# Stage 06 — enrollment patterns + template key-retention in Keyfactor Command.
#
# For each imported AnyCA template (ConfigurationTenant = CONFIGURATION_TENANT):
#   (a) ensure an enrollment pattern exists and allows enrollment, and
#   (b) set the template's private-key retention.
#
# VERIFIED against Command (Portal-proxy /KeyfactorProxy, API v1) on 2026-06-09.
# Schema gotchas baked in from that run — see scripts/register/README.md:
#   - EnrollmentPatterns POST: `Template` is an INTEGER (not {Id:..});
#     `AllowedEnrollmentTypes` is PLURAL (singular is silently ignored -> 0);
#     `Policies` is REQUIRED ({} is accepted); `TemplateDefault` must be true
#     for the template's default pattern; `AssociatedRoles` are role NAME
#     strings that must already exist (this instance has "Command Admin",
#     NOT "InstanceAdmin").
#   - Update is PUT /EnrollmentPatterns/{id} (collection PUT returns 405).
#   - Template retention: PUT /Templates with a partial {Id,KeyRetention,
#     KeyRetentionDays} body (other fields are preserved).
#
# Env (in addition to the command-auth.sh contract):
#   CONFIGURATION_TENANT    template tenant to operate on (= gateway instance
#                           name, e.g. "certinext-0"). REQUIRED to match anything.
#   ENROLL_ROLE             role name granted on each pattern (default "Command Admin")
#   ENROLL_TYPES            AllowedEnrollmentTypes bitmask (default 3 = CSR+PFX)
#   PATTERN_PREFIX          name prefix for patterns (default "" -> use DisplayName)
#   TEMPLATE_KEY_RETENTION  KeyRetention value (default "Indefinite"; e.g. "None","Days")
#   TEMPLATE_KEY_RETENTION_DAYS  default 0 (used when retention is "Days")
#   SKIP_PATTERNS=1         only do template retention
#   SKIP_FIXUPS=1           only do enrollment patterns
#   DRY_RUN=1               print intended actions, no writes
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
export REPO_ROOT

# shellcheck disable=SC1090
[ -f ~/.env_certinext ] && . ~/.env_certinext
# shellcheck source=../lib/command-auth.sh
. "$SCRIPT_DIR/../lib/command-auth.sh"

DRY_RUN="${DRY_RUN:-0}"
ENROLL_ROLE="${ENROLL_ROLE:-Command Admin}"
ENROLL_TYPES="${ENROLL_TYPES:-3}"
PATTERN_PREFIX="${PATTERN_PREFIX:-}"
TEMPLATE_KEY_RETENTION="${TEMPLATE_KEY_RETENTION:-Indefinite}"
TEMPLATE_KEY_RETENTION_DAYS="${TEMPLATE_KEY_RETENTION_DAYS:-0}"

echo "== Stage 06: enrollment patterns + template key-retention =="
echo "   command : $(cmd_show)"
echo "   tenant  : $CONFIGURATION_TENANT   role: $ENROLL_ROLE   types: $ENROLL_TYPES"
echo "   keyret  : $TEMPLATE_KEY_RETENTION (days=$TEMPLATE_KEY_RETENTION_DAYS)"

if [ "$DRY_RUN" = "1" ]; then
    echo "   (dry run) for each template in tenant '$CONFIGURATION_TENANT':"
    [ "${SKIP_PATTERNS:-0}" = "1" ] || echo "     - ensure enrollment pattern '${PATTERN_PREFIX}<DisplayName>' (role $ENROLL_ROLE, types $ENROLL_TYPES)"
    [ "${SKIP_FIXUPS:-0}" = "1" ]   || echo "     - PUT /Templates KeyRetention=$TEMPLATE_KEY_RETENTION"
    echo "== done (dry run): no calls made =="
    exit 0
fi

TOK="$(command_token)"

# Templates for this tenant (zsh-safe: drive loops via while-read, not word-split).
TEMPLATES="$(cmd_curl "$TOK" GET "/Templates?ReturnLimit=500" "" 1 \
    | jq --arg t "$CONFIGURATION_TENANT" '[.[] | select(.ConfigurationTenant==$t)]')"
tcount="$(echo "$TEMPLATES" | jq 'length')"
echo "   templates: $tcount"
if [ "$tcount" -eq 0 ]; then
    echo "   nothing to do — no templates in tenant '$CONFIGURATION_TENANT'." >&2
    echo "   (set CONFIGURATION_TENANT to the gateway instance name; run stage 05 first.)" >&2
    exit 0
fi

# --- (a) enrollment patterns -------------------------------------------------
if [ "${SKIP_PATTERNS:-0}" != "1" ]; then
    EXISTING="$(cmd_curl "$TOK" GET /EnrollmentPatterns "" 1)"
    echo "$TEMPLATES" | jq -c '.[]' | while IFS= read -r tmpl; do
        tid="$(echo "$tmpl" | jq -r .Id)"
        disp="$(echo "$tmpl" | jq -r '.DisplayName // .CommonName')"
        pname="${PATTERN_PREFIX}${disp}"
        body="$(jq -n --arg n "$pname" --argjson t "$tid" --argjson types "$ENROLL_TYPES" \
            --arg role "$ENROLL_ROLE" \
            '{Name:$n, Template:$t, AllowedEnrollmentTypes:$types, TemplateDefault:true,
              AssociatedRoles:[$role], Policies:{}}')"
        pid="$(echo "$EXISTING" | jq -r --arg n "$pname" \
            'map(select(.Name==$n)) | (.[0].Id // empty)')"
        if [ -n "$pid" ]; then
            body="$(echo "$body" | jq --argjson id "$pid" '. + {Id:$id}')"
            resp="$(cmd_curl "$TOK" PUT "/EnrollmentPatterns/$pid" "$body" 1)"
            verb="PUT id=$pid"
        else
            resp="$(cmd_curl "$TOK" POST /EnrollmentPatterns "$body" 1)"
            verb="POST"
        fi
        ok="$(echo "$resp" | jq -r 'if .Id then "AllowedEnrollmentTypes=\(.AllowedEnrollmentTypes)" else "ERR: \(.Message//.)" end')"
        printf '   [pattern %-9s] %-44s %s\n' "$verb" "$pname" "$ok"
    done
fi

# --- (b) template key-retention ---------------------------------------------
if [ "${SKIP_FIXUPS:-0}" != "1" ]; then
    echo "$TEMPLATES" | jq -c '.[]' | while IFS= read -r tmpl; do
        tid="$(echo "$tmpl" | jq -r .Id)"
        cn="$(echo "$tmpl" | jq -r .CommonName)"
        body="$(jq -n --argjson id "$tid" --arg kr "$TEMPLATE_KEY_RETENTION" \
            --argjson days "$TEMPLATE_KEY_RETENTION_DAYS" \
            '{Id:$id, KeyRetention:$kr, KeyRetentionDays:$days}')"
        resp="$(cmd_curl "$TOK" PUT /Templates "$body" 1)"
        kr="$(echo "$resp" | jq -r '.KeyRetention // ("ERR: "+(.Message//"?"))')"
        printf '   [template PUT] %-44s KeyRetention=%s\n' "$cn" "$kr"
    done
fi

echo "== done =="
