#!/usr/bin/env bash
# Stage 03 — register gateway access claims (IAM).
#
# POSTs /config/claim for each entry, mapping an OAuth subject to a gateway role.
# Idempotent: claims already present (matched on type+value+role) are skipped.
#
# STATUS: UNVERIFIED — shape from docs/reference/gateway/claims.json and
# kfc-in-a-box init-anygateway.sh. Validate against a live gateway.
#
# Env:
#   CLAIMS_JSON   JSON array of claim objects to ensure. Default mirrors the
#                 captured reference: the machine client (admin+user) and the
#                 human admin (akadmin). Each object:
#                   {type, value, role, provider, description}
#   DRY_RUN=1     print intended actions, no writes
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
export REPO_ROOT

# shellcheck disable=SC1090
[ -f ~/.env_certinext ] && . ~/.env_certinext
# shellcheck source=../lib/command-auth.sh
. "$SCRIPT_DIR/../lib/command-auth.sh"

DRY_RUN="${DRY_RUN:-0}"

# OIDC client id drives the machine-client subject (ak-<client>_credentials).
_machine_sub="${CLAIM_MACHINE_SUBJECT:-ak-${OIDC_CLIENT_ID:-anygateway-gateway-certinext-client}_credentials}"
_admin_user="${CLAIM_ADMIN_USER:-akadmin}"
_provider="${CLAIM_PROVIDER:-Authentik}"

DEFAULT_CLAIMS_JSON="$(jq -n \
    --arg msub "$_machine_sub" --arg admin "$_admin_user" --arg prov "$_provider" \
    '[
      {type:"OAuth_sub", value:$msub,  role:"admin", provider:$prov, description:"Authentik machine client"},
      {type:"OAuth_sub", value:$msub,  role:"user",  provider:$prov, description:"Authentik machine client"},
      {type:"OAuth_sub", value:$admin, role:"admin", provider:$prov, description:"Authentik admin user"}
    ]')"
CLAIMS_JSON="${CLAIMS_JSON:-$DEFAULT_CLAIMS_JSON}"

echo "== Stage 03: gateway claims =="
echo "   gateway : $(gw_show)"

count="$(echo "$CLAIMS_JSON" | jq 'length')"
echo "   claims  : $count"

if [ "$DRY_RUN" = "1" ]; then
    echo "$CLAIMS_JSON" | jq -c '.[] | {type, value, role}'
    echo "== done (dry run): no calls made =="
    exit 0
fi

TOK="$(gateway_token)"
EXISTING="$(gw_curl "$TOK" GET /config/claim)"

added=0 skipped=0
n=0
while [ "$n" -lt "$count" ]; do
    claim="$(echo "$CLAIMS_JSON" | jq -c ".[$n]")"
    n=$((n + 1))
    t="$(echo "$claim" | jq -r .type)"
    v="$(echo "$claim" | jq -r .value)"
    r="$(echo "$claim" | jq -r .role)"
    present="$(echo "$EXISTING" | jq --arg t "$t" --arg v "$v" --arg r "$r" \
        'map(select(.type==$t and .value==$v and .role==$r)) | length' 2>/dev/null || echo 0)"
    if [ "${present:-0}" != "0" ]; then
        printf '   [skip] %s / %s\n' "$r" "$v"
        skipped=$((skipped + 1))
        continue
    fi
    printf '   [POST] %s / %s\n' "$r" "$v"
    resp="$(gw_curl "$TOK" POST /config/claim "$claim")"
    echo "$resp" | jq -e 'has("error") or has("Message")' >/dev/null 2>&1 \
        && echo "       ! failed: $resp" >&2
    added=$((added + 1))
done

echo "== done: $added added, $skipped already present =="
