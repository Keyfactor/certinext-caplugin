#!/usr/bin/env bash
# Stage 04 — register the CA (gateway connector) in Keyfactor Command.
#
# Creates the Certificate Authority record that points Command at the gateway
# tenant, so templates can be imported (stage 05) and used for enrollment.
# Idempotent: looks up by LogicalName first and skips if it already exists.
#
# STATUS: UNVERIFIED — body modeled on docs/reference/command/certificate-authority.json.
# Command CA POST shapes are version-sensitive; validate against your Command.
#
# Env (in addition to the command-auth.sh contract):
#   CA_LOGICAL_NAME    default: $CONFIGURATION_TENANT
#   CA_HOSTNAME        gateway tenant URL Command connects to. Default derived:
#                      https://$GATEWAY_HOST$GATEWAY_BASE_PATH/ejbca
#   CA_BODY_JSON       override the entire request body (advanced)
#   FULL_SCAN_MINUTES  default 720;  INCR_SCAN_MINUTES default 5
#   DRY_RUN=1          print the body, make no write call
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
export REPO_ROOT

# shellcheck disable=SC1090
[ -f ~/.env_certinext ] && . ~/.env_certinext
# shellcheck source=../lib/command-auth.sh
. "$SCRIPT_DIR/../lib/command-auth.sh"

DRY_RUN="${DRY_RUN:-0}"
CA_LOGICAL_NAME="${CA_LOGICAL_NAME:-$CONFIGURATION_TENANT}"
CA_HOSTNAME="${CA_HOSTNAME:-${GATEWAY_HOST:+$(gw_base)/ejbca}}"
FULL_SCAN_MINUTES="${FULL_SCAN_MINUTES:-720}"
INCR_SCAN_MINUTES="${INCR_SCAN_MINUTES:-5}"

echo "== Stage 04: Command CA registration =="
echo "   command : $(cmd_show)"
echo "   logical : $CA_LOGICAL_NAME"
echo "   host    : ${CA_HOSTNAME:-(unset)}"

if [ -n "${CA_BODY_JSON:-}" ]; then
    BODY="$CA_BODY_JSON"
else
    BODY="$(jq -n \
        --arg logical "$CA_LOGICAL_NAME" \
        --arg tenant  "$CONFIGURATION_TENANT" \
        --arg host    "$CA_HOSTNAME" \
        --arg clientId "${OIDC_CLIENT_ID:-}" \
        --arg clientSecret "${OIDC_CLIENT_SECRET:-}" \
        --arg tokenUrl "${TOKEN_URL:-}" \
        --arg scope    "$GATEWAY_SCOPE" \
        --argjson full "$FULL_SCAN_MINUTES" \
        --argjson incr "$INCR_SCAN_MINUTES" \
        '{
          LogicalName: $logical,
          ConfigurationTenant: $tenant,
          ForestRoot: $tenant,
          HostName: $host,
          CAType: 1,
          ClientId: $clientId,
          ClientSecret: { SecretValue: $clientSecret },
          TokenURL: $tokenUrl,
          Scope: $scope,
          UseForEnrollment: true,
          UseCAConnector: false,
          KeyRetention: 1,
          AllowOneClickRenewals: true,
          AllowedEnrollmentTypes: 3,
          NewEndEntityOnRenewAndReissue: true,
          FullScan:        { Interval: { Minutes: $full } },
          IncrementalScan: { Interval: { Minutes: $incr } }
        }')"
fi

if [ "$DRY_RUN" = "1" ]; then
    echo "   (dry run) CA body (secret redacted):"
    echo "$BODY" | jq '(.ClientSecret.SecretValue) |= (if . then "***" else . end)'
    echo "== done (dry run): no calls made =="
    exit 0
fi

TOK="$(command_token)"

# Idempotency: skip if a CA with this LogicalName already exists.
EXISTING="$(cmd_curl "$TOK" GET /CertificateAuthority "" 1)"
present="$(echo "$EXISTING" | jq --arg n "$CA_LOGICAL_NAME" \
    'map(select(.LogicalName==$n)) | length' 2>/dev/null || echo 0)"
if [ "${present:-0}" != "0" ]; then
    echo "== CA '$CA_LOGICAL_NAME' already registered — skipping =="
    exit 0
fi

resp="$(cmd_curl "$TOK" POST /CertificateAuthority "$BODY" 1)"
echo "$resp" | jq -e 'has("Id")' >/dev/null 2>&1 \
    || { echo "   ! CA registration may have failed: $resp" >&2; exit 1; }
echo "== done: CA registered (Id=$(echo "$resp" | jq -r .Id)) =="
