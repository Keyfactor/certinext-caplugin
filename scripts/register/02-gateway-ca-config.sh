#!/usr/bin/env bash
# Stage 02 — register the gateway CA configuration (CAConnection + Templates).
#
# PUTs /config/configuration on the AnyCA REST Gateway: the CERTInext plugin
# connection settings plus the Templates[] array mapping each product_id to its
# certificate profile (created in stage 01) and per-template enrollment params.
#
# STATUS: UNVERIFIED — body shapes built from kfc-in-a-box init-anygateway.sh
# and docs/reference/command/certificate-authority.json. Validate against a live
# gateway before relying on it.
#
# Env (in addition to the command-auth.sh contract):
#   GATEWAY_LOGICAL_NAME   CA name registered in Command (default: $CONFIGURATION_TENANT)
#   GATEWAY_CERT_FILE      PEM chain for GatewayRegistration (default: certinext-sandbox-chain.pem)
#   CA_CONNECTION_JSON     override the entire CAConnection object (advanced)
#   TEMPLATE_PARAMS_JSON   default per-template Parameters object (default: {})
#   FULL_SCAN_MINUTES      default 720;  INCR_SCAN_MINUTES default 5
#   DRY_RUN=1              print the body, make no write call
#
# CAConnection is assembled from the CERTINEXT_* env vars (same values the
# integration tests use), keyed by the plugin's ca_plugin_config field names.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
export REPO_ROOT

# shellcheck disable=SC1090
[ -f ~/.env_certinext ] && . ~/.env_certinext
# shellcheck source=../lib/command-auth.sh
. "$SCRIPT_DIR/../lib/command-auth.sh"

MANIFEST="${MANIFEST:-$REPO_ROOT/integration-manifest.json}"
DRY_RUN="${DRY_RUN:-0}"
GATEWAY_LOGICAL_NAME="${GATEWAY_LOGICAL_NAME:-$CONFIGURATION_TENANT}"
GATEWAY_CERT_FILE="${GATEWAY_CERT_FILE:-$REPO_ROOT/certinext-sandbox-chain.pem}"
TEMPLATE_PARAMS_JSON="${TEMPLATE_PARAMS_JSON:-{}}"
FULL_SCAN_MINUTES="${FULL_SCAN_MINUTES:-720}"
INCR_SCAN_MINUTES="${INCR_SCAN_MINUTES:-5}"

echo "== Stage 02: gateway CA configuration =="
echo "   gateway : $(gw_show)"
echo "   logical : $GATEWAY_LOGICAL_NAME"

# --- CAConnection (CERTInext plugin settings) -------------------------------
if [ -n "${CA_CONNECTION_JSON:-}" ]; then
    CA_CONNECTION="$CA_CONNECTION_JSON"
else
    CA_CONNECTION="$(jq -n \
        --arg apiUrl     "${CERTINEXT_API_URL:-}" \
        --arg account    "${CERTINEXT_ACCOUNT_NUMBER:-}" \
        --arg group      "${CERTINEXT_GROUP_NUMBER:-}" \
        --arg org        "${CERTINEXT_ORG_NUMBER:-}" \
        --arg authMode   "${CERTINEXT_AUTH_MODE:-AccessKey}" \
        --arg apiKey     "${CERTINEXT_ACCESS_KEY:-}" \
        --arg reqName    "${CERTINEXT_REQUESTOR_NAME:-}" \
        --arg reqEmail   "${CERTINEXT_REQUESTOR_EMAIL:-}" \
        --arg reqIsd     "${CERTINEXT_REQUESTOR_ISD_CODE:-1}" \
        --arg reqMobile  "${CERTINEXT_REQUESTOR_MOBILE:-}" \
        --arg signerPlace "${CERTINEXT_SIGNER_PLACE:-}" \
        --arg signerIp    "${CERTINEXT_SIGNER_IP:-}" \
        '{
          ApiUrl: $apiUrl,
          AccountNumber: $account,
          GroupNumber: $group,
          OrganizationNumber: $org,
          AuthMode: $authMode,
          ApiKey: $apiKey,
          RequestorName: $reqName,
          RequestorEmail: $reqEmail,
          RequestorIsdCode: $reqIsd,
          RequestorMobileNumber: $reqMobile,
          SignerPlace: $signerPlace,
          SignerIp: $signerIp,
          Enabled: true
        } | with_entries(select(.value != ""))')"
fi

# --- GatewayRegistration cert ------------------------------------------------
GATEWAY_CERT_BLOCK='{}'
if [ -f "$GATEWAY_CERT_FILE" ]; then
    pem="$(cat "$GATEWAY_CERT_FILE")"
    GATEWAY_CERT_BLOCK="$(jq -n --arg pem "$pem" \
        '{Source: "FileUpload", ImportedCertificate: $pem}')"
else
    echo "   warn: GATEWAY_CERT_FILE not found ($GATEWAY_CERT_FILE) — sending empty cert block" >&2
fi

# --- Templates[] (one per product_id) ---------------------------------------
TEMPLATES="$(manifest_product_ids "$MANIFEST" | jq -R . | jq -s \
    --argjson params "$TEMPLATE_PARAMS_JSON" \
    '[.[] | {ProductID: ., CertificateProfile: ., Parameters: $params}]')"

# --- Assemble configuration body --------------------------------------------
BODY="$(jq -n \
    --argjson caconn "$CA_CONNECTION" \
    --arg logical "$GATEWAY_LOGICAL_NAME" \
    --argjson cert "$GATEWAY_CERT_BLOCK" \
    --argjson full "$FULL_SCAN_MINUTES" \
    --argjson incr "$INCR_SCAN_MINUTES" \
    --argjson templates "$TEMPLATES" \
    '{
      CAConnection: $caconn,
      GatewayRegistration: { LogicalName: $logical, GatewayCertificate: $cert },
      ServiceSettings: {
        FullScan:        { Interval: { Minutes: $full } },
        IncrementalScan: { Interval: { Minutes: $incr } }
      },
      Templates: $templates
    }')"

if [ "$DRY_RUN" = "1" ]; then
    echo "   (dry run) configuration body (ApiKey redacted):"
    echo "$BODY" | jq '(.CAConnection.ApiKey) |= (if . then "***" else . end)'
    echo "== done (dry run): no calls made =="
    exit 0
fi

TOK="$(gateway_token)"
resp="$(gw_curl "$TOK" PUT /config/configuration "$BODY")"
echo "$resp" | jq -e 'has("error") or has("Message")' >/dev/null 2>&1 \
    && { echo "   ! configuration PUT failed: $resp" >&2; exit 1; }
echo "== done: configuration applied for $GATEWAY_LOGICAL_NAME =="
