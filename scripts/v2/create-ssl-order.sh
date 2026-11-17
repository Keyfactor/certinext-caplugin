#!/usr/bin/env bash
# V2 ssl-certificates — PLACE a new SSL/TLS certificate order. MUTATING (may incur cost).
# Refuses to run and prints the planned request unless --yes-mutate is passed.
# Required env vars: PRODUCT_CODE, DOMAIN
# Optional env vars: VARIANT (default dv)
# Env-file keys: CERTINEXT_REQUESTOR_EMAIL (required), CERTINEXT_REQUESTOR_NAME,
#                CERTINEXT_REQUESTOR_MOBILE, CERTINEXT_SIGNER_IP (else api.ipify.org lookup)
#
# On success prints the orderId. Use it with track-order, get-dcv, verify-dcv,
# submit-csr, accept-agreement, download-certificate, revoke-ssl, cancel-ssl-order.
# Credentials: see scripts/v2/README.md.
set -euo pipefail
# shellcheck source=scripts/lib/certinext-v2-auth.sh
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"
v2_usage() { echo "Usage: PRODUCT_CODE=<code> DOMAIN=<domain> [VARIANT=dv] scripts/v2/create-ssl-order.sh [--yes-mutate]" >&2; }
v2_parse_mutating_args "$@"

PRODUCT_CODE="${PRODUCT_CODE:-}"
DOMAIN="${DOMAIN:-}"
VARIANT="${VARIANT:-dv}"
v2_require_var PRODUCT_CODE
v2_require_var DOMAIN

name=$(v2_cfg CERTINEXT_REQUESTOR_NAME "Keyfactor Gateway Test")
email=$(v2_require CERTINEXT_REQUESTOR_EMAIL)
phone=$(v2_cfg CERTINEXT_REQUESTOR_MOBILE "$(v2_cfg CERTINEXT_REQUESTOR_PHONE "+10000000000")")

build_body() {
    jq -n \
        --arg variant "$VARIANT" \
        --arg domain "$DOMAIN" \
        --arg name "$name" \
        --arg email "$email" \
        --arg phone "$phone" \
        --arg signerIp "$1" \
        '{productVariant:$variant,
          emailNotifications:"all",
          requestor:{name:$name,email:$email,phone:$phone,designation:"IT Administrator"},
          certificate:{domain:$domain,autoSecureWww:true},
          subscription:{validityYears:1,autoRenew:false,renewBeforeDays:30},
          agreement:{signerName:$name,signerIp:$signerIp,signerPlace:"Gateway",accepted:true},
          remarks:"Issued via Keyfactor Command AnyCA REST Gateway."}'
}

path="/api/certinext/v2/ssl-certificates"
v2_mutation_gate POST "$path  (X-Product-Code: $PRODUCT_CODE)" "$(build_body "$(v2_signer_ip --offline)")"

body=$(build_body "$(v2_signer_ip)")
idempotency_key=$(v2_uuid)

echo "V2 POST $path  productCode=$PRODUCT_CODE  domain=$DOMAIN  variant=$VARIANT  idempotencyKey=$idempotency_key" >&2
rc=0
result=$(v2_request POST "$path" \
    -H "Content-Type: application/json" \
    -H "X-Product-Code: $PRODUCT_CODE" \
    -H "Idempotency-Key: $idempotency_key" \
    --data-binary "$body") || rc=$?

echo "==> Full response:"
printf '%s\n' "$result"
echo "==> orderId (use with track-order, get-dcv, etc.):"
printf '%s' "$result" | jq -r '.orderId // .detail // .title // "none"' 2>/dev/null || echo "none"
exit "$rc"
