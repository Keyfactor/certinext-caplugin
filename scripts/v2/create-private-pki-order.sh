#!/usr/bin/env bash
# V2 private-pki-certificates — PLACE a Private PKI certificate order. MUTATING.
# Refuses to run and prints the planned request unless --yes-mutate is passed.
# Required env vars: PRODUCT_CODE, CERT_HOSTNAME, CA_PROFILE_ID, MASTER_PRODUCT_ID
#   (CERT_HOSTNAME, not HOSTNAME: bash always sets HOSTNAME to the local machine name,
#    so the old HOSTNAME input silently ordered a certificate for this workstation.)
# Env-file keys: CERTINEXT_REQUESTOR_EMAIL (required), CERTINEXT_REQUESTOR_NAME,
#                CERTINEXT_REQUESTOR_MOBILE
#
# On success prints the orderId. Use it with track-private-pki, submit-csr-private-pki,
# download-certificate-private-pki, and revoke-private-pki.
# Credentials: see scripts/v2/README.md.
set -euo pipefail
# shellcheck source=scripts/lib/certinext-v2-auth.sh
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"
v2_usage() { echo "Usage: PRODUCT_CODE=<code> CERT_HOSTNAME=<host> CA_PROFILE_ID=<id> MASTER_PRODUCT_ID=<id> scripts/v2/create-private-pki-order.sh [--yes-mutate]" >&2; }
v2_parse_mutating_args "$@"

PRODUCT_CODE="${PRODUCT_CODE:-}"
CERT_HOSTNAME="${CERT_HOSTNAME:-}"
CA_PROFILE_ID="${CA_PROFILE_ID:-}"
MASTER_PRODUCT_ID="${MASTER_PRODUCT_ID:-}"
v2_require_var PRODUCT_CODE
v2_require_var CERT_HOSTNAME
v2_require_var CA_PROFILE_ID
v2_require_var MASTER_PRODUCT_ID

name=$(v2_cfg CERTINEXT_REQUESTOR_NAME "Keyfactor Gateway Test")
email=$(v2_require CERTINEXT_REQUESTOR_EMAIL)
phone=$(v2_cfg CERTINEXT_REQUESTOR_MOBILE "$(v2_cfg CERTINEXT_REQUESTOR_PHONE "+10000000000")")

body=$(jq -n \
    --arg caProfileId "$CA_PROFILE_ID" \
    --arg masterProductId "$MASTER_PRODUCT_ID" \
    --arg hostname "$CERT_HOSTNAME" \
    --arg name "$name" \
    --arg email "$email" \
    --arg phone "$phone" \
    '{variant:"intranet-ssl",
      caProfileId:$caProfileId,
      masterProductId:$masterProductId,
      hostname:$hostname,
      additionalHosts:[],
      emailNotifications:"all",
      subscription:{validityYears:1},
      requestor:{name:$name,email:$email,phone:$phone,designation:"IT Administrator"}}')

path="/api/certinext/v2/private-pki-certificates"
v2_mutation_gate POST "$path  (X-Product-Code: $PRODUCT_CODE)" "$body"

idempotency_key=$(v2_uuid)
echo "V2 POST $path  productCode=$PRODUCT_CODE  hostname=$CERT_HOSTNAME  caProfileId=$CA_PROFILE_ID  masterProductId=$MASTER_PRODUCT_ID  idempotencyKey=$idempotency_key" >&2
rc=0
result=$(v2_request POST "$path" \
    -H "Content-Type: application/json" \
    -H "X-Product-Code: $PRODUCT_CODE" \
    -H "Idempotency-Key: $idempotency_key" \
    --data-binary "$body") || rc=$?

echo "==> Full response:"
printf '%s\n' "$result"
echo "==> orderId (use with track-private-pki, submit-csr-private-pki, etc.):"
printf '%s' "$result" | jq -r '.orderId // .detail // .title // "none"' 2>/dev/null || echo "none"
exit "$rc"
