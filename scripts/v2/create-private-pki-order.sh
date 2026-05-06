#!/usr/bin/env bash
# V2 private-pki-certificates — create a Private PKI certificate order.
# Required env vars: PRODUCT_CODE, HOSTNAME, CA_PROFILE_ID, MASTER_PRODUCT_ID
#
# On success prints the orderId prominently.
# Use orderId with v2-track-private-pki, v2-submit-csr-private-pki,
# v2-download-certificate-private-pki, and v2-revoke-private-pki.
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"

PRODUCT_CODE="${PRODUCT_CODE:-}"
HOSTNAME="${HOSTNAME:-}"
CA_PROFILE_ID="${CA_PROFILE_ID:-}"
MASTER_PRODUCT_ID="${MASTER_PRODUCT_ID:-}"

if [ -z "$PRODUCT_CODE" ] || [ -z "$HOSTNAME" ] || [ -z "$CA_PROFILE_ID" ] || [ -z "$MASTER_PRODUCT_ID" ]; then
    echo "Usage: PRODUCT_CODE=<code> HOSTNAME=<host> CA_PROFILE_ID=<id> MASTER_PRODUCT_ID=<id> scripts/v2/create-private-pki-order.sh" >&2
    exit 1
fi

idempotency_key=$(python3 -c "import uuid; print(uuid.uuid4())")

name="${CERTINEXT_REQUESTOR_NAME:-Keyfactor Gateway Test}"
email="${CERTINEXT_REQUESTOR_EMAIL}"
phone="${CERTINEXT_REQUESTOR_PHONE:-+10000000000}"

echo "V2 POST /api/certinext/v2/private-pki-certificates  productCode=$PRODUCT_CODE  hostname=$HOSTNAME  caProfileId=$CA_PROFILE_ID  masterProductId=$MASTER_PRODUCT_ID  idempotencyKey=$idempotency_key"

result=$(jq -n \
    --arg caProfileId "$CA_PROFILE_ID" \
    --arg masterProductId "$MASTER_PRODUCT_ID" \
    --arg hostname "$HOSTNAME" \
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
      requestor:{name:$name,email:$email,phone:$phone,designation:"IT Administrator"}}' \
    | curl -s -X POST "$CERTINEXT_V2_API_URL/api/certinext/v2/private-pki-certificates" \
           -H "Authorization: Bearer $CERTINEXT_V2_TOKEN" \
           -H "Content-Type: application/json" \
           -H "X-Product-Code: $PRODUCT_CODE" \
           -H "Idempotency-Key: $idempotency_key" \
           -d @-)

echo ""
echo "==> Full response:"
echo "$result" | jq .
echo ""
echo "==> orderId (use with v2-track-private-pki, v2-submit-csr-private-pki, etc.):"
echo "$result" | jq -r '.orderId // .detail // .title // "none"'
