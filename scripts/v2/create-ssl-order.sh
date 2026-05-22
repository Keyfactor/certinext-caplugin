#!/usr/bin/env bash
# V2 ssl-certificates — create a new SSL/TLS certificate order.
# Required env vars: PRODUCT_CODE, DOMAIN
# Optional env vars: VARIANT (default dv)
#
# On success prints the orderId prominently.
# Use orderId with v2-get-dcv, v2-verify-dcv, v2-submit-csr, v2-accept-agreement,
# v2-download-certificate, v2-revoke-ssl, and v2-cancel-ssl-order.
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"

PRODUCT_CODE="${PRODUCT_CODE:-}"
DOMAIN="${DOMAIN:-}"
VARIANT="${VARIANT:-dv}"

if [ -z "$PRODUCT_CODE" ] || [ -z "$DOMAIN" ]; then
    echo "Usage: PRODUCT_CODE=<code> DOMAIN=<domain> [VARIANT=dv] scripts/v2/create-ssl-order.sh" >&2
    exit 1
fi

idempotency_key=$(python3 -c "import uuid; print(uuid.uuid4())")

name="${CERTINEXT_REQUESTOR_NAME:-Keyfactor Gateway Test}"
email="${CERTINEXT_REQUESTOR_EMAIL}"
phone="${CERTINEXT_REQUESTOR_PHONE:-+10000000000}"

signerIp="${CERTINEXT_SIGNER_IP:-}"
if [ -z "$signerIp" ]; then signerIp=$(curl -s https://api.ipify.org); fi

echo "V2 POST /api/certinext/v2/ssl-certificates  productCode=$PRODUCT_CODE  domain=$DOMAIN  variant=$VARIANT  idempotencyKey=$idempotency_key"

result=$(jq -n \
    --arg variant "$VARIANT" \
    --arg domain "$DOMAIN" \
    --arg name "$name" \
    --arg email "$email" \
    --arg phone "$phone" \
    --arg signerIp "$signerIp" \
    '{productVariant:$variant,
      emailNotifications:"all",
      requestor:{name:$name,email:$email,phone:$phone,designation:"IT Administrator"},
      certificate:{domain:$domain,autoSecureWww:true},
      subscription:{validityYears:1,autoRenew:false,renewBeforeDays:30},
      agreement:{signerName:$name,signerIp:$signerIp,signerPlace:"Gateway",accepted:true},
      remarks:"Issued via Keyfactor Command AnyCA REST Gateway."}' \
    | curl -s -X POST "$CERTINEXT_V2_API_URL/api/certinext/v2/ssl-certificates" \
           -H "Authorization: Bearer $CERTINEXT_V2_TOKEN" \
           -H "Content-Type: application/json" \
           -H "X-Product-Code: $PRODUCT_CODE" \
           -H "Idempotency-Key: $idempotency_key" \
           -d @-)

echo ""
echo "==> Full response:"
echo "$result" | jq .
echo ""
echo "==> orderId (use with v2-track-order, v2-get-dcv, etc.):"
echo "$result" | jq -r '.orderId // .detail // .title // "none"'
