#!/usr/bin/env bash
# V2 ssl-certificates/{orderId}/dcv/verify — ask the CA to re-check a DCV artifact.
# Required env vars: ORDER_ID, DOMAIN
# Optional env var:  METHOD (default http-url; also: dns-txt, email)
#
# 204 No Content = DCV passed; order advances to pending-csr.
# 422 = CA could not find the artifact; check file path or DNS propagation.
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"

ORDER_ID="${ORDER_ID:-}"
DOMAIN="${DOMAIN:-}"
METHOD="${METHOD:-http-url}"

if [ -z "$ORDER_ID" ] || [ -z "$DOMAIN" ]; then
    echo "Usage: ORDER_ID=<orderId> DOMAIN=<domain> [METHOD=http-url] scripts/v2/verify-dcv.sh" >&2
    exit 1
fi

echo "V2 POST /api/certinext/v2/ssl-certificates/$ORDER_ID/dcv/verify  domain=$DOMAIN  method=$METHOD"
curl -s -X POST "$CERTINEXT_V2_API_URL/api/certinext/v2/ssl-certificates/$ORDER_ID/dcv/verify" \
     -H "Authorization: Bearer $CERTINEXT_V2_TOKEN" \
     -H "Content-Type: application/json" \
     -d "$(jq -n --arg domain "$DOMAIN" --arg method "$METHOD" '{domain:$domain,method:$method}')" \
| jq .
