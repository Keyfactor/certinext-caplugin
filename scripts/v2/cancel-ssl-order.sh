#!/usr/bin/env bash
# V2 ssl-certificates/{orderId}/cancel — withdraw an SSL order before issuance.
# Required env var: ORDER_ID
#
# Use this before the certificate is issued.
# Once issued, use v2-revoke-ssl instead.
# 204 No Content = cancelled; order remains visible via v2-track-order with status=cancelled.
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"

ORDER_ID="${ORDER_ID:-}"

if [ -z "$ORDER_ID" ]; then
    echo "Usage: ORDER_ID=<orderId> scripts/v2/cancel-ssl-order.sh" >&2
    exit 1
fi

echo "V2 POST /api/certinext/v2/ssl-certificates/$ORDER_ID/cancel"
curl -s -X POST "$CERTINEXT_V2_API_URL/api/certinext/v2/ssl-certificates/$ORDER_ID/cancel" \
     -H "Authorization: Bearer $CERTINEXT_V2_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"reason":"No longer required"}' \
| jq .
