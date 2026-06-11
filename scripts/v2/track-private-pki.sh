#!/usr/bin/env bash
# V2 private-pki-certificates/{orderId} — fetch current state of a Private PKI order.
# Required env var: ORDER_ID
#
# Status values: pending-csr -> issued (or cancelled / revoked).
# Private PKI orders skip vetting because the CA is customer-owned.
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"

ORDER_ID="${ORDER_ID:-}"

if [ -z "$ORDER_ID" ]; then
    echo "Usage: ORDER_ID=<orderId> scripts/v2/track-private-pki.sh" >&2
    exit 1
fi

echo "V2 GET /api/certinext/v2/private-pki-certificates/$ORDER_ID"
curl -s -X GET "$CERTINEXT_V2_API_URL/api/certinext/v2/private-pki-certificates/$ORDER_ID" \
     -H "Authorization: Bearer $CERTINEXT_V2_TOKEN" \
     -H "Accept: application/json" \
| jq .
