#!/usr/bin/env bash
# V2 ssl-certificates/{orderId}/certificate — download issued SSL certificate.
# Required env var: ORDER_ID
#
# Returns JSON with certificatePem, serialNumber, subject, issuer, notBefore, notAfter.
# Returns 422 if the order is not yet in issued state.
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"

ORDER_ID="${ORDER_ID:-}"

if [ -z "$ORDER_ID" ]; then
    echo "Usage: ORDER_ID=<orderId> scripts/v2/download-certificate.sh" >&2
    exit 1
fi

echo "V2 GET /api/certinext/v2/ssl-certificates/$ORDER_ID/certificate"
curl -s -X GET "$CERTINEXT_V2_API_URL/api/certinext/v2/ssl-certificates/$ORDER_ID/certificate" \
     -H "Authorization: Bearer $CERTINEXT_V2_TOKEN" \
     -H "Accept: application/json" \
| jq .
