#!/usr/bin/env bash
# V2 ssl-certificates/{orderId}/dcv — get DCV challenge artifacts for a domain.
# Required env vars: ORDER_ID, DOMAIN
#
# Returns http-url, dns-txt, and email challenge methods.
# Publish the artifact for your chosen method, then call v2-verify-dcv.
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"

ORDER_ID="${ORDER_ID:-}"
DOMAIN="${DOMAIN:-}"

if [ -z "$ORDER_ID" ] || [ -z "$DOMAIN" ]; then
    echo "Usage: ORDER_ID=<orderId> DOMAIN=<domain> scripts/v2/get-dcv.sh" >&2
    exit 1
fi

echo "V2 GET /api/certinext/v2/ssl-certificates/$ORDER_ID/dcv?domain=$DOMAIN"
curl -s -X GET "$CERTINEXT_V2_API_URL/api/certinext/v2/ssl-certificates/$ORDER_ID/dcv?domain=$DOMAIN" \
     -H "Authorization: Bearer $CERTINEXT_V2_TOKEN" \
     -H "Accept: application/json" \
| jq .
