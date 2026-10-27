#!/usr/bin/env bash
# V2 reports/orders — paginated order history.
# NOTE: currently returns 501 Not Implemented.
# Use v1 make get-order-report (POST /emSignHub-API/GetOrderReport) meanwhile.
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"

echo "V2 GET /api/certinext/v2/reports/orders?page=0&size=50"
echo "NOTE: this endpoint currently returns 501 Not Implemented — use v1 make get-order-report as a fallback."
curl -s -X GET "$CERTINEXT_V2_API_URL/api/certinext/v2/reports/orders?page=0&size=50" \
     -H "Authorization: Bearer $CERTINEXT_V2_TOKEN" \
     -H "Accept: application/json" \
| jq .
