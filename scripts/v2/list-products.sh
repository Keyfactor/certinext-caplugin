#!/usr/bin/env bash
# V2 catalog/products — list all products the account can order.
# Each entry has a stable productCode used in the X-Product-Code header.
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"

echo "V2 GET /api/certinext/v2/catalog/products"
curl -s -X GET "$CERTINEXT_V2_API_URL/api/certinext/v2/catalog/products" \
     -H "Authorization: Bearer $CERTINEXT_V2_TOKEN" \
     -H "Accept: application/json" \
| jq .
