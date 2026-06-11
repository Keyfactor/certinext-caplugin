#!/usr/bin/env bash
# V2 catalog/products/{code}/custom-fields — mandatory + optional custom fields for a product.
# Required env var: PRODUCT_CODE
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"

PRODUCT_CODE="${PRODUCT_CODE:-}"

if [ -z "$PRODUCT_CODE" ]; then
    echo "Usage: PRODUCT_CODE=<code> scripts/v2/get-custom-fields.sh" >&2
    exit 1
fi

echo "V2 GET /api/certinext/v2/catalog/products/$PRODUCT_CODE/custom-fields"
curl -s -X GET "$CERTINEXT_V2_API_URL/api/certinext/v2/catalog/products/$PRODUCT_CODE/custom-fields" \
     -H "Authorization: Bearer $CERTINEXT_V2_TOKEN" \
     -H "Accept: application/json" \
| jq .
