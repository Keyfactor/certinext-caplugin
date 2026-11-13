#!/usr/bin/env bash
# V2 catalog/products/{code}/custom-fields — mandatory + optional custom fields for a
# product. Read-only.
# Required env var: PRODUCT_CODE
# Credentials: see scripts/v2/README.md.
set -euo pipefail
# shellcheck source=scripts/lib/certinext-v2-auth.sh
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"
v2_usage() { echo "Usage: PRODUCT_CODE=<code> scripts/v2/get-custom-fields.sh" >&2; }
v2_parse_args "$@"

PRODUCT_CODE="${PRODUCT_CODE:-}"
v2_require_id PRODUCT_CODE

echo "V2 GET /api/certinext/v2/catalog/products/$PRODUCT_CODE/custom-fields" >&2
v2_request GET "/api/certinext/v2/catalog/products/$PRODUCT_CODE/custom-fields"
