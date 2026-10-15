#!/usr/bin/env bash
# V2 catalog/products — list all products the account can order. Read-only.
# Each entry has a stable productCode used in the X-Product-Code header.
# Credentials: see scripts/v2/README.md.
set -euo pipefail
# shellcheck source=scripts/lib/certinext-v2-auth.sh
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"
v2_usage() { echo "Usage: scripts/v2/list-products.sh" >&2; }
v2_parse_args "$@"

echo "V2 GET /api/certinext/v2/catalog/products" >&2
v2_request GET "/api/certinext/v2/catalog/products"
