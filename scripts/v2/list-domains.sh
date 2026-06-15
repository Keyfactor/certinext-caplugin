#!/usr/bin/env bash
# V2 domains — list domains already pre-validated under this account.
# DCV does not need to be repeated for domains in this list.
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"

echo "V2 GET /api/certinext/v2/domains"
curl -s -X GET "$CERTINEXT_V2_API_URL/api/certinext/v2/domains" \
     -H "Authorization: Bearer $CERTINEXT_V2_TOKEN" \
     -H "Accept: application/json" \
| jq .
