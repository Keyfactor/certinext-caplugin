#!/usr/bin/env bash
# V2 groups — list billing groups accessible to this account.
# Use a groupNumber from here in order bodies to charge a specific cost centre.
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"

echo "V2 GET /api/certinext/v2/groups"
curl -s -X GET "$CERTINEXT_V2_API_URL/api/certinext/v2/groups" \
     -H "Authorization: Bearer $CERTINEXT_V2_TOKEN" \
     -H "Accept: application/json" \
| jq .
