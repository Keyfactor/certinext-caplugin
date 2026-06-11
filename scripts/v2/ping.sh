#!/usr/bin/env bash
# V2 auth/me — returns the account context the Bearer token resolves to.
# Mirrors ICERTInextClient.PingAsync via the V2 API.
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"

echo "V2 GET /api/certinext/v2/auth/me"
curl -s -X GET "$CERTINEXT_V2_API_URL/api/certinext/v2/auth/me" \
     -H "Authorization: Bearer $CERTINEXT_V2_TOKEN" \
     -H "Accept: application/json" \
| jq .
