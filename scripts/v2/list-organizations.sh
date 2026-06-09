#!/usr/bin/env bash
# V2 organizations — list pre-vetted organizations available for OV/EV SSL.
# Reference an organizationNumber in order bodies to skip re-vetting.
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"

echo "V2 GET /api/certinext/v2/organizations"
curl -s -X GET "$CERTINEXT_V2_API_URL/api/certinext/v2/organizations" \
     -H "Authorization: Bearer $CERTINEXT_V2_TOKEN" \
     -H "Accept: application/json" \
| jq .
