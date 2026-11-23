#!/usr/bin/env bash
# V2 ssl-certificates/{orderId}/dcv — get DCV challenge artifacts for a domain. Read-only.
# Required env vars: ORDER_ID, DOMAIN
#
# Returns http-url, dns-txt, and email challenge methods.
# Publish the artifact for your chosen method, then run verify-dcv.sh --yes-mutate.
# Credentials: see scripts/v2/README.md.
set -euo pipefail
# shellcheck source=scripts/lib/certinext-v2-auth.sh
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"
v2_usage() { echo "Usage: ORDER_ID=<orderId> DOMAIN=<domain> scripts/v2/get-dcv.sh" >&2; }
v2_parse_args "$@"

ORDER_ID="${ORDER_ID:-}"
DOMAIN="${DOMAIN:-}"
v2_require_id ORDER_ID
v2_require_var DOMAIN

echo "V2 GET /api/certinext/v2/ssl-certificates/$ORDER_ID/dcv?domain=$DOMAIN" >&2
v2_request GET "/api/certinext/v2/ssl-certificates/$ORDER_ID/dcv" \
    -G --data-urlencode "domain=$DOMAIN"
