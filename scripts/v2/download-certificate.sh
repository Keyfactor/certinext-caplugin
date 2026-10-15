#!/usr/bin/env bash
# V2 ssl-certificates/{orderId}/certificate — download issued SSL certificate. Read-only.
# Required env var: ORDER_ID
#
# Returns JSON with certificatePem, serialNumber, subject, issuer, notBefore, notAfter.
# Returns 422 if the order is not yet in issued state.
# Credentials: see scripts/v2/README.md.
set -euo pipefail
# shellcheck source=scripts/lib/certinext-v2-auth.sh
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"
v2_usage() { echo "Usage: ORDER_ID=<orderId> scripts/v2/download-certificate.sh" >&2; }
v2_parse_args "$@"

ORDER_ID="${ORDER_ID:-}"
v2_require_id ORDER_ID

echo "V2 GET /api/certinext/v2/ssl-certificates/$ORDER_ID/certificate" >&2
v2_request GET "/api/certinext/v2/ssl-certificates/$ORDER_ID/certificate"
