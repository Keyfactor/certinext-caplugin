#!/usr/bin/env bash
# V2 ssl-certificates/{orderId} — fetch current state of an SSL order. Read-only.
# Required env var: ORDER_ID
#
# Status values: pending-dcv -> pending-csr -> pending-agreement -> issued
#                (or cancelled / revoked)
# Credentials: see scripts/v2/README.md.
set -euo pipefail
# shellcheck source=scripts/lib/certinext-v2-auth.sh
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"
v2_usage() { echo "Usage: ORDER_ID=<orderId> scripts/v2/track-order.sh" >&2; }
v2_parse_args "$@"

ORDER_ID="${ORDER_ID:-}"
v2_require_id ORDER_ID

echo "V2 GET /api/certinext/v2/ssl-certificates/$ORDER_ID" >&2
v2_request GET "/api/certinext/v2/ssl-certificates/$ORDER_ID"
