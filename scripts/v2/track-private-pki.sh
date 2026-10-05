#!/usr/bin/env bash
# V2 private-pki-certificates/{orderId} — fetch current state of a Private PKI order.
# Read-only.
# Required env var: ORDER_ID
#
# Status values: pending-csr -> issued (or cancelled / revoked).
# Private PKI orders skip vetting because the CA is customer-owned.
# Credentials: see scripts/v2/README.md.
set -euo pipefail
# shellcheck source=scripts/lib/certinext-v2-auth.sh
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"
v2_usage() { echo "Usage: ORDER_ID=<orderId> scripts/v2/track-private-pki.sh" >&2; }
v2_parse_args "$@"

ORDER_ID="${ORDER_ID:-}"
v2_require_id ORDER_ID

echo "V2 GET /api/certinext/v2/private-pki-certificates/$ORDER_ID" >&2
v2_request GET "/api/certinext/v2/private-pki-certificates/$ORDER_ID"
