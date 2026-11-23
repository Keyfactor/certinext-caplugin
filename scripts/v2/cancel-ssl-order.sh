#!/usr/bin/env bash
# V2 ssl-certificates/{orderId}/cancel — CANCEL an SSL order before issuance. MUTATING.
# Refuses to run and prints the planned request unless --yes-mutate is passed.
# Required env var: ORDER_ID
#
# Once issued, use revoke-ssl.sh instead.
# 204 No Content = cancelled; order remains visible via track-order with status=cancelled.
# Credentials: see scripts/v2/README.md.
set -euo pipefail
# shellcheck source=scripts/lib/certinext-v2-auth.sh
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"
v2_usage() { echo "Usage: ORDER_ID=<orderId> scripts/v2/cancel-ssl-order.sh [--yes-mutate]" >&2; }
v2_parse_mutating_args "$@"

ORDER_ID="${ORDER_ID:-}"
v2_require_id ORDER_ID

path="/api/certinext/v2/ssl-certificates/$ORDER_ID/cancel"
body='{"reason":"No longer required"}'
v2_mutation_gate POST "$path" "$body"

echo "V2 POST $path" >&2
v2_request POST "$path" -H "Content-Type: application/json" --data-binary "$body"
