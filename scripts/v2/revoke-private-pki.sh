#!/usr/bin/env bash
# V2 private-pki-certificates/{orderId}/revoke — permanently REVOKE an issued Private PKI
# certificate. MUTATING and irreversible. Refuses to run and prints the planned request
# unless --yes-mutate is passed.
# Required env var: ORDER_ID
# Optional env var: REASON (default superseded)
#
# RFC 5280 reason values: unspecified, keyCompromise, affiliationChanged,
#   superseded, cessationOfOperation, privilegeWithdrawn
#
# 204 No Content = revocation recorded on the customer CA.
# 422 = order not yet issued, or already revoked.
# Credentials: see scripts/v2/README.md.
set -euo pipefail
# shellcheck source=scripts/lib/certinext-v2-auth.sh
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"
v2_usage() { echo "Usage: ORDER_ID=<orderId> [REASON=superseded] scripts/v2/revoke-private-pki.sh [--yes-mutate]" >&2; }
v2_parse_mutating_args "$@"

ORDER_ID="${ORDER_ID:-}"
REASON="${REASON:-superseded}"
v2_require_id ORDER_ID

path="/api/certinext/v2/private-pki-certificates/$ORDER_ID/revoke"
body=$(jq -n --arg reason "$REASON" '{reason:$reason,note:"Revoked via scripts/v2 dev helper."}')
v2_mutation_gate POST "$path" "$body"

idempotency_key=$(v2_uuid)
echo "V2 POST $path  reason=$REASON  idempotencyKey=$idempotency_key" >&2
v2_request POST "$path" \
    -H "Content-Type: application/json" \
    -H "Idempotency-Key: $idempotency_key" \
    --data-binary "$body"
