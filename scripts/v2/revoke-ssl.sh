#!/usr/bin/env bash
# V2 ssl-certificates/{orderId}/revoke — permanently revoke an issued SSL certificate.
# Required env var: ORDER_ID
# Optional env var: REASON (default superseded)
#
# RFC 5280 reason values: unspecified, keyCompromise, caCompromise, affiliationChanged,
#   superseded, cessationOfOperation, privilegeWithdrawn
#
# 204 No Content = revocation queued; CRL/OCSP reflect this on next publish.
# 422 = order not yet issued, or already revoked.
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"

ORDER_ID="${ORDER_ID:-}"
REASON="${REASON:-superseded}"

if [ -z "$ORDER_ID" ]; then
    echo "Usage: ORDER_ID=<orderId> [REASON=superseded] scripts/v2/revoke-ssl.sh" >&2
    exit 1
fi

idempotency_key=$(python3 -c "import uuid; print(uuid.uuid4())")

echo "V2 POST /api/certinext/v2/ssl-certificates/$ORDER_ID/revoke  reason=$REASON  idempotencyKey=$idempotency_key"
curl -s -X POST "$CERTINEXT_V2_API_URL/api/certinext/v2/ssl-certificates/$ORDER_ID/revoke" \
     -H "Authorization: Bearer $CERTINEXT_V2_TOKEN" \
     -H "Content-Type: application/json" \
     -H "Idempotency-Key: $idempotency_key" \
     -d "$(jq -n --arg reason "$REASON" '{reason:$reason,note:"Revoked via Makefile smoke test."}')" \
| jq .
