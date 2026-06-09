#!/usr/bin/env bash
# Required env var: ORDER_NUMBER
# Optional env var: REASON_ID (default 1 = KeyCompromise)
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/lib/certinext-auth.sh"

if [ -z "${ORDER_NUMBER:-}" ]; then
    echo "Usage: ORDER_NUMBER=<order number> [REASON_ID=1] scripts/revoke-order.sh" >&2
    exit 1
fi

REASON_ID="${REASON_ID:-1}"

read -r ts txn authKey <<< "$(certinext_meta)"
echo "RevokeOrder  orderNumber=$ORDER_NUMBER  revokeReasonId=$REASON_ID  ts=$ts  txn=$txn"
curl -s -X POST "$CERTINEXT_API_URL/RevokeOrder" \
     -H "Content-Type: application/json" \
     -d "{\"meta\":{\"ver\":\"1.0\",\"ts\":\"$ts\",\"txn\":\"$txn\",\"accountNumber\":\"$CERTINEXT_ACCOUNT_NUMBER\",\"authKey\":\"$authKey\"},\"revocationDetails\":{\"orderNumber\":\"$ORDER_NUMBER\",\"requestorEmail\":\"$CERTINEXT_REQUESTOR_EMAIL\",\"revokeReasonId\":\"$REASON_ID\",\"revokeRemarks\":\"Revoked via Makefile smoke test.\"}}" \
| jq .
