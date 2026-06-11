#!/usr/bin/env bash
# Cancel/reject a PENDING CERTInext order (pre-issuance) by order number.
#
# Unlike RevokeOrder (which targets issued certs), RejectOrder cancels an order that
# has not yet been issued — e.g. one parked at EXTERNALVALIDATION awaiting DCV. Whether
# this refunds the consumed credit is a CERTInext billing-policy question; run it on one
# order and check GetProductDetails / your credit balance before/after to confirm.
#
# Required env var: ORDER_NUMBER
# Optional env var: REMARKS (default "Cancelled pending order to reclaim sandbox credits.")
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/lib/certinext-auth.sh"

if [ -z "${ORDER_NUMBER:-}" ]; then
    echo "Usage: ORDER_NUMBER=<order number> [REMARKS=...] scripts/reject-order.sh" >&2
    exit 1
fi

REMARKS="${REMARKS:-Cancelled pending order to reclaim sandbox credits.}"

read -r ts txn authKey <<< "$(certinext_meta)"
echo "RejectOrder  orderNumber=$ORDER_NUMBER  ts=$ts  txn=$txn"
curl -s -X POST "$CERTINEXT_API_URL/RejectOrder" \
     -H "Content-Type: application/json" \
     -d "{\"meta\":{\"ver\":\"1.0\",\"ts\":\"$ts\",\"txn\":\"$txn\",\"accountNumber\":\"$CERTINEXT_ACCOUNT_NUMBER\",\"authKey\":\"$authKey\"},\"orderDetails\":{\"orderNumber\":\"$ORDER_NUMBER\",\"rejectRemarks\":\"$REMARKS\"}}" \
| jq .
