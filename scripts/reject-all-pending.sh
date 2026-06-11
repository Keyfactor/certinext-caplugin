#!/usr/bin/env bash
# Reject ALL pending (pre-issuance) CERTInext orders — to reclaim credits / declutter the
# sandbox. Targets certificateStatusId in {2,24} ("Pending for Approver"). NEVER touches
# issued certs (9 "Certificate Downloaded") or already-rejected orders (13).
#
# Safety: dry-run by default (lists what it WOULD reject). Set REJECT_ALL_PENDING=1 to fire.
# Optional: PAGE_SIZE (default 100), REMARKS.
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/lib/certinext-auth.sh"

DRY=1; [ "${REJECT_ALL_PENDING:-}" = "1" ] && DRY=0
PAGE_SIZE="${PAGE_SIZE:-100}"
REMARKS="${REMARKS:-Cancelled pending order to reclaim sandbox credits.}"

report_page() {  # $1 = page number
    read -r ts txn authKey <<< "$(certinext_meta)"
    curl -s -X POST "$CERTINEXT_API_URL/GetOrderReport" -H "Content-Type: application/json" \
      -d "{\"meta\":{\"ver\":\"1.0\",\"ts\":\"$ts\",\"txn\":\"$txn\",\"accountNumber\":\"$CERTINEXT_ACCOUNT_NUMBER\",\"authKey\":\"$authKey\"},\"searchCriteria\":{\"groupNumber\":\"$CERTINEXT_GROUP_NUMBER\",\"pageNumber\":\"$1\",\"pageSize\":\"$PAGE_SIZE\"}}"
}

# --- Snapshot all pending order numbers up front (before rejecting anything) ---
first=$(report_page 1)
pages=$(echo "$first" | jq -r '.orderDetails.noOfPages // 1')
pending=$(echo "$first" | jq -r '.orderDetails.ordersArray[] | select(.certificateStatusId=="24" or .certificateStatusId=="2") | .orderNumber')
p=2
while [ "$p" -le "$pages" ]; do
    more=$(report_page "$p" | jq -r '.orderDetails.ordersArray[] | select(.certificateStatusId=="24" or .certificateStatusId=="2") | .orderNumber')
    [ -n "$more" ] && pending="$pending"$'\n'"$more"
    p=$((p+1))
done
pending=$(echo "$pending" | sed '/^$/d')

count=$(echo "$pending" | grep -c . || true)
echo "Found $count pending order(s) (certificateStatusId 2/24) across $pages page(s)."

if [ "$DRY" = "1" ]; then
    echo "DRY RUN — set REJECT_ALL_PENDING=1 to reject. First 10:"
    echo "$pending" | head -10 | sed 's/^/  /'
    exit 0
fi

ok=0; fail=0
while IFS= read -r n; do
    [ -z "$n" ] && continue
    read -r ts txn authKey <<< "$(certinext_meta)"
    st=$(curl -s -X POST "$CERTINEXT_API_URL/RejectOrder" -H "Content-Type: application/json" \
      -d "{\"meta\":{\"ver\":\"1.0\",\"ts\":\"$ts\",\"txn\":\"$txn\",\"accountNumber\":\"$CERTINEXT_ACCOUNT_NUMBER\",\"authKey\":\"$authKey\"},\"orderDetails\":{\"orderNumber\":\"$n\",\"rejectRemarks\":\"$REMARKS\"}}" \
      | jq -r '.meta.status // "?"')
    if [ "$st" = "1" ]; then ok=$((ok+1)); else fail=$((fail+1)); echo "  FAIL $n (status=$st)"; fi
done <<< "$pending"

echo "Done. Rejected ok=$ok  fail=$fail  (of $count)."
