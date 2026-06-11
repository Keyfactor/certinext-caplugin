#!/usr/bin/env bash
# Required env vars: ORDER_NUMBER, DOMAIN_NAME
# Optional: DCV_METHOD (default: 1 = DNS TXT record)
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/lib/certinext-auth.sh"

ORDER_NUMBER="${ORDER_NUMBER:?Usage: ORDER_NUMBER=<order> DOMAIN_NAME=<domain> [DCV_METHOD=1] scripts/get-dcv.sh}"
DOMAIN_NAME="${DOMAIN_NAME:?DOMAIN_NAME is required}"
DCV_METHOD="${DCV_METHOD:-1}"

read -r ts txn authKey <<< "$(certinext_meta)"

# SOC2 CC6.1: do NOT echo authKey — it is a valid single-use request authenticator.
echo "GetDcv  orderNumber=$ORDER_NUMBER  domainName=$DOMAIN_NAME  dcvMethod=$DCV_METHOD  ts=$ts  txn=$txn"

# SOX CC6.6: use jq --arg to safely interpolate all user-supplied values into the JSON body,
# preventing shell injection via specially crafted ORDER_NUMBER or DOMAIN_NAME values.
jq -n \
  --arg ver "1.0" \
  --arg ts "$ts" \
  --arg txn "$txn" \
  --arg acct "$CERTINEXT_ACCOUNT_NUMBER" \
  --arg authKey "$authKey" \
  --arg email "$CERTINEXT_REQUESTOR_EMAIL" \
  --arg order "$ORDER_NUMBER" \
  --arg domain "$DOMAIN_NAME" \
  --arg method "$DCV_METHOD" \
  '{
    meta: {ver: $ver, ts: $ts, txn: $txn, accountNumber: $acct, authKey: $authKey},
    dcvDetails: {requestorEmail: $email, orderNumber: $order, domainName: $domain, dcvMethod: $method}
  }' \
| curl -s -X POST "$CERTINEXT_API_URL/GetDcv" \
       -H "Content-Type: application/json" \
       --data-binary @- \
| jq .
