#!/usr/bin/env bash
# Optional env vars: PRODUCT_CODE (default 149), CATEGORY_ID (default 8)
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/lib/certinext-auth.sh"

PRODUCT_CODE="${PRODUCT_CODE:-149}"
CATEGORY_ID="${CATEGORY_ID:-8}"

read -r ts txn authKey <<< "$(certinext_meta)"
echo "GetFieldDetails  product=$PRODUCT_CODE  category=$CATEGORY_ID  ts=$ts  txn=$txn"
curl -s -X POST "$CERTINEXT_API_URL/GetFieldDetails" \
     -H "Content-Type: application/json" \
     -d "$(jq -n \
         --arg ver "1.0" --arg ts "$ts" --arg txn "$txn" \
         --arg acct "$CERTINEXT_ACCOUNT_NUMBER" --arg auth "$authKey" \
         --arg grp "$CERTINEXT_GROUP_NUMBER" \
         --arg pc "$PRODUCT_CODE" \
         --arg cat "$CATEGORY_ID" \
         '{meta:{ver:$ver,ts:$ts,txn:$txn,accountNumber:$acct,authKey:$auth},
           productDetails:{groupNumber:$grp,categoryID:$cat,productCode:$pc}}')" \
| jq .
