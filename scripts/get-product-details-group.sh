#!/usr/bin/env bash
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/lib/certinext-auth.sh"

read -r ts txn authKey <<< "$(certinext_meta)"
echo "GetProductDetails (with groupNumber=$CERTINEXT_GROUP_NUMBER)  ts=$ts  txn=$txn"
curl -s -X POST "$CERTINEXT_API_URL/GetProductDetails" \
     -H "Content-Type: application/json" \
     -d "$(jq -n \
         --arg ver "1.0" --arg ts "$ts" --arg txn "$txn" \
         --arg acct "$CERTINEXT_ACCOUNT_NUMBER" --arg auth "$authKey" \
         --arg grp "$CERTINEXT_GROUP_NUMBER" \
         '{meta:{ver:$ver,ts:$ts,txn:$txn,accountNumber:$acct,authKey:$auth},
           productDetails:{groupNumber:$grp}}')" \
| jq .
