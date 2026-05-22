#!/usr/bin/env bash
# Required env vars: ORDER_NUMBER, CSR_FILE
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/lib/certinext-auth.sh"

if [ -z "${ORDER_NUMBER:-}" ] || [ -z "${CSR_FILE:-}" ]; then
    echo "Usage: ORDER_NUMBER=<order number> CSR_FILE=<path> scripts/submit-csr.sh" >&2
    exit 1
fi

if [ ! -f "$CSR_FILE" ]; then
    echo "CSR_FILE '$CSR_FILE' not found" >&2
    exit 1
fi

read -r ts txn authKey <<< "$(certinext_meta)"
echo "SubmitCSR  orderNumber=$ORDER_NUMBER  csrFile=$CSR_FILE  ts=$ts  txn=$txn"
curl -s -X POST "$CERTINEXT_API_URL/SubmitCSR" \
     -H "Content-Type: application/json" \
     -d "$(jq -n \
         --arg ver "1.0" --arg ts "$ts" --arg txn "$txn" \
         --arg acct "$CERTINEXT_ACCOUNT_NUMBER" --arg auth "$authKey" \
         --arg order "$ORDER_NUMBER" --arg email "$CERTINEXT_REQUESTOR_EMAIL" \
         --rawfile csr "$CSR_FILE" \
         '{meta:{ver:$ver,ts:$ts,txn:$txn,accountNumber:$acct,authKey:$auth},
           orderDetails:{orderNumber:$order,requestorEmail:$email,csr:$csr}}')" \
| jq .
