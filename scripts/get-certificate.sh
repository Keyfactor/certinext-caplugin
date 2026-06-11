#!/usr/bin/env bash
# Required env var: ORDER_NUMBER
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/lib/certinext-auth.sh"

if [ -z "${ORDER_NUMBER:-}" ]; then
    echo "Usage: ORDER_NUMBER=<order number> scripts/get-certificate.sh" >&2
    exit 1
fi

read -r ts txn authKey <<< "$(certinext_meta)"
echo "GetCertificate  orderNumber=$ORDER_NUMBER  ts=$ts  txn=$txn"
curl -s -X POST "$CERTINEXT_API_URL/GetCertificate" \
     -H "Content-Type: application/json" \
     -d "{\"meta\":{\"ver\":\"1.0\",\"ts\":\"$ts\",\"txn\":\"$txn\",\"accountNumber\":\"$CERTINEXT_ACCOUNT_NUMBER\",\"authKey\":\"$authKey\"},\"orderDetails\":{\"orderNumber\":\"$ORDER_NUMBER\",\"requestorEmail\":\"$CERTINEXT_REQUESTOR_EMAIL\"}}" \
| jq .
