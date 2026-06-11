#!/usr/bin/env bash
# Optional env vars: PAGE (default 1), PAGE_SIZE (default 10)
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/lib/certinext-auth.sh"

PAGE="${PAGE:-1}"
PAGE_SIZE="${PAGE_SIZE:-10}"

read -r ts txn authKey <<< "$(certinext_meta)"
echo "GetOrderReport  page=$PAGE  pageSize=$PAGE_SIZE  ts=$ts  txn=$txn"
curl -s -X POST "$CERTINEXT_API_URL/GetOrderReport" \
     -H "Content-Type: application/json" \
     -d "{\"meta\":{\"ver\":\"1.0\",\"ts\":\"$ts\",\"txn\":\"$txn\",\"accountNumber\":\"$CERTINEXT_ACCOUNT_NUMBER\",\"authKey\":\"$authKey\"},\"searchCriteria\":{\"groupNumber\":\"$CERTINEXT_GROUP_NUMBER\",\"pageNumber\":\"$PAGE\",\"pageSize\":\"$PAGE_SIZE\"}}" \
| jq .
