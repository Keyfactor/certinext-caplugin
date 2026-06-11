#!/usr/bin/env bash
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/lib/certinext-auth.sh"

read -r ts txn authKey <<< "$(certinext_meta)"
echo "ValidateCredentials  ts=$ts  txn=$txn"
curl -s -X POST "$CERTINEXT_API_URL/ValidateCredentials" \
     -H "Content-Type: application/json" \
     -d "{\"meta\":{\"ver\":\"1.0\",\"ts\":\"$ts\",\"txn\":\"$txn\",\"accountNumber\":\"$CERTINEXT_ACCOUNT_NUMBER\",\"authKey\":\"$authKey\"}}" \
| jq .
