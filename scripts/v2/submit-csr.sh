#!/usr/bin/env bash
# V2 ssl-certificates/{orderId}/csr — attach a PEM CSR to an SSL order.
# Required env vars: ORDER_ID, CSR_FILE (path to PEM file)
#
# 204 No Content = CSR accepted; order advances to pending-agreement.
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"

ORDER_ID="${ORDER_ID:-}"
CSR_FILE="${CSR_FILE:-}"

if [ -z "$ORDER_ID" ] || [ -z "$CSR_FILE" ]; then
    echo "Usage: ORDER_ID=<orderId> CSR_FILE=<path> scripts/v2/submit-csr.sh" >&2
    exit 1
fi

if [ ! -f "$CSR_FILE" ]; then
    echo "CSR_FILE '$CSR_FILE' not found" >&2
    exit 1
fi

echo "V2 PUT /api/certinext/v2/ssl-certificates/$ORDER_ID/csr  csrFile=$CSR_FILE"
curl -s -X PUT "$CERTINEXT_V2_API_URL/api/certinext/v2/ssl-certificates/$ORDER_ID/csr" \
     -H "Authorization: Bearer $CERTINEXT_V2_TOKEN" \
     -H "Content-Type: application/json" \
     -d "$(jq -n --rawfile csr "$CSR_FILE" '{csr:$csr,attested:false}')" \
| jq .
