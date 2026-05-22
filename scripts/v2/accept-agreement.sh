#!/usr/bin/env bash
# V2 ssl-certificates/{orderId}/agreement — record Subscriber Agreement acceptance.
# Required env var: ORDER_ID
#
# 204 No Content = recorded; the CA proceeds to issue the certificate.
# After this step poll v2-track-order until status=issued, then v2-download-certificate.
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"

ORDER_ID="${ORDER_ID:-}"

if [ -z "$ORDER_ID" ]; then
    echo "Usage: ORDER_ID=<orderId> scripts/v2/accept-agreement.sh" >&2
    exit 1
fi

name="${CERTINEXT_REQUESTOR_NAME:-Keyfactor Gateway Test}"
signerIp="${CERTINEXT_SIGNER_IP:-}"
if [ -z "$signerIp" ]; then signerIp=$(curl -s https://api.ipify.org); fi

echo "V2 POST /api/certinext/v2/ssl-certificates/$ORDER_ID/agreement  signerName=$name  signerIp=$signerIp"
curl -s -X POST "$CERTINEXT_V2_API_URL/api/certinext/v2/ssl-certificates/$ORDER_ID/agreement" \
     -H "Authorization: Bearer $CERTINEXT_V2_TOKEN" \
     -H "Content-Type: application/json" \
     -d "$(jq -n \
         --arg name "$name" \
         --arg ip "$signerIp" \
         '{agreement:{signerName:$name,signerIp:$ip,signerPlace:"Gateway",accepted:true}}')" \
| jq .
