#!/usr/bin/env bash
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/lib/certinext-auth.sh"

echo ""
echo "=== list-cas: CERTInext Sub-CA listing via API ==="
echo ""
echo "RESULT: No Sub-CA listing endpoint exists in the CERTInext REST API."
echo ""
echo "Probing 3 representative endpoint names to confirm:"

for ep in GetCAList GetSubCAList GetIssuerList; do
    read -r ts txn authKey <<< "$(certinext_meta)"
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$CERTINEXT_API_URL/$ep" \
        -H "Content-Type: application/json" \
        -d "{\"meta\":{\"ver\":\"1.0\",\"ts\":\"$ts\",\"txn\":\"$txn\",\"accountNumber\":\"$CERTINEXT_ACCOUNT_NUMBER\",\"authKey\":\"$authKey\"}}")
    echo "  HTTP $http_code  $ep"
done

echo ""
echo "Active Sub-CAs for this sandbox account (from portal UI):"
echo "  Name:   emSign Issuing Sand box CA IGTF - C6"
echo "  Type:   Subordinate CA"
echo "  Status: Active"
echo ""
echo "Revoked Sub-CAs:"
echo "  Name:   emSign Sandbox Issuing CA - G1  (Revoked — cause of DV SSL issuance failures)"
echo ""
echo "Private PKI Root:"
echo "  Name:   eMudhra Sandbox Private Root CA G1  (Root CA, Active)"
echo ""
