#!/usr/bin/env bash
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/lib/certinext-auth.sh"

echo ""
echo "=== create-product: CERTInext product management via API ==="
echo ""
echo "RESULT: No product creation or configuration endpoint exists in the"
echo "        CERTInext REST API.  Products must be created via the portal UI."
echo ""
echo "Probing 3 representative endpoint names to confirm:"

for ep in CreateProduct ConfigureProduct AddCertificateProfile; do
    read -r ts txn authKey <<< "$(certinext_meta)"
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$CERTINEXT_API_URL/$ep" \
        -H "Content-Type: application/json" \
        -d "{\"meta\":{\"ver\":\"1.0\",\"ts\":\"$ts\",\"txn\":\"$txn\",\"accountNumber\":\"$CERTINEXT_ACCOUNT_NUMBER\",\"authKey\":\"$authKey\"}}")
    echo "  HTTP $http_code  $ep"
done

echo ""
echo "Portal URL: https://sandbox-us.certinext.io"
echo "Path:       Account -> Products -> Configure Product"
echo ""
echo "To create a Private PKI product with auto-approval:"
echo "  1. Log in to the portal."
echo "  2. Navigate to Account -> Products -> Configure Product."
echo "  3. Set Product Name: Keyfactor Integration Test"
echo "  4. Select Subordinate CA: emSign Issuing Sand box CA IGTF - C6"
echo "  5. Set Validity In Days: 365"
echo "  6. Select Key Algorithm: RSA 2048 SHA-256"
echo "  7. Under Advanced Settings, enable: Automatically approve the certificate requests"
echo "  8. Save.  The portal assigns a new product code."
echo "  9. Add the new product code to ~/.env_certinext as CERTINEXT_PRODUCT_CODE."
echo ""
