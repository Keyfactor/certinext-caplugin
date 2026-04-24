#!/usr/bin/env bash
# Optional env var: PROBE_DOMAIN (default test-integration.example.com)
# Depends on /tmp/certinext-test.csr being present (run generate-test-csr first).
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/lib/certinext-auth.sh"

PROBE_DOMAIN="${PROBE_DOMAIN:-test-integration.example.com}"

signerIp="${CERTINEXT_SIGNER_IP:-}"
if [ -z "$signerIp" ]; then signerIp=$(curl -s https://api.ipify.org); fi

name="${CERTINEXT_REQUESTOR_NAME:-Keyfactor Gateway Test}"
mobile="${CERTINEXT_REQUESTOR_MOBILE:-0000000000}"

echo ""
echo "=== probe-products: testing SSL/TLS product codes for account $CERTINEXT_ACCOUNT_NUMBER ==="
echo ""

for code in 842 843 844 845 846 847 848 849 850 851 149; do
    read -r ts txn authKey <<< "$(certinext_meta)"
    result=$(jq -n \
        --arg ver "1.0" --arg ts "$ts" --arg txn "$txn" \
        --arg acct "$CERTINEXT_ACCOUNT_NUMBER" --arg auth "$authKey" \
        --arg pc "$code" \
        --arg grp "$CERTINEXT_GROUP_NUMBER" \
        --arg org "$CERTINEXT_ORG_NUMBER" \
        --arg domain "$PROBE_DOMAIN" \
        --arg email "$CERTINEXT_REQUESTOR_EMAIL" \
        --arg name "$name" \
        --arg mobile "$mobile" \
        --arg signerIp "$signerIp" \
        --rawfile csr /tmp/certinext-test.csr \
        '{meta:{ver:$ver,ts:$ts,txn:$txn,accountNumber:$acct,authKey:$auth},
          orderDetails:{
            productCode:$pc,
            accountingModel:"2",
            saveAndHold:"1",
            emailNotifications:"0",
            delegationInformation:{groupNumber:$grp},
            organizationDetails:{preVetting:"1",organizationNumber:$org},
            requestorInformation:{requestorName:$name,
              requestorIsdCode:"1",requestorMobileNumber:$mobile,
              requestorEmail:$email},
            subscriptionDetails:{validity:"1",autoRenew:"0",renewCriteria:"30"},
            certificateInformation:{domainName:$domain,autoSecureWWW:"1"},
            technicalPointOfContact:{tpcName:$name,tpcEmail:$email,
              tpcIsdCode:"1",tpcMobileNumber:$mobile},
            csr:$csr,
            agreementDetails:{acceptAgreement:"1",signerName:$name,
              signerPlace:"Gateway",signerIP:$signerIp},
            additionalInformation:{remarks:"Keyfactor probe-products smoke test"}}}' \
        | curl -s -X POST "$CERTINEXT_API_URL/GenerateOrderSSL" \
               -H "Content-Type: application/json" \
               -d @-)
    status=$(echo "$result" | jq -r '.meta.status // "?"')
    errCode=$(echo "$result" | jq -r '.meta.errorCode // ""')
    errMsg=$(echo "$result" | jq -r '.meta.errorMessage // ""')
    reqNum=$(echo "$result" | jq -r '.orderDetails.requestNumber // ""')
    if [ "$status" = "1" ] && [ -n "$reqNum" ]; then
        echo "  VALID   code=$code  requestNumber=$reqNum"
    else
        echo "  INVALID code=$code  errorCode=$errCode  errorMessage=$errMsg"
    fi
done

echo ""
