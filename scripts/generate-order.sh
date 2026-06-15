#!/usr/bin/env bash
# Required env var: DOMAIN
# Optional env vars: CSR_FILE, VALIDITY (default 1), SAVE_AND_HOLD (default 1), CODE
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/lib/certinext-auth.sh"

DOMAIN="${DOMAIN:-}"
CSR_FILE="${CSR_FILE:-}"
VALIDITY="${VALIDITY:-1}"
SAVE_AND_HOLD="${SAVE_AND_HOLD:-1}"

if [ -z "$DOMAIN" ]; then
    echo "Usage: DOMAIN=<domain> [CSR_FILE=<path>] [VALIDITY=1] [SAVE_AND_HOLD=1] scripts/generate-order.sh" >&2
    exit 1
fi

if [ -n "${CODE:-}" ]; then
    CERTINEXT_PRODUCT_CODE="$CODE"
fi

read -r ts txn authKey <<< "$(certinext_meta)"

signerIp="${CERTINEXT_SIGNER_IP:-}"
if [ -z "$signerIp" ]; then signerIp=$(curl -s https://api.ipify.org); fi

mobile="${CERTINEXT_REQUESTOR_MOBILE:-0000000000}"
name="${CERTINEXT_REQUESTOR_NAME:-Keyfactor Gateway Test}"

echo "GenerateOrderSSL  domain=$DOMAIN  productCode=$CERTINEXT_PRODUCT_CODE  validity=$VALIDITY  saveAndHold=$SAVE_AND_HOLD  signerIp=$signerIp  ts=$ts  txn=$txn"

if [ -n "$CSR_FILE" ] && [ -f "$CSR_FILE" ]; then
    result=$(jq -n \
        --arg ver "1.0" --arg ts "$ts" --arg txn "$txn" \
        --arg acct "$CERTINEXT_ACCOUNT_NUMBER" --arg auth "$authKey" \
        --arg pc "$CERTINEXT_PRODUCT_CODE" \
        --arg grp "$CERTINEXT_GROUP_NUMBER" \
        --arg org "$CERTINEXT_ORG_NUMBER" \
        --arg domain "$DOMAIN" \
        --arg validity "$VALIDITY" \
        --arg sah "$SAVE_AND_HOLD" \
        --arg email "$CERTINEXT_REQUESTOR_EMAIL" \
        --arg name "$name" \
        --arg mobile "$mobile" \
        --arg signerIp "$signerIp" \
        --rawfile csr "$CSR_FILE" \
        '{meta:{ver:$ver,ts:$ts,txn:$txn,accountNumber:$acct,authKey:$auth},
          orderDetails:{
            productCode:$pc,
            accountingModel:"2",
            saveAndHold:$sah,
            emailNotifications:"1",
            delegationInformation:{groupNumber:$grp},
            organizationDetails:{preVetting:"1",organizationNumber:$org},
            requestorInformation:{requestorName:$name,
              requestorIsdCode:"91",requestorMobileNumber:$mobile,
              requestorEmail:$email},
            subscriptionDetails:{validity:$validity,autoRenew:"0",renewCriteria:"30"},
            certificateInformation:{domainName:$domain,autoSecureWWW:"1"},
            technicalPointOfContact:{tpcName:$name,tpcEmail:$email,
              tpcIsdCode:"91",tpcMobileNumber:$mobile},
            csr:$csr,
            agreementDetails:{acceptAgreement:"1",signerName:$name,
              signerPlace:"Gateway",signerIP:$signerIp},
            additionalInformation:{remarks:"Issued via Keyfactor Command AnyCA REST Gateway."}}}' \
        | curl -s -X POST "$CERTINEXT_API_URL/GenerateOrderSSL" \
               -H "Content-Type: application/json" \
               -d @-)
else
    result=$(jq -n \
        --arg ver "1.0" --arg ts "$ts" --arg txn "$txn" \
        --arg acct "$CERTINEXT_ACCOUNT_NUMBER" --arg auth "$authKey" \
        --arg pc "$CERTINEXT_PRODUCT_CODE" \
        --arg grp "$CERTINEXT_GROUP_NUMBER" \
        --arg org "$CERTINEXT_ORG_NUMBER" \
        --arg domain "$DOMAIN" \
        --arg validity "$VALIDITY" \
        --arg sah "$SAVE_AND_HOLD" \
        --arg email "$CERTINEXT_REQUESTOR_EMAIL" \
        --arg name "$name" \
        --arg mobile "$mobile" \
        --arg signerIp "$signerIp" \
        '{meta:{ver:$ver,ts:$ts,txn:$txn,accountNumber:$acct,authKey:$auth},
          orderDetails:{
            productCode:$pc,
            accountingModel:"2",
            saveAndHold:$sah,
            emailNotifications:"1",
            delegationInformation:{groupNumber:$grp},
            organizationDetails:{preVetting:"1",organizationNumber:$org},
            requestorInformation:{requestorName:$name,
              requestorIsdCode:"91",requestorMobileNumber:$mobile,
              requestorEmail:$email},
            subscriptionDetails:{validity:$validity,autoRenew:"0",renewCriteria:"30"},
            certificateInformation:{domainName:$domain,autoSecureWWW:"1"},
            technicalPointOfContact:{tpcName:$name,tpcEmail:$email,
              tpcIsdCode:"91",tpcMobileNumber:$mobile},
            agreementDetails:{acceptAgreement:"1",signerName:$name,
              signerPlace:"Gateway",signerIP:$signerIp},
            additionalInformation:{remarks:"Issued via Keyfactor Command AnyCA REST Gateway."}}}' \
        | curl -s -X POST "$CERTINEXT_API_URL/GenerateOrderSSL" \
               -H "Content-Type: application/json" \
               -d @-)
fi

echo ""
echo "==> Full response:"
echo "$result" | jq .
echo ""
echo "==> requestNumber (draft ID — use with make submit-csr):"
echo "$result" | jq -r '.orderDetails.requestNumber // .meta.errorMessage // "none"'
