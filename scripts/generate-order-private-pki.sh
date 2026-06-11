#!/usr/bin/env bash
# Optional env vars: PRIVATE_PKI_CODE (default 149),
#                    PRIVATE_PKI_DOMAIN (default test-private-pki.example.com),
#                    PRIVATE_PKI_CSR (default /tmp/certinext-igtf-test.csr),
#                    SAVE_AND_HOLD (default 1)
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/lib/certinext-auth.sh"

PRIVATE_PKI_CODE="${PRIVATE_PKI_CODE:-149}"
PRIVATE_PKI_DOMAIN="${PRIVATE_PKI_DOMAIN:-test-private-pki.example.com}"
PRIVATE_PKI_CSR="${PRIVATE_PKI_CSR:-/tmp/certinext-igtf-test.csr}"
SAVE_AND_HOLD="${SAVE_AND_HOLD:-1}"

if [ ! -f "$PRIVATE_PKI_CSR" ]; then
    echo "CSR file not found: $PRIVATE_PKI_CSR" >&2
    exit 1
fi

read -r ts txn authKey <<< "$(certinext_meta)"

signerIp="${CERTINEXT_SIGNER_IP:-}"
if [ -z "$signerIp" ]; then signerIp=$(curl -s https://api.ipify.org); fi

mobile="${CERTINEXT_REQUESTOR_MOBILE:-0000000000}"
name="${CERTINEXT_REQUESTOR_NAME:-Keyfactor Plugin Test}"

echo "GenerateOrderPrivatePKI  product=$PRIVATE_PKI_CODE  domain=$PRIVATE_PKI_DOMAIN  saveAndHold=$SAVE_AND_HOLD  ts=$ts  txn=$txn"

result=$(jq -n \
    --arg ver "1.0" --arg ts "$ts" --arg txn "$txn" \
    --arg acct "$CERTINEXT_ACCOUNT_NUMBER" --arg auth "$authKey" \
    --arg pc "$PRIVATE_PKI_CODE" \
    --arg grp "$CERTINEXT_GROUP_NUMBER" \
    --arg domain "$PRIVATE_PKI_DOMAIN" \
    --arg email "$CERTINEXT_REQUESTOR_EMAIL" \
    --arg name "$name" \
    --arg mobile "$mobile" \
    --arg signerIp "$signerIp" \
    --arg sah "$SAVE_AND_HOLD" \
    --rawfile csr "$PRIVATE_PKI_CSR" \
    '{meta:{ver:$ver,ts:$ts,txn:$txn,accountNumber:$acct,authKey:$auth},
      orderDetails:{
        productCode:$pc,
        accountingModel:"2",
        saveAndHold:$sah,
        emailNotifications:"0",
        delegationInformation:{groupNumber:$grp},
        requestorInformation:{requestorName:$name,
          requestorIsdCode:"1",requestorMobileNumber:$mobile,
          requestorEmail:$email},
        certificateInformation:{domainName:$domain,
          organizationName:"Keyfactor Inc",dnsType:"1",additionalDomains:[]},
        additionalInformation:{remarks:"Keyfactor Private PKI smoke test"},
        csr:$csr,
        agreementDetails:{acceptAgreement:"1",signerName:$name,
          signerPlace:"Gateway",signerIP:$signerIp}}}' \
    | curl -s -X POST "$CERTINEXT_API_URL/GenerateOrderPrivatePKI" \
           -H "Content-Type: application/json" \
           -d @-)

echo ""
echo "==> Full response:"
echo "$result" | jq .
echo ""
echo "==> Order status summary:"
echo "$result" | jq -r '"  status=\(.meta.status)  orderNumber=\(.orderDetails.orderNumber // "none")  requestNumber=\(.orderDetails.requestNumber // "none")  orderStatus=\(.orderDetails.orderStatus // "none")  errorCode=\(.meta.errorCode)  errorMsg=\(.meta.errorMessage)"'
