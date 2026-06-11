#!/usr/bin/env bash
# Optional env var: SAVE_AND_HOLD (default 1)
set -euo pipefail
. ~/.env_certinext
. "$(dirname "$0")/lib/certinext-auth.sh"

SAVE_AND_HOLD="${SAVE_AND_HOLD:-1}"

cn=$(sh "$(dirname "$0")/generate-fresh-csr.sh")
echo "Fresh CSR generated for CN=$cn"

read -r ts txn authKey <<< "$(certinext_meta)"

signerIp="${CERTINEXT_SIGNER_IP:-}"
if [ -z "$signerIp" ]; then signerIp=$(curl -s https://api.ipify.org); fi

mobile="${CERTINEXT_REQUESTOR_MOBILE:-0000000000}"
name="${CERTINEXT_REQUESTOR_NAME:-Keyfactor Plugin Test}"

echo "GenerateOrderPrivatePKI  product=149  domain=$cn  saveAndHold=$SAVE_AND_HOLD  ts=$ts  txn=$txn"

result=$(jq -n \
    --arg ver "1.0" --arg ts "$ts" --arg txn "$txn" \
    --arg acct "$CERTINEXT_ACCOUNT_NUMBER" --arg auth "$authKey" \
    --arg grp "$CERTINEXT_GROUP_NUMBER" \
    --arg domain "$cn" \
    --arg email "$CERTINEXT_REQUESTOR_EMAIL" \
    --arg name "$name" \
    --arg mobile "$mobile" \
    --arg signerIp "$signerIp" \
    --arg sah "$SAVE_AND_HOLD" \
    --rawfile csr "/tmp/certinext-unique.csr" \
    '{meta:{ver:$ver,ts:$ts,txn:$txn,accountNumber:$acct,authKey:$auth},
      orderDetails:{
        productCode:"149",
        accountingModel:"2",
        saveAndHold:$sah,
        emailNotifications:"0",
        delegationInformation:{groupNumber:$grp},
        requestorInformation:{requestorName:$name,
          requestorIsdCode:"1",requestorMobileNumber:$mobile,
          requestorEmail:$email},
        certificateInformation:{domainName:$domain,
          organizationName:"Keyfactor Inc",dnsType:"1",additionalDomains:[]},
        additionalInformation:{remarks:"Keyfactor integration test — auto-approve probe"},
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
echo "$result" | jq -r '"  status=\(.meta.status)  orderNumber=\(.orderDetails.orderNumber // "none")  requestNumber=\(.orderDetails.requestNumber // "none")  orderStatus=\(.orderDetails.orderStatus // "none")  certStatusId=\(.orderDetails.certificateStatusId // "none")  errorCode=\(.meta.errorCode)  errorMsg=\(.meta.errorMessage)"'
