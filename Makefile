SLN         := certinext-caplugin.sln
COVERAGE_DIR := /tmp/certinext-coverage
REPORT_DIR   := /tmp/certinext-coverage-report

.PHONY: build test integration-test coverage coverage-report open-coverage clean \
        ping \
        get-product-details products \
        get-order-report orders \
        track-order get-order \
        get-certificate get-cert \
        generate-order \
        revoke-order \
        submit-csr \
        api-help

build:
	dotnet build $(SLN)

test:
	dotnet test $(SLN) --verbosity normal

integration-test:
	dotnet test CERTInext.IntegrationTests/ --verbosity normal

coverage:
	rm -rf $(COVERAGE_DIR)
	dotnet test $(SLN) \
		--collect:"XPlat Code Coverage" \
		--results-directory $(COVERAGE_DIR)
	dotnet tool install -g dotnet-reportgenerator-globaltool 2>/dev/null || true
	reportgenerator \
		-reports:"$(COVERAGE_DIR)/**/coverage.cobertura.xml" \
		-targetdir:$(REPORT_DIR) \
		-reporttypes:"TextSummary;Html"
	@cat $(REPORT_DIR)/Summary.txt

coverage-report: coverage
	open $(REPORT_DIR)/index.html

clean:
	dotnet clean $(SLN)
	rm -rf $(COVERAGE_DIR) $(REPORT_DIR)

# ---------------------------------------------------------------------------
# API smoke tests  (credentials from ~/.env_certinext)
#
# Shared variables set inside every recipe shell:
#   ts      : current timestamp in IST (Asia/Kolkata), format required by CERTInext
#   txn     : random 16-digit transaction ID
#   authKey : SHA-256(accessKey + ts + txn) — HMAC computation stays in python3
#
# All JSON output is piped through jq for pretty-printing.
# ---------------------------------------------------------------------------

# Makefile does not support multi-line variable expansion inside recipes the
# way define/endef does across shells, so the preamble is repeated verbatim
# in each recipe.  All three lines must appear before any curl call.
#
# PREAMBLE (copy into each recipe):
#   . ~/.env_certinext; \
#   ts=$$(TZ=Asia/Kolkata date +%Y-%m-%dT%H:%M:%S+05:30); \
#   txn=$$(python3 -c "import random; print(str(random.randint(1000000000000000,9999999999999999)))"); \
#   authKey=$$(python3 -c "import hashlib,sys; print(hashlib.sha256((sys.argv[1]+sys.argv[2]+sys.argv[3]).encode()).hexdigest())" "$$CERTINEXT_ACCESS_KEY" "$$ts" "$$txn");

# ---------------------------------------------------------------------------
# ValidateCredentials — POST {baseURL}ValidateCredentials
# Health / connectivity probe — mirrors ICERTInextClient.PingAsync
# ---------------------------------------------------------------------------

ping:
	@set -euo pipefail; \
	. ~/.env_certinext; \
	ts=$$(TZ=Asia/Kolkata date +%Y-%m-%dT%H:%M:%S+05:30); \
	txn=$$(python3 -c "import random; print(str(random.randint(1000000000000000,9999999999999999)))"); \
	authKey=$$(python3 -c "import hashlib,sys; print(hashlib.sha256((sys.argv[1]+sys.argv[2]+sys.argv[3]).encode()).hexdigest())" "$$CERTINEXT_ACCESS_KEY" "$$ts" "$$txn"); \
	echo "ValidateCredentials  ts=$$ts  txn=$$txn"; \
	curl -s -X POST "$$CERTINEXT_API_URL/ValidateCredentials" \
	     -H "Content-Type: application/json" \
	     -d "{\"meta\":{\"ver\":\"1.0\",\"ts\":\"$$ts\",\"txn\":\"$$txn\",\"accountNumber\":\"$$CERTINEXT_ACCOUNT_NUMBER\",\"authKey\":\"$$authKey\"}}" \
	| jq .

# ---------------------------------------------------------------------------
# GetProductDetails — POST {baseURL}GetProductDetails
# Lists available product codes — mirrors ICERTInextClient.GetProductDetailsAsync
# Aliases: products
# ---------------------------------------------------------------------------

get-product-details products:
	@set -euo pipefail; \
	. ~/.env_certinext; \
	ts=$$(TZ=Asia/Kolkata date +%Y-%m-%dT%H:%M:%S+05:30); \
	txn=$$(python3 -c "import random; print(str(random.randint(1000000000000000,9999999999999999)))"); \
	authKey=$$(python3 -c "import hashlib,sys; print(hashlib.sha256((sys.argv[1]+sys.argv[2]+sys.argv[3]).encode()).hexdigest())" "$$CERTINEXT_ACCESS_KEY" "$$ts" "$$txn"); \
	echo "GetProductDetails  ts=$$ts  txn=$$txn"; \
	curl -s -X POST "$$CERTINEXT_API_URL/GetProductDetails" \
	     -H "Content-Type: application/json" \
	     -d "{\"meta\":{\"ver\":\"1.0\",\"ts\":\"$$ts\",\"txn\":\"$$txn\",\"accountNumber\":\"$$CERTINEXT_ACCOUNT_NUMBER\",\"authKey\":\"$$authKey\"},\"productDetails\":{\"groupNumber\":\"$$CERTINEXT_GROUP_NUMBER\"}}" \
	| jq .

# ---------------------------------------------------------------------------
# GetOrderReport — POST {baseURL}GetOrderReport
# Paginated order listing — mirrors ICERTInextClient.ListOrdersAsync
# Aliases: orders
# Optional overrides: PAGE (default 1), PAGE_SIZE (default 10)
#
# Response shape (live API, verified 2026-04):
#   { "orderDetails": { "ordersArray": [...], "noOfPages": N,
#                       "totalNoOfResults": N, "pageSize": N, "currentPage": "1" },
#     "meta": { "status": "1", ... } }
#
# Each entry in ordersArray has "orderNumber" (blank when saveAndHold/draft)
# and "requestNumber" (the draft ID before the order is formally submitted).
# Use orderNumber for all post-issuance operations (TrackOrder, GetCertificate, RevokeOrder).
# ---------------------------------------------------------------------------

PAGE      ?= 1
PAGE_SIZE ?= 10

get-order-report orders:
	@set -euo pipefail; \
	. ~/.env_certinext; \
	ts=$$(TZ=Asia/Kolkata date +%Y-%m-%dT%H:%M:%S+05:30); \
	txn=$$(python3 -c "import random; print(str(random.randint(1000000000000000,9999999999999999)))"); \
	authKey=$$(python3 -c "import hashlib,sys; print(hashlib.sha256((sys.argv[1]+sys.argv[2]+sys.argv[3]).encode()).hexdigest())" "$$CERTINEXT_ACCESS_KEY" "$$ts" "$$txn"); \
	echo "GetOrderReport  page=$(PAGE)  pageSize=$(PAGE_SIZE)  ts=$$ts  txn=$$txn"; \
	curl -s -X POST "$$CERTINEXT_API_URL/GetOrderReport" \
	     -H "Content-Type: application/json" \
	     -d "{\"meta\":{\"ver\":\"1.0\",\"ts\":\"$$ts\",\"txn\":\"$$txn\",\"accountNumber\":\"$$CERTINEXT_ACCOUNT_NUMBER\",\"authKey\":\"$$authKey\"},\"searchCriteria\":{\"groupNumber\":\"$$CERTINEXT_GROUP_NUMBER\",\"pageNumber\":\"$(PAGE)\",\"pageSize\":\"$(PAGE_SIZE)\"}}" \
	| jq .

# ---------------------------------------------------------------------------
# TrackOrder — POST {baseURL}TrackOrder
# Fetches current order / certificate status — mirrors ICERTInextClient.TrackOrderAsync
# Aliases: get-order
# Required: ORDER_NUMBER=<order number>
#
# IMPORTANT: ORDER_NUMBER must be the "orderNumber" field from GetOrderReport
# (the field assigned after formal submission), NOT the "requestNumber" (draft ID).
# Using a requestNumber will return EMS-943 (order not found).
# ---------------------------------------------------------------------------

track-order get-order:
	@set -euo pipefail; \
	if [ -z "$(ORDER_NUMBER)" ]; then \
	  echo "Usage: make track-order ORDER_NUMBER=<order number>"; exit 1; \
	fi; \
	. ~/.env_certinext; \
	ts=$$(TZ=Asia/Kolkata date +%Y-%m-%dT%H:%M:%S+05:30); \
	txn=$$(python3 -c "import random; print(str(random.randint(1000000000000000,9999999999999999)))"); \
	authKey=$$(python3 -c "import hashlib,sys; print(hashlib.sha256((sys.argv[1]+sys.argv[2]+sys.argv[3]).encode()).hexdigest())" "$$CERTINEXT_ACCESS_KEY" "$$ts" "$$txn"); \
	echo "TrackOrder  orderNumber=$(ORDER_NUMBER)  ts=$$ts  txn=$$txn"; \
	curl -s -X POST "$$CERTINEXT_API_URL/TrackOrder" \
	     -H "Content-Type: application/json" \
	     -d "{\"meta\":{\"ver\":\"1.0\",\"ts\":\"$$ts\",\"txn\":\"$$txn\",\"accountNumber\":\"$$CERTINEXT_ACCOUNT_NUMBER\",\"authKey\":\"$$authKey\"},\"orderDetails\":{\"orderNumber\":\"$(ORDER_NUMBER)\"}}" \
	| jq .

# ---------------------------------------------------------------------------
# GetCertificate — POST {baseURL}GetCertificate
# Downloads the issued certificate PEM — mirrors ICERTInextClient.DownloadCertificateAsync
# Aliases: get-cert
# Required: ORDER_NUMBER=<order number>
# ---------------------------------------------------------------------------

get-certificate get-cert:
	@set -euo pipefail; \
	if [ -z "$(ORDER_NUMBER)" ]; then \
	  echo "Usage: make get-certificate ORDER_NUMBER=<order number>"; exit 1; \
	fi; \
	. ~/.env_certinext; \
	ts=$$(TZ=Asia/Kolkata date +%Y-%m-%dT%H:%M:%S+05:30); \
	txn=$$(python3 -c "import random; print(str(random.randint(1000000000000000,9999999999999999)))"); \
	authKey=$$(python3 -c "import hashlib,sys; print(hashlib.sha256((sys.argv[1]+sys.argv[2]+sys.argv[3]).encode()).hexdigest())" "$$CERTINEXT_ACCESS_KEY" "$$ts" "$$txn"); \
	echo "GetCertificate  orderNumber=$(ORDER_NUMBER)  ts=$$ts  txn=$$txn"; \
	curl -s -X POST "$$CERTINEXT_API_URL/GetCertificate" \
	     -H "Content-Type: application/json" \
	     -d "{\"meta\":{\"ver\":\"1.0\",\"ts\":\"$$ts\",\"txn\":\"$$txn\",\"accountNumber\":\"$$CERTINEXT_ACCOUNT_NUMBER\",\"authKey\":\"$$authKey\"},\"orderDetails\":{\"orderNumber\":\"$(ORDER_NUMBER)\",\"requestorEmail\":\"$$CERTINEXT_REQUESTOR_EMAIL\"}}" \
	| jq .

# ---------------------------------------------------------------------------
# GenerateOrderSSL — POST {baseURL}GenerateOrderSSL
# Places a new SSL/TLS certificate order — mirrors ICERTInextClient.PlaceOrderAsync
# Required: DOMAIN=<primary domain>
# Optional: CSR_FILE=<path to PEM CSR file>  VALIDITY=1|2|3  (subscription years)
#           SAVE_AND_HOLD=1 (default) — "1"=save draft, "0"=submit immediately
#
# On success, prints the requestNumber (draft ID) prominently.
# Use requestNumber to attach a CSR later (make submit-csr).
# Once the order is formally submitted, an orderNumber is assigned — use that
# for TrackOrder, GetCertificate, and RevokeOrder.
#
# Reads CERTINEXT_SIGNER_IP from ~/.env_certinext; falls back to public IP via ipify.
# Reads CERTINEXT_REQUESTOR_MOBILE from ~/.env_certinext (digits only, no country code).
# ---------------------------------------------------------------------------

DOMAIN       ?=
CSR_FILE     ?=
VALIDITY     ?= 1
SAVE_AND_HOLD ?= 1

generate-order:
	@set -euo pipefail; \
	if [ -z "$(DOMAIN)" ]; then \
	  echo "Usage: make generate-order DOMAIN=<domain> [CSR_FILE=<path>] [VALIDITY=1] [SAVE_AND_HOLD=1]"; exit 1; \
	fi; \
	. ~/.env_certinext; \
	ts=$$(TZ=Asia/Kolkata date +%Y-%m-%dT%H:%M:%S+05:30); \
	txn=$$(python3 -c "import random; print(str(random.randint(1000000000000000,9999999999999999)))"); \
	authKey=$$(python3 -c "import hashlib,sys; print(hashlib.sha256((sys.argv[1]+sys.argv[2]+sys.argv[3]).encode()).hexdigest())" "$$CERTINEXT_ACCESS_KEY" "$$ts" "$$txn"); \
	signerIp="$${CERTINEXT_SIGNER_IP:-}"; \
	if [ -z "$$signerIp" ]; then signerIp=$$(curl -s https://api.ipify.org); fi; \
	mobile="$${CERTINEXT_REQUESTOR_MOBILE:-0000000000}"; \
	name="$${CERTINEXT_REQUESTOR_NAME:-Keyfactor Gateway Test}"; \
	echo "GenerateOrderSSL  domain=$(DOMAIN)  productCode=$$CERTINEXT_PRODUCT_CODE  validity=$(VALIDITY)  saveAndHold=$(SAVE_AND_HOLD)  signerIp=$$signerIp  ts=$$ts  txn=$$txn"; \
	if [ -n "$(CSR_FILE)" ] && [ -f "$(CSR_FILE)" ]; then \
	  result=$$(jq -n \
	    --arg ver "1.0" --arg ts "$$ts" --arg txn "$$txn" \
	    --arg acct "$$CERTINEXT_ACCOUNT_NUMBER" --arg auth "$$authKey" \
	    --arg pc "$$CERTINEXT_PRODUCT_CODE" \
	    --arg grp "$$CERTINEXT_GROUP_NUMBER" \
	    --arg org "$$CERTINEXT_ORG_NUMBER" \
	    --arg domain "$(DOMAIN)" \
	    --arg validity "$(VALIDITY)" \
	    --arg sah "$(SAVE_AND_HOLD)" \
	    --arg email "$$CERTINEXT_REQUESTOR_EMAIL" \
	    --arg name "$$name" \
	    --arg mobile "$$mobile" \
	    --arg signerIp "$$signerIp" \
	    --rawfile csr "$(CSR_FILE)" \
	    '{meta:{ver:$$ver,ts:$$ts,txn:$$txn,accountNumber:$$acct,authKey:$$auth}, \
	      orderDetails:{ \
	        productCode:$$pc, \
	        accountingModel:"2", \
	        saveAndHold:$$sah, \
	        emailNotifications:"1", \
	        delegationInformation:{groupNumber:$$grp}, \
	        organizationDetails:{preVetting:"1",organizationNumber:$$org}, \
	        requestorInformation:{requestorName:$$name, \
	          requestorIsdCode:"91",requestorMobileNumber:$$mobile, \
	          requestorEmail:$$email}, \
	        subscriptionDetails:{validity:$$validity,autoRenew:"0",renewCriteria:"30"}, \
	        certificateInformation:{domainName:$$domain,autoSecureWWW:"1"}, \
	        technicalPointOfContact:{tpcName:$$name,tpcEmail:$$email, \
	          tpcIsdCode:"91",tpcMobileNumber:$$mobile}, \
	        csr:$$csr, \
	        agreementDetails:{acceptAgreement:"1",signerName:$$name, \
	          signerPlace:"Gateway",signerIP:$$signerIp}}}' \
	  | curl -s -X POST "$$CERTINEXT_API_URL/GenerateOrderSSL" \
	         -H "Content-Type: application/json" \
	         -d @-); \
	else \
	  result=$$(jq -n \
	    --arg ver "1.0" --arg ts "$$ts" --arg txn "$$txn" \
	    --arg acct "$$CERTINEXT_ACCOUNT_NUMBER" --arg auth "$$authKey" \
	    --arg pc "$$CERTINEXT_PRODUCT_CODE" \
	    --arg grp "$$CERTINEXT_GROUP_NUMBER" \
	    --arg org "$$CERTINEXT_ORG_NUMBER" \
	    --arg domain "$(DOMAIN)" \
	    --arg validity "$(VALIDITY)" \
	    --arg sah "$(SAVE_AND_HOLD)" \
	    --arg email "$$CERTINEXT_REQUESTOR_EMAIL" \
	    --arg name "$$name" \
	    --arg mobile "$$mobile" \
	    --arg signerIp "$$signerIp" \
	    '{meta:{ver:$$ver,ts:$$ts,txn:$$txn,accountNumber:$$acct,authKey:$$auth}, \
	      orderDetails:{ \
	        productCode:$$pc, \
	        accountingModel:"2", \
	        saveAndHold:$$sah, \
	        emailNotifications:"1", \
	        delegationInformation:{groupNumber:$$grp}, \
	        organizationDetails:{preVetting:"1",organizationNumber:$$org}, \
	        requestorInformation:{requestorName:$$name, \
	          requestorIsdCode:"91",requestorMobileNumber:$$mobile, \
	          requestorEmail:$$email}, \
	        subscriptionDetails:{validity:$$validity,autoRenew:"0",renewCriteria:"30"}, \
	        certificateInformation:{domainName:$$domain,autoSecureWWW:"1"}, \
	        technicalPointOfContact:{tpcName:$$name,tpcEmail:$$email, \
	          tpcIsdCode:"91",tpcMobileNumber:$$mobile}, \
	        agreementDetails:{acceptAgreement:"1",signerName:$$name, \
	          signerPlace:"Gateway",signerIP:$$signerIp}}}' \
	  | curl -s -X POST "$$CERTINEXT_API_URL/GenerateOrderSSL" \
	         -H "Content-Type: application/json" \
	         -d @-); \
	fi; \
	echo ""; \
	echo "==> Full response:"; \
	echo "$$result" | jq .; \
	echo ""; \
	echo "==> requestNumber (draft ID — use with make submit-csr):"; \
	echo "$$result" | jq -r '.orderDetails.requestNumber // .meta.errorMessage // "none"'

# ---------------------------------------------------------------------------
# RevokeOrder — POST {baseURL}RevokeOrder
# Revokes an issued certificate — mirrors ICERTInextClient.RevokeOrderAsync
# Required: ORDER_NUMBER=<order number>
# Optional: REASON_ID=<revokeReasonId>  (default 1 = KeyCompromise)
#
# CERTInext revokeReasonId values:
#   1 = KeyCompromise          3 = AffiliationChanged   4 = Superseded
#   5 = CessationOfOperation   9 = PrivilegeWithdrawn
# ---------------------------------------------------------------------------

REASON_ID ?= 1

revoke-order:
	@set -euo pipefail; \
	if [ -z "$(ORDER_NUMBER)" ]; then \
	  echo "Usage: make revoke-order ORDER_NUMBER=<order number> [REASON_ID=1]"; exit 1; \
	fi; \
	. ~/.env_certinext; \
	ts=$$(TZ=Asia/Kolkata date +%Y-%m-%dT%H:%M:%S+05:30); \
	txn=$$(python3 -c "import random; print(str(random.randint(1000000000000000,9999999999999999)))"); \
	authKey=$$(python3 -c "import hashlib,sys; print(hashlib.sha256((sys.argv[1]+sys.argv[2]+sys.argv[3]).encode()).hexdigest())" "$$CERTINEXT_ACCESS_KEY" "$$ts" "$$txn"); \
	echo "RevokeOrder  orderNumber=$(ORDER_NUMBER)  revokeReasonId=$(REASON_ID)  ts=$$ts  txn=$$txn"; \
	curl -s -X POST "$$CERTINEXT_API_URL/RevokeOrder" \
	     -H "Content-Type: application/json" \
	     -d "{\"meta\":{\"ver\":\"1.0\",\"ts\":\"$$ts\",\"txn\":\"$$txn\",\"accountNumber\":\"$$CERTINEXT_ACCOUNT_NUMBER\",\"authKey\":\"$$authKey\"},\"revocationDetails\":{\"orderNumber\":\"$(ORDER_NUMBER)\",\"requestorEmail\":\"$$CERTINEXT_REQUESTOR_EMAIL\",\"revokeReasonId\":\"$(REASON_ID)\",\"revokeRemarks\":\"Revoked via Makefile smoke test.\"}}" \
	| jq .

# ---------------------------------------------------------------------------
# SubmitCSR — POST {baseURL}SubmitCSR
# Attaches a CSR to a saveAndHold order — mirrors ICERTInextClient.SubmitCsrAsync
# Required: ORDER_NUMBER=<order number>  CSR_FILE=<path to PEM CSR file>
# ---------------------------------------------------------------------------

submit-csr:
	@set -euo pipefail; \
	if [ -z "$(ORDER_NUMBER)" ] || [ -z "$(CSR_FILE)" ]; then \
	  echo "Usage: make submit-csr ORDER_NUMBER=<order number> CSR_FILE=<path>"; exit 1; \
	fi; \
	if [ ! -f "$(CSR_FILE)" ]; then \
	  echo "CSR_FILE '$(CSR_FILE)' not found"; exit 1; \
	fi; \
	. ~/.env_certinext; \
	ts=$$(TZ=Asia/Kolkata date +%Y-%m-%dT%H:%M:%S+05:30); \
	txn=$$(python3 -c "import random; print(str(random.randint(1000000000000000,9999999999999999)))"); \
	authKey=$$(python3 -c "import hashlib,sys; print(hashlib.sha256((sys.argv[1]+sys.argv[2]+sys.argv[3]).encode()).hexdigest())" "$$CERTINEXT_ACCESS_KEY" "$$ts" "$$txn"); \
	echo "SubmitCSR  orderNumber=$(ORDER_NUMBER)  csrFile=$(CSR_FILE)  ts=$$ts  txn=$$txn"; \
	curl -s -X POST "$$CERTINEXT_API_URL/SubmitCSR" \
	     -H "Content-Type: application/json" \
	     -d "$$(jq -n \
	         --arg ver "1.0" --arg ts "$$ts" --arg txn "$$txn" \
	         --arg acct "$$CERTINEXT_ACCOUNT_NUMBER" --arg auth "$$authKey" \
	         --arg order "$(ORDER_NUMBER)" --arg email "$$CERTINEXT_REQUESTOR_EMAIL" \
	         --rawfile csr "$(CSR_FILE)" \
	         '{meta:{ver:$$ver,ts:$$ts,txn:$$txn,accountNumber:$$acct,authKey:$$auth}, \
	           orderDetails:{orderNumber:$$order,requestorEmail:$$email,csr:$$csr}}')" \
	| jq .

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

api-help:
	@echo ""
	@echo "CERTInext API smoke-test targets (credentials from ~/.env_certinext):"
	@echo ""
	@echo "  make ping"
	@echo "      ValidateCredentials — verify credentials are accepted"
	@echo ""
	@echo "  make get-product-details   (alias: products)"
	@echo "      GetProductDetails — list available certificate products"
	@echo ""
	@echo "  make get-order-report      (alias: orders)   [PAGE=1] [PAGE_SIZE=10]"
	@echo "      GetOrderReport — paginated order listing"
	@echo ""
	@echo "  make track-order           (alias: get-order)   ORDER_NUMBER=NNNNN"
	@echo "      TrackOrder — fetch current status for a specific order"
	@echo ""
	@echo "  make get-certificate       (alias: get-cert)    ORDER_NUMBER=NNNNN"
	@echo "      GetCertificate — download issued certificate PEM for an order"
	@echo ""
	@echo "  make generate-order   DOMAIN=example.com  [CSR_FILE=req.pem]  [VALIDITY=1]  [SAVE_AND_HOLD=1]"
	@echo "      GenerateOrderSSL — place a new SSL/TLS certificate order"
	@echo "      VALIDITY is subscription years: 1, 2, or 3 (default 1)"
	@echo "      SAVE_AND_HOLD=1 (default) saves as draft — returns requestNumber"
	@echo "      SAVE_AND_HOLD=0 submits immediately — returns orderNumber"
	@echo "      Prints requestNumber prominently on success (use with submit-csr)"
	@echo ""
	@echo "  make revoke-order   ORDER_NUMBER=NNNNN  [REASON_ID=1]"
	@echo "      RevokeOrder — revoke an issued certificate"
	@echo "      REASON_ID: 1=KeyCompromise 3=AffiliationChanged 4=Superseded"
	@echo "                 5=CessationOfOperation 9=PrivilegeWithdrawn"
	@echo ""
	@echo "  make submit-csr   ORDER_NUMBER=NNNNN  CSR_FILE=req.pem"
	@echo "      SubmitCSR — attach a CSR to a saveAndHold (draft) order"
	@echo ""
