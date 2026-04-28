SLN         := certinext-caplugin.sln
COVERAGE_DIR := /tmp/certinext-coverage
REPORT_DIR   := /tmp/certinext-coverage-report

# ---------------------------------------------------------------------------
# V2 API credentials — set CERTINEXT_V2_API_URL in ~/.env_certinext.
# For the sandbox environment this is the same host as V1 but without the
# /emSignHub-API/ suffix, e.g.:
#   CERTINEXT_V2_API_URL=https://sandbox-us.certinext.io
# ---------------------------------------------------------------------------

.PHONY: build test integration-test coverage coverage-report open-coverage clean \
        ping \
        get-product-details products \
        get-product-details-group \
        probe-products \
        generate-test-csr \
        get-order-report orders \
        track-order get-order \
        get-certificate get-cert \
        generate-order \
        revoke-order \
        submit-csr \
        list-cas \
        create-product \
        generate-order-igtf \
        generate-order-149-fresh \
        generate-order-private-pki \
        probe-endpoints \
        get-field-details \
        show-postman-bodies \
        show-postman-variables \
        probe-private-pki-payloads \
        api-help \
        v2-ping \
        v2-list-products \
        v2-get-custom-fields \
        v2-list-groups \
        v2-list-organizations \
        v2-list-domains \
        v2-create-ssl-order \
        v2-track-order \
        v2-get-dcv \
        v2-verify-dcv \
        v2-submit-csr \
        v2-accept-agreement \
        v2-download-certificate \
        v2-revoke-ssl \
        v2-cancel-ssl-order \
        v2-create-private-pki-order \
        v2-track-private-pki \
        v2-submit-csr-private-pki \
        v2-download-certificate-private-pki \
        v2-revoke-private-pki \
        v2-orders-report

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
# Each target delegates to a script under scripts/.
# The shared HMAC signing logic lives in scripts/lib/certinext-auth.sh.
# All JSON output is piped through jq for pretty-printing (inside the scripts).
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# ValidateCredentials — POST {baseURL}ValidateCredentials
# Health / connectivity probe — mirrors ICERTInextClient.PingAsync
# ---------------------------------------------------------------------------

ping:
	@scripts/ping.sh

# ---------------------------------------------------------------------------
# GetProductDetails — POST {baseURL}GetProductDetails
# Lists available product codes — mirrors ICERTInextClient.GetProductDetailsAsync
# Aliases: products
# ---------------------------------------------------------------------------

get-product-details products:
	@scripts/get-product-details.sh

# ---------------------------------------------------------------------------
# GetProductDetails with groupNumber — POST {baseURL}GetProductDetails
# Identical to get-product-details but explicitly passes groupNumber in the
# productDetails block, which is required by some sandbox accounts in order
# to receive any results.  Useful when the plain get-product-details target
# returns an empty list.
# ---------------------------------------------------------------------------

get-product-details-group:
	@scripts/get-product-details-group.sh

# ---------------------------------------------------------------------------
# generate-test-csr — generates a fresh RSA-2048 PKCS#10 CSR for
# CN=test-integration.example.com using openssl and writes it to
# /tmp/certinext-test.csr.  Used by probe-products and other smoke tests.
# ---------------------------------------------------------------------------

generate-test-csr:
	@openssl req -new -newkey rsa:2048 -nodes \
	    -subj "/CN=test-integration.example.com" \
	    -addext "subjectAltName=DNS:test-integration.example.com" \
	    -out /tmp/certinext-test.csr \
	    -keyout /tmp/certinext-test.key 2>/dev/null; \
	echo "CSR written to /tmp/certinext-test.csr"

# ---------------------------------------------------------------------------
# probe-products — places saveAndHold=1 draft orders for every SSL/TLS
# product code known to be provisioned on this sandbox account and reports
# which codes are accepted by GenerateOrderSSL.
#
# Product codes exercised (all SSL/TLS from GetProductDetails for this
# sandbox account with groupNumber=2171775848):
#   842 DV SSL Certificate
#   843 DV SSL Certificate Wildcard
#   844 DV SSL Certificate UCC
#   845 DV SSL Certificate Wildcard UCC
#   846 OV SSL Certificate
#   847 OV SSL Certificate Wildcard
#   848 OV SSL Certificate UCC
#   849 OV SSL Certificate Wildcard UCC
#   850 EV SSL Certificate
#   851 EV SSL Certificate UCC
#   149 Sandbox emSign Intranet SSL 1 Year (Private PKI)
# ---------------------------------------------------------------------------

PROBE_DOMAIN ?= test-integration.example.com

probe-products: generate-test-csr
	@PROBE_DOMAIN=$(PROBE_DOMAIN) scripts/probe-products.sh

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
	@PAGE=$(PAGE) PAGE_SIZE=$(PAGE_SIZE) scripts/get-order-report.sh

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
	@ORDER_NUMBER=$(ORDER_NUMBER) scripts/track-order.sh

# ---------------------------------------------------------------------------
# GetCertificate — POST {baseURL}GetCertificate
# Downloads the issued certificate PEM — mirrors ICERTInextClient.DownloadCertificateAsync
# Aliases: get-cert
# Required: ORDER_NUMBER=<order number>
# ---------------------------------------------------------------------------

get-certificate get-cert:
	@ORDER_NUMBER=$(ORDER_NUMBER) scripts/get-certificate.sh

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

DOMAIN        ?=
CSR_FILE      ?=
VALIDITY      ?= 1
SAVE_AND_HOLD ?= 1

generate-order:
	@DOMAIN=$(DOMAIN) CSR_FILE=$(CSR_FILE) VALIDITY=$(VALIDITY) SAVE_AND_HOLD=$(SAVE_AND_HOLD) CODE=$(CODE) scripts/generate-order.sh

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
	@ORDER_NUMBER=$(ORDER_NUMBER) REASON_ID=$(REASON_ID) scripts/revoke-order.sh

# ---------------------------------------------------------------------------
# SubmitCSR — POST {baseURL}SubmitCSR
# Attaches a CSR to a saveAndHold order — mirrors ICERTInextClient.SubmitCsrAsync
# Required: ORDER_NUMBER=<order number>  CSR_FILE=<path to PEM CSR file>
# ---------------------------------------------------------------------------

submit-csr:
	@ORDER_NUMBER=$(ORDER_NUMBER) CSR_FILE=$(CSR_FILE) scripts/submit-csr.sh

# ---------------------------------------------------------------------------
# list-cas — Sub-CA listing via API
#
# The CERTInext REST API does NOT expose a Sub-CA listing endpoint.
# All 18 candidate endpoint names return HTTP 404.
#
# Sub-CA information must be obtained via the sandbox portal UI at
# https://sandbox-us.certinext.io.  Active Sub-CAs for this account:
#   Name : emSign Issuing Sand box CA IGTF - C6
#   Type : Subordinate CA
#   Status : Active
#   (Backed by emSign Trusted Sandbox Root CA - C6)
#
# See analysis/certinext-caplugin/postman-api-findings.md for full details.
# ---------------------------------------------------------------------------

list-cas:
	@scripts/list-cas.sh

# ---------------------------------------------------------------------------
# create-product — Create a custom product via API
#
# The CERTInext REST API does NOT expose a product creation or configuration
# endpoint.  All 8 candidate endpoint names return HTTP 404.
#
# Products must be created via the sandbox portal UI at
# https://sandbox-us.certinext.io under:
#   Account → Products → Configure Product
#
# See analysis/certinext-caplugin/postman-api-findings.md for full details.
# ---------------------------------------------------------------------------

create-product:
	@scripts/create-product.sh

# ---------------------------------------------------------------------------
# generate-order-igtf — Place a Private PKI order using product 149
#
# Product 149 (Sandbox emSign Intranet SSL 1 Year) is the only Private PKI
# product provisioned on this sandbox account.  Product 108 (IGTF Host
# Certificate) is NOT provisioned here — GetFieldDetails returns EMS-1269.
#
# Uses GenerateOrderPrivatePKI.
# Required: CSR at /tmp/certinext-igtf-test.csr (run generate-test-csr first)
# Optional: IGTF_CSR_FILE=<path>  IGTF_DOMAIN=test-igtf.example.com  SAVE_AND_HOLD=1
# ---------------------------------------------------------------------------

IGTF_DOMAIN   ?= test-igtf.example.com
IGTF_CSR_FILE ?= /tmp/certinext-igtf-test.csr

generate-order-igtf: generate-test-csr
	@IGTF_CSR_FILE=$(IGTF_CSR_FILE) IGTF_DOMAIN=$(IGTF_DOMAIN) SAVE_AND_HOLD=$(SAVE_AND_HOLD) scripts/generate-order-igtf.sh

# ---------------------------------------------------------------------------
# generate-order-149-fresh — Place product-149 Private PKI order with a
# timestamp-unique CSR to avoid EMS-1099 duplicate-CSR rejection.
#
# Optional: SAVE_AND_HOLD=1  (default; use 0 to submit immediately)
# ---------------------------------------------------------------------------

generate-order-149-fresh:
	@SAVE_AND_HOLD=$(SAVE_AND_HOLD) scripts/generate-order-149-fresh.sh

# ---------------------------------------------------------------------------
# generate-order-private-pki — Place a Private PKI order for any product code
#
# Generic target for Private PKI orders.  Defaults to product 149 but accepts
# PRIVATE_PKI_CODE= override.  Uses GenerateOrderPrivatePKI.
#
# Optional: PRIVATE_PKI_CODE=149  PRIVATE_PKI_DOMAIN=...  PRIVATE_PKI_CSR=...  SAVE_AND_HOLD=1
# ---------------------------------------------------------------------------

PRIVATE_PKI_CODE   ?= 149
PRIVATE_PKI_DOMAIN ?= test-private-pki.example.com
PRIVATE_PKI_CSR    ?= /tmp/certinext-test.csr

generate-order-private-pki: generate-test-csr
	@PRIVATE_PKI_CODE=$(PRIVATE_PKI_CODE) PRIVATE_PKI_DOMAIN=$(PRIVATE_PKI_DOMAIN) PRIVATE_PKI_CSR=$(PRIVATE_PKI_CSR) SAVE_AND_HOLD=$(SAVE_AND_HOLD) scripts/generate-order-private-pki.sh

# ---------------------------------------------------------------------------
# probe-endpoints — Probe candidate product-management and CA-listing endpoints
#
# POSTs a minimal meta block to each of 18 candidate endpoint names and
# reports whether they exist (non-404) or not (404).  Wraps
# scripts/probe_endpoints.py.
#
# Result (confirmed 2026-04): ALL 18 candidates return HTTP 404.
# ---------------------------------------------------------------------------

probe-endpoints:
	@scripts/probe-endpoints.sh

# ---------------------------------------------------------------------------
# get-field-details — GetFieldDetails for a specific product code
#
# Returns the field definitions (mandatory / optional fields) for a product
# code so you know exactly what certificateInformation to include in an order.
#
# Optional: PRODUCT_CODE=149  CATEGORY_ID=8
# ---------------------------------------------------------------------------

PRODUCT_CODE ?= 149
CATEGORY_ID  ?= 8

get-field-details:
	@PRODUCT_CODE=$(PRODUCT_CODE) CATEGORY_ID=$(CATEGORY_ID) scripts/get-field-details.sh

# ---------------------------------------------------------------------------
# show-postman-bodies — Extract request bodies from the Postman collection
#
# Prints the full URL + request body for every endpoint in the Postman
# collection.  Use FILTER= to narrow output (case-insensitive substring).
#
# Examples:
#   make show-postman-bodies                        # print all
#   make show-postman-bodies FILTER="private pki"   # Private PKI only
#   make show-postman-bodies FILTER=igtf            # IGTF only
#   make show-postman-bodies FILTER=intranet        # Intranet SSL only
#
# Wraps scripts/extract_postman_bodies.py — run that script directly for
# additional options (--collection, etc.).
# ---------------------------------------------------------------------------

FILTER ?=

show-postman-bodies:
	@python3 /Users/sbailey/RiderProjects/certinext-caplugin/scripts/extract_postman_bodies.py \
	  --filter "$(FILTER)"

# ---------------------------------------------------------------------------
# show-postman-variables — Extract collection-level variable values
#
# Resolves variable names like {{PrivatePKI_IntranetSSL}}, {{SSL_DV}}, etc.
# to their concrete values as stored in the Postman collection.
# Wraps scripts/extract_postman_variables.py
# ---------------------------------------------------------------------------

show-postman-variables:
	@python3 /Users/sbailey/RiderProjects/certinext-caplugin/scripts/extract_postman_variables.py

# ---------------------------------------------------------------------------
# probe-private-pki-payloads — Try three payload variants for
# GenerateOrderPrivatePKI with product 149.
#
# Tests Postman-minimal, +agreementDetails, and +delegationInformation
# to isolate which payload structure the server accepts without EMS-939.
#
# Optional: DOMAIN=...  PRODUCT_CODE=149  SAVE_AND_HOLD=0
# Wraps scripts/order_private_pki_minimal.py
# ---------------------------------------------------------------------------

probe-private-pki-payloads: generate-test-csr
	@python3 /Users/sbailey/RiderProjects/certinext-caplugin/scripts/order_private_pki_minimal.py \
	  --csr /tmp/certinext-test.csr \
	  --domain "$(IGTF_DOMAIN)" \
	  --product "$(PRIVATE_PKI_CODE)" \
	  --save-and-hold "$(SAVE_AND_HOLD)"

# ---------------------------------------------------------------------------
# V2 API targets  (credentials + CERTINEXT_V2_API_URL from ~/.env_certinext)
#
# Auth: scripts/lib/certinext-v2-auth.sh exchanges SHA256(accessKey+ts+txn)
# for a short-lived Bearer JWT at POST {v2BaseURL}/oauth/token.  All V2
# scripts source that lib automatically — no manual token step needed.
#
# Scripts live in scripts/v2/.  Each script sources ~/.env_certinext and
# scripts/lib/certinext-v2-auth.sh; jq is used for JSON construction and
# pretty-printing.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# v2-ping — GET /api/certinext/v2/auth/me
# Connectivity + auth check; returns the account context the token resolves to.
# Mirrors ICERTInextClient.PingAsync via the V2 API.
# ---------------------------------------------------------------------------

v2-ping:
	@echo "V2 ping — GET /api/certinext/v2/auth/me"
	@scripts/v2/ping.sh

# ---------------------------------------------------------------------------
# v2-list-products — GET /api/certinext/v2/catalog/products
# Lists every SSL / Document Signer / Private PKI product the account can order.
# Each entry carries a stable productCode used as the X-Product-Code header.
# ---------------------------------------------------------------------------

v2-list-products:
	@echo "V2 list products — GET /api/certinext/v2/catalog/products"
	@scripts/v2/list-products.sh

# ---------------------------------------------------------------------------
# v2-get-custom-fields — GET /api/certinext/v2/catalog/products/{code}/custom-fields
# Returns mandatory + optional custom fields for a product code.
# Required: PRODUCT_CODE=<code>
# ---------------------------------------------------------------------------

V2_PRODUCT_CODE ?= 842

v2-get-custom-fields:
	@echo "V2 get custom fields — GET /api/certinext/v2/catalog/products/$(V2_PRODUCT_CODE)/custom-fields"
	@PRODUCT_CODE=$(V2_PRODUCT_CODE) scripts/v2/get-custom-fields.sh

# ---------------------------------------------------------------------------
# v2-list-groups — GET /api/certinext/v2/groups
# Lists billing groups accessible to this account.
# Use a groupNumber in order bodies to charge a specific cost centre.
# ---------------------------------------------------------------------------

v2-list-groups:
	@echo "V2 list groups — GET /api/certinext/v2/groups"
	@scripts/v2/list-groups.sh

# ---------------------------------------------------------------------------
# v2-list-organizations — GET /api/certinext/v2/organizations
# Lists pre-vetted organizations available for OV/EV SSL orders.
# Reference an organizationNumber in order bodies to skip re-vetting.
# ---------------------------------------------------------------------------

v2-list-organizations:
	@echo "V2 list organizations — GET /api/certinext/v2/organizations"
	@scripts/v2/list-organizations.sh

# ---------------------------------------------------------------------------
# v2-list-domains — GET /api/certinext/v2/domains
# Lists domains already pre-validated under this account.
# DCV does not need to be repeated for domains in this list.
# ---------------------------------------------------------------------------

v2-list-domains:
	@echo "V2 list domains — GET /api/certinext/v2/domains"
	@scripts/v2/list-domains.sh

# ---------------------------------------------------------------------------
# v2-create-ssl-order — POST /api/certinext/v2/ssl-certificates
# Places a new SSL/TLS certificate order.
# Required: PRODUCT_CODE=<code>  DOMAIN=<domain>
# Optional: VARIANT=dv (also: ov, ev)
#
# Prints orderId on success.  Use orderId with v2-track-order, v2-get-dcv,
# v2-verify-dcv, v2-submit-csr, v2-accept-agreement, v2-download-certificate,
# v2-revoke-ssl, and v2-cancel-ssl-order.
# ---------------------------------------------------------------------------

V2_DOMAIN  ?=
V2_VARIANT ?= dv

v2-create-ssl-order:
	@echo "V2 create SSL order — POST /api/certinext/v2/ssl-certificates"
	@PRODUCT_CODE=$(V2_PRODUCT_CODE) DOMAIN=$(V2_DOMAIN) VARIANT=$(V2_VARIANT) scripts/v2/create-ssl-order.sh

# ---------------------------------------------------------------------------
# v2-track-order — GET /api/certinext/v2/ssl-certificates/{orderId}
# Fetches current state of an SSL order.
# Required: ORDER_ID=<orderId>
#
# Status sequence: pending-dcv -> pending-csr -> pending-agreement -> issued
# (or cancelled / revoked)
# ---------------------------------------------------------------------------

ORDER_ID ?=

v2-track-order:
	@echo "V2 track SSL order — GET /api/certinext/v2/ssl-certificates/$(ORDER_ID)"
	@ORDER_ID=$(ORDER_ID) scripts/v2/track-order.sh

# ---------------------------------------------------------------------------
# v2-get-dcv — GET /api/certinext/v2/ssl-certificates/{orderId}/dcv?domain={domain}
# Returns DCV challenge artifacts (http-url, dns-txt, email) for a domain.
# Required: ORDER_ID=<orderId>  DOMAIN=<domain>
# ---------------------------------------------------------------------------

v2-get-dcv:
	@echo "V2 get DCV challenges — GET /api/certinext/v2/ssl-certificates/$(ORDER_ID)/dcv"
	@ORDER_ID=$(ORDER_ID) DOMAIN=$(V2_DOMAIN) scripts/v2/get-dcv.sh

# ---------------------------------------------------------------------------
# v2-verify-dcv — POST /api/certinext/v2/ssl-certificates/{orderId}/dcv/verify
# Asks the CA to re-check the DCV artifact you published.
# Required: ORDER_ID=<orderId>  DOMAIN=<domain>
# Optional: METHOD=http-url  (also: dns-txt, email)
# ---------------------------------------------------------------------------

V2_DCV_METHOD ?= http-url

v2-verify-dcv:
	@echo "V2 verify DCV — POST /api/certinext/v2/ssl-certificates/$(ORDER_ID)/dcv/verify"
	@ORDER_ID=$(ORDER_ID) DOMAIN=$(V2_DOMAIN) METHOD=$(V2_DCV_METHOD) scripts/v2/verify-dcv.sh

# ---------------------------------------------------------------------------
# v2-submit-csr — PUT /api/certinext/v2/ssl-certificates/{orderId}/csr
# Attaches a PEM CSR to an SSL order.
# Required: ORDER_ID=<orderId>  CSR_FILE=<path to PEM file>
# ---------------------------------------------------------------------------

V2_CSR_FILE ?=

v2-submit-csr:
	@echo "V2 submit CSR (SSL) — PUT /api/certinext/v2/ssl-certificates/$(ORDER_ID)/csr"
	@ORDER_ID=$(ORDER_ID) CSR_FILE=$(V2_CSR_FILE) scripts/v2/submit-csr.sh

# ---------------------------------------------------------------------------
# v2-accept-agreement — POST /api/certinext/v2/ssl-certificates/{orderId}/agreement
# Records Subscriber Agreement acceptance.  The CA proceeds to issue after this.
# Required: ORDER_ID=<orderId>
# ---------------------------------------------------------------------------

v2-accept-agreement:
	@echo "V2 accept agreement — POST /api/certinext/v2/ssl-certificates/$(ORDER_ID)/agreement"
	@ORDER_ID=$(ORDER_ID) scripts/v2/accept-agreement.sh

# ---------------------------------------------------------------------------
# v2-download-certificate — GET /api/certinext/v2/ssl-certificates/{orderId}/certificate
# Downloads the issued SSL certificate (JSON with PEM, serial, subject, validity).
# Required: ORDER_ID=<orderId>
# ---------------------------------------------------------------------------

v2-download-certificate:
	@echo "V2 download certificate (SSL) — GET /api/certinext/v2/ssl-certificates/$(ORDER_ID)/certificate"
	@ORDER_ID=$(ORDER_ID) scripts/v2/download-certificate.sh

# ---------------------------------------------------------------------------
# v2-revoke-ssl — POST /api/certinext/v2/ssl-certificates/{orderId}/revoke
# Permanently revokes an issued SSL certificate.
# Required: ORDER_ID=<orderId>
# Optional: REASON=superseded
#
# RFC 5280 reason values: unspecified, keyCompromise, caCompromise,
#   affiliationChanged, superseded, cessationOfOperation, privilegeWithdrawn
# ---------------------------------------------------------------------------

V2_REASON ?= superseded

v2-revoke-ssl:
	@echo "V2 revoke SSL — POST /api/certinext/v2/ssl-certificates/$(ORDER_ID)/revoke"
	@ORDER_ID=$(ORDER_ID) REASON=$(V2_REASON) scripts/v2/revoke-ssl.sh

# ---------------------------------------------------------------------------
# v2-cancel-ssl-order — POST /api/certinext/v2/ssl-certificates/{orderId}/cancel
# Withdraws an SSL order before issuance.  Use v2-revoke-ssl after issuance.
# Required: ORDER_ID=<orderId>
# ---------------------------------------------------------------------------

v2-cancel-ssl-order:
	@echo "V2 cancel SSL order — POST /api/certinext/v2/ssl-certificates/$(ORDER_ID)/cancel"
	@ORDER_ID=$(ORDER_ID) scripts/v2/cancel-ssl-order.sh

# ---------------------------------------------------------------------------
# v2-create-private-pki-order — POST /api/certinext/v2/private-pki-certificates
# Creates a Private PKI certificate order against a customer-owned CA.
# Required: PRODUCT_CODE=<code>  HOSTNAME=<host>  CA_PROFILE_ID=<id>  MASTER_PRODUCT_ID=<id>
#
# Prints orderId on success.  Use orderId with v2-track-private-pki,
# v2-submit-csr-private-pki, v2-download-certificate-private-pki, and
# v2-revoke-private-pki.
# ---------------------------------------------------------------------------

V2_HOSTNAME         ?=
V2_CA_PROFILE_ID    ?=
V2_MASTER_PRODUCT_ID ?=

v2-create-private-pki-order:
	@echo "V2 create Private PKI order — POST /api/certinext/v2/private-pki-certificates"
	@PRODUCT_CODE=$(V2_PRODUCT_CODE) HOSTNAME=$(V2_HOSTNAME) CA_PROFILE_ID=$(V2_CA_PROFILE_ID) MASTER_PRODUCT_ID=$(V2_MASTER_PRODUCT_ID) scripts/v2/create-private-pki-order.sh

# ---------------------------------------------------------------------------
# v2-track-private-pki — GET /api/certinext/v2/private-pki-certificates/{orderId}
# Fetches current state of a Private PKI order.
# Required: ORDER_ID=<orderId>
#
# Status sequence: pending-csr -> issued (or cancelled / revoked)
# ---------------------------------------------------------------------------

v2-track-private-pki:
	@echo "V2 track Private PKI order — GET /api/certinext/v2/private-pki-certificates/$(ORDER_ID)"
	@ORDER_ID=$(ORDER_ID) scripts/v2/track-private-pki.sh

# ---------------------------------------------------------------------------
# v2-submit-csr-private-pki — PUT /api/certinext/v2/private-pki-certificates/{orderId}/csr
# Attaches a PEM CSR to a Private PKI order.  The customer CA signs immediately.
# Required: ORDER_ID=<orderId>  CSR_FILE=<path to PEM file>
# ---------------------------------------------------------------------------

v2-submit-csr-private-pki:
	@echo "V2 submit CSR (Private PKI) — PUT /api/certinext/v2/private-pki-certificates/$(ORDER_ID)/csr"
	@ORDER_ID=$(ORDER_ID) CSR_FILE=$(V2_CSR_FILE) scripts/v2/submit-csr-private-pki.sh

# ---------------------------------------------------------------------------
# v2-download-certificate-private-pki — GET /api/certinext/v2/private-pki-certificates/{orderId}/certificate
# Downloads the issued Private PKI certificate.
# Required: ORDER_ID=<orderId>
# ---------------------------------------------------------------------------

v2-download-certificate-private-pki:
	@echo "V2 download certificate (Private PKI) — GET /api/certinext/v2/private-pki-certificates/$(ORDER_ID)/certificate"
	@ORDER_ID=$(ORDER_ID) scripts/v2/download-certificate-private-pki.sh

# ---------------------------------------------------------------------------
# v2-revoke-private-pki — POST /api/certinext/v2/private-pki-certificates/{orderId}/revoke
# Permanently revokes an issued Private PKI certificate.
# Required: ORDER_ID=<orderId>
# Optional: REASON=superseded
#
# RFC 5280 reason values: unspecified, keyCompromise, affiliationChanged,
#   superseded, cessationOfOperation, privilegeWithdrawn
# ---------------------------------------------------------------------------

v2-revoke-private-pki:
	@echo "V2 revoke Private PKI — POST /api/certinext/v2/private-pki-certificates/$(ORDER_ID)/revoke"
	@ORDER_ID=$(ORDER_ID) REASON=$(V2_REASON) scripts/v2/revoke-private-pki.sh

# ---------------------------------------------------------------------------
# v2-orders-report — GET /api/certinext/v2/reports/orders?page=0&size=50
# Paginated order history across all product types.
# NOTE: currently returns 501 Not Implemented.
# Use v1 make get-order-report (POST /emSignHub-API/GetOrderReport) meanwhile.
# ---------------------------------------------------------------------------

v2-orders-report:
	@echo "V2 orders report — GET /api/certinext/v2/reports/orders (NOTE: currently 501)"
	@scripts/v2/orders-report.sh

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
	@echo "      Note: some sandbox accounts require groupNumber to return results."
	@echo "      Use get-product-details-group if this target returns an empty list."
	@echo ""
	@echo "  make get-product-details-group"
	@echo "      GetProductDetails — same as get-product-details but explicitly passes"
	@echo "      groupNumber from CERTINEXT_GROUP_NUMBER.  Use this when the plain"
	@echo "      get-product-details target returns an empty list."
	@echo ""
	@echo "  make generate-test-csr"
	@echo "      Generate a fresh RSA-2048 CSR for CN=test-integration.example.com"
	@echo "      and write it to /tmp/certinext-test.csr.  Required by probe-products."
	@echo ""
	@echo "  make probe-products   [PROBE_DOMAIN=test-integration.example.com]"
	@echo "      Place saveAndHold=1 draft orders for all SSL/TLS product codes"
	@echo "      provisioned on the sandbox account (842–851, 149) and report which"
	@echo "      codes are accepted.  A code returning a requestNumber is valid."
	@echo "      Depends on generate-test-csr (called automatically)."
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
	@echo "  make list-cas"
	@echo "      Document that no Sub-CA listing endpoint exists in the CERTInext API."
	@echo "      CA information must be obtained via the sandbox portal UI."
	@echo ""
	@echo "  make create-product"
	@echo "      Document that no product management (create/configure) endpoint exists"
	@echo "      in the CERTInext REST API.  Products must be created via the portal UI."
	@echo ""
	@echo "  make generate-order-igtf   [IGTF_CSR_FILE=/tmp/certinext-igtf-test.csr]"
	@echo "      GenerateOrderPrivatePKI — place a Private PKI order using product 149"
	@echo "      (Sandbox emSign Intranet SSL, the only active Private PKI product on this"
	@echo "      sandbox account).  Uses saveAndHold=1 by default."
	@echo "      NOTE: product 108 (IGTF Host) is not provisioned on this account."
	@echo ""
	@echo "  make generate-order-private-pki   [PRIVATE_PKI_CSR=...] [PRIVATE_PKI_DOMAIN=...] [PRIVATE_PKI_CODE=149]"
	@echo "      GenerateOrderPrivatePKI — place a Private PKI order for any product code."
	@echo "      Defaults to product 149.  Use PRIVATE_PKI_CODE= to override."
	@echo ""
	@echo "  make probe-endpoints"
	@echo "      POST a minimal meta block to every candidate product-management and"
	@echo "      CA-listing endpoint name.  404 = does not exist.  Any other response"
	@echo "      (including an application errorCode) = endpoint exists."
	@echo ""
	@echo "  make get-field-details   [PRODUCT_CODE=149] [CATEGORY_ID=8]"
	@echo "      GetFieldDetails — return the field definition for a product code."
	@echo "      Shows which certificateInformation fields are mandatory vs optional."
	@echo ""
