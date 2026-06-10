# CERTInext API Findings — Postman Collection + Live Sandbox Exploration

Generated: 2026-04-22. Updated: 2026-04-22 (product management probe, IGTF order test, Private PKI auto-issuance investigation). Source: `~/Downloads/CERTInext APIs.postman_collection.json` + live calls against sandbox account `9374221333`.

---

## Product Codes Are Global Per Environment, Not Per-Account

Product codes are the same for all accounts within the same environment. The Postman collection is the authoritative reference.

### Sandbox Product Codes

| Product Name | Code |
|---|---|
| DV SSL Certificate 1 Year | **842** |
| DV SSL Certificate Wildcard 1 Year | **843** |
| DV SSL Certificate UCC 1 Year | **844** |
| DV SSL Certificate Wildcard UCC 1 Year | **845** |
| OV SSL Certificate 1 Year | **846** |
| OV SSL Certificate Wildcard 1 Year | **847** |
| OV SSL Certificate UCC 1 Year | **848** |
| OV SSL Certificate Wildcard UCC 1 Year | **849** |
| EV SSL Certificate 1 Year | **850** |
| EV SSL Certificate UCC 1 Year | **851** |
| emSign Intranet SSL 1 Year (Private PKI) | **104** |
| IGTF Host Certificate 1 Year | **108** |
| emSign S/MIME Simple MV-S 1 Year | **914** |
| emSign Natural Person NonRepudiation 1/2/3 Year | **825 / 826 / 827** |
| emSign Legal Person NonRepudiation 1/2/3 Year | **822 / 823 / 824** |
| emSign Legal Entity NonRepudiation 1/2/3 Year | **819 / 820 / 821** |

### Production Product Codes

| Product Name | Code |
|---|---|
| DV SSL Certificate 1 Year | **838** |
| DV SSL Certificate Wildcard 1 Year | **839** |
| DV SSL Certificate UCC 1 Year | **840** |
| DV SSL Certificate Wildcard UCC 1 Year | **841** |
| OV SSL Certificate 1 Year | **842** |
| OV SSL Certificate Wildcard 1 Year | **843** |
| OV SSL Certificate UCC 1 Year | **844** |
| OV SSL Certificate Wildcard UCC 1 Year | **845** |
| EV SSL Certificate 1 Year | **846** |
| EV SSL Certificate UCC 1 Year | **847** |
| emSign Intranet SSL 1 Year (Private PKI) | **100** |
| IGTF Host Certificate 1 Year | **104** |
| emSign S/MIME Simple MV-S 1 Year | **894** |
| emSign Natural Person NonRepudiation 1/2/3 Year | **825 / 826 / 827** |
| emSign Legal Person NonRepudiation 1/2/3 Year | **822 / 823 / 824** |
| emSign Legal Entity NonRepudiation 1/2/3 Year | **819 / 820 / 821** |

**Note**: Codes `819–827` (signing certificates) are the same in both environments.

**Implication for the plugin**: `DefaultProductCode` in `CERTInextConfig` and the `ProfileId` template parameter must use the code appropriate for the target environment. The plugin docs should reference this table rather than hard-coding any specific code.

---

## Endpoints Discovered from Postman Collection

All endpoints are `POST` with a JSON body containing a `meta` auth block.

### Order Lifecycle Endpoints

| Endpoint | Purpose | Notes |
|---|---|---|
| `GenerateOrderSSL` | Place a new DV/OV/EV SSL order | Includes CSR, agreement block, org details |
| `GenerateOrderSMIME` | Place a new S/MIME order | |
| `GenerateOrderSignature` | Place a signing certificate order | |
| `GenerateOrderPrivatePKI` | Place a Private PKI / Intranet SSL order | Separate endpoint from `GenerateOrderSSL` — product 104/100 does NOT work via `GenerateOrderSSL` |
| `SubmitCSR` | Submit CSR to an existing draft order | Used when `saveAndHold:"1"` at placement |
| `SubmitDocument` | Submit validation documents | |
| `TrackOrder` | Poll order/certificate status | Returns `certificateStatusId`, `domainVerification`, `subscriberAgreement` blocks |
| `RejectOrder` | Cancel/reject an order by `orderNumber` | |
| `RejectRequest` | Cancel/reject a request by `requestNumber` | For draft (on-hold) orders that have no `orderNumber` yet |
| `AgreementAcceptance` | Submit subscriber agreement acceptance | See below |

### Certificate Endpoints

| Endpoint | Purpose |
|---|---|
| `GetCertificate` | Download issued certificate (PEM) |
| `RevokeOrder` | Revoke by `orderNumber` + reason code |

### Account / Discovery Endpoints

| Endpoint | Purpose | Notes |
|---|---|---|
| `ValidateCredentials` | Ping / auth check | |
| `GetProductDetails` | List available products | Requires `groupNumber` in `productDetails` block for some accounts |
| `GetFieldDetails` | Get required fields per product code | Takes `groupNumber` + `categoryID` + `productCode` — use to discover required order fields |
| `GetGroupDetails` | Get group info | |
| `GetGroupDetailsV2` | Updated group info endpoint | |
| `GetOrganizationDetails` | Get org info | |
| `GetDomainDetails` | Get pre-validated domains | |
| `GetOrderReport` | Paginated order/cert listing | Used for sync |

### DCV Endpoints

| Endpoint | Purpose |
|---|---|
| `GetDcv` | Get DCV token/instructions for a domain |
| `VerifyDcv` | Trigger DCV verification |

**Important**: `dcvMethod` is a **numeric string**, not a word. The Postman collection uses `"3"`. The numeric codes are not yet fully mapped — ask eMudhra for the complete enum.

---

## AgreementAcceptance — How Subscriber Agreement Works

`AgreementAcceptance` is the endpoint for accepting the CERTInext subscriber agreement on a placed order.

**Request body:**
```json
{
  "meta": { ... },
  "agreementDetails": {
    "requestorEmail": "plugin-test@keyfactor.com",
    "orderNumber": "6655828778",
    "acceptAgreement": "1",
    "signerName": "Keyfactor Plugin Test",
    "signerPlace": "Gateway",
    "signerIP": "99.102.196.148"  ← must be the real public IP, not 127.0.0.1
  }
}
```

**Key findings from live testing:**
- The agreement is **automatically accepted** during `GenerateOrderSSL` when the order includes a populated `agreementDetails` block — the API returns `EMS-1082 Agreement already signed` if you call `AgreementAcceptance` afterwards.
- `signerIP` must be the **real public IP** of the calling machine — `127.0.0.1` returns `EMS-1091 Invalid Signer IP`.
- The `consentSentTo` email in `TrackOrder` is set to the **connector-level requestor email** (`sean.bailey@keyfactor.com` in testing), not the template-level email. The plugin should ensure the correct email is in the agreement block.
- A `trackingUrl` is returned in `TrackOrder` — a public link the subscriber can use to review/accept the agreement manually if needed.

**Plugin implication**: The `agreementDetails` block in `GenerateOrderSSL` already handles acceptance. `AgreementAcceptance` is only needed for orders placed without an agreement block (e.g., draft orders without signer details). The `AutoApprove` template parameter in the plugin currently does nothing (`autoApprove` is passed to `BuildEnrollmentResult` but never used) — if it was intended to call `AgreementAcceptance`, that logic is missing.

---

## Product Management API — Does Not Exist

**Confirmed 2026-04-22**: The CERTInext REST API has no product creation, configuration, or management endpoints.

All 18 candidate endpoint names were probed via POST with a minimal meta block. All returned HTTP 404:

| Endpoint name | Result |
|---|---|
| `ConfigureProduct` | 404 — not found |
| `CreateProduct` | 404 — not found |
| `AddProduct` | 404 — not found |
| `RegisterProduct` | 404 — not found |
| `GetProductConfiguration` | 404 — not found |
| `UpdateProduct` | 404 — not found |
| `DeleteProduct` | 404 — not found |
| `AddCertificateProfile` | 404 — not found |
| `CreateCertificateProfile` | 404 — not found |
| `ConfigureCertificate` | 404 — not found |
| `AddCertificateTemplate` | 404 — not found |
| `GetCAList` | 404 — not found |
| `ListCAs` | 404 — not found |
| `GetSubCAList` | 404 — not found |
| `GetCADetails` | 404 — not found |
| `GetPrivateCAList` | 404 — not found |
| `ListSubCAs` | 404 — not found |
| `GetIssuerList` | 404 — not found |

**Products and Sub-CA assignments must be configured via the portal UI** at `https://sandbox-us.certinext.io` under Account → Products → Configure Product.

The portal UI "Configure Product" form has the following fields (confirmed from the portal):
- Product Name (required)
- Subordinate CA (dropdown — only active Sub-CAs appear)
- Validity In Days (required)
- Key Algorithm (RSA 2048/3072/4096, ECC P256/P384, PQC variants)
- Description (required)
- Subject Attributes (OID → Request Field mapping)
- SAN Attributes
- Extensions
- Advanced Settings → "Automatically approve the certificate requests"

To create a custom auto-approving Private PKI product, this must be done manually in the portal.  The product code assigned by the portal can then be used with `GenerateOrderPrivatePKI` in the plugin.

---

## Sub-CA Listing — No API Endpoint

**Confirmed 2026-04-22**: There is no Sub-CA or CA listing endpoint in the CERTInext REST API. Sub-CA information must be obtained from the portal UI.

Sub-CAs visible in the sandbox portal for account `9374221333`:

| Name | Type | Status |
|---|---|---|
| Test CAk81 | Root CA | Active |
| Test Root emCA1 | Root CA | Pending |
| emSign Trusted Root CA - C5 | Root CA | Active |
| emSign Sandbox Issuing CA - G1 | Subordinate CA | **Revoked** — likely cause of DV SSL issuance failures |
| eMudhra Sandbox Private Root CA G1 | Root CA | Active |
| **emSign Issuing Sand box CA IGTF - C6** | Subordinate CA | **Active** — only active Sub-CA |
| emSign Trusted Sandbox Root CA - C6 | Root CA | Active |
| Test CA | Root CA | Active |

The only active Sub-CA on this account is `emSign Issuing Sand box CA IGTF - C6`.  Any new product created via the portal must use this Sub-CA until `emSign Sandbox Issuing CA - G1` is replaced or a new Sub-CA is provisioned.

---

## IGTF Product (108) — Not Provisioned on This Account

**Confirmed 2026-04-22**: Product 108 (IGTF Host Certificate) does not appear in `GetProductDetails` for this account, and `GetFieldDetails` with `categoryID=8, productCode=108` returns `EMS-1269: This product is not mapped to this group number`.

The Postman collection references product code `{{PrivatePKI_IGTF}}` for `GenerateOrderPrivatePKI`, suggesting this product exists on eMudhra's global product catalogue but has not been provisioned for group `2171775848`.

This is consistent with the earlier finding that product `104` (emSign Intranet SSL) was also not provisioned. Product `149` (Sandbox emSign Intranet SSL 1 Year) is the only Private PKI product on this account.

---

## Product 149 (Private PKI) — Auto-Issuance Status

**Confirmed 2026-04-22**: Product 149 (`Sandbox emSign Intranet SSL 1 Year`) accepts draft orders (`saveAndHold=1`) but **does NOT auto-issue**. Orders sit in "Pending for Approver" / "On Hold".

### Test results

All payloads tested with `GenerateOrderPrivatePKI`:

| Variant | `saveAndHold` | Result |
|---|---|---|
| Minimal (no agreement, no accountingModel) | `0` | `EMS-939: Something went Wrong` |
| With `agreementDetails` | `0` | `EMS-939: Something went Wrong` |
| With `delegationInformation` | `0` | `EMS-939: Something went Wrong` |
| Minimal (Postman-style) | `1` | Success — `requestNumber=7314663138` |
| Minimal | `1` | Success — `requestNumber=5668336671` |

**`saveAndHold=0` always fails with EMS-939 for product 149** regardless of payload shape. This is a server-side constraint, not a payload structure issue.

**Draft orders (`saveAndHold=1`) for product 149 land in `GetOrderReport` as:**
```
orderStatus:        "On Hold"
certificateStatus:  "Pending for Approver"
orderNumber:        (blank — no orderNumber until formally submitted)
issuerCA:           (blank)
```

This means auto-approval is **not** enabled for product 149 in the portal. The portal's "Automatically approve the certificate requests" toggle is off for this product. Orders cannot be auto-issued via the API until:
1. The portal setting is enabled for product 149 by an account admin, OR
2. A new product is created via the portal with auto-approval ON.

### Workaround

Use the portal at `https://sandbox-us.certinext.io` to:
1. Locate product 149 under Account → Products.
2. Edit it and enable "Automatically approve the certificate requests" under Advanced Settings.
3. Re-run `make generate-order-igtf` or `make generate-order-private-pki` to verify auto-issuance.

Alternatively, create a new product via the portal (see "Product Management API — Does Not Exist" above) with auto-approval ON, backed by `emSign Issuing Sand box CA IGTF - C6`, and update `CERTINEXT_PRODUCT_CODE` in `~/.env_certinext`.

---

## Why DV SSL Orders Are Stuck on This Sandbox Account

All 8 "Pending for Approver" orders show:
- `certificateStatusId: 24` = `PendingForApproverAutoApproval`
- `domainVerification.status: "0"` — DCV not completed
- `subscriberAgreement.status: "1"` — agreement already signed at order placement

The orders are blocked because `test-integration.example.com` is a non-real domain — DCV via DNS, HTTP file, or email cannot complete for it. The order cannot advance to issued state without DCV.

**To unblock integration tests**, one of the following is needed (in order of preference):

1. **Enable auto-approval on product 149** — log in to the portal as account admin, edit product 149, enable "Automatically approve the certificate requests" under Advanced Settings. Then `make generate-order-igtf` should auto-issue. This requires no eMudhra support involvement.

2. **Create a new Private PKI product via the portal** with auto-approval ON, backed by `emSign Issuing Sand box CA IGTF - C6`. Use the resulting product code in `~/.env_certinext` as `CERTINEXT_PRODUCT_CODE` and test with `make generate-order-private-pki PRIVATE_PKI_CODE=<new_code>`.

3. **Request IGTF product (108) provisioning** — ask eMudhra to add product `108` (IGTF Host Certificate) to group `2171775848`. If that product has auto-approval ON by default, it would immediately unblock the integration tests.

4. **Use a real domain you control** — place DV SSL orders (products 842–851) using a domain where you can create DNS records or serve HTTP files to complete DCV.

5. **Use the sandbox portal** to manually approve and issue certificates — the approver login at `https://sandbox-us.certinext.io` can advance orders for testing purposes.

**Product `104` (emSign Intranet SSL) is not provisioned on account `9374221333`** and product `108` (IGTF Host) is also not provisioned. Product `149` is provisioned but auto-approval is off. This is the most important configuration item to resolve, either via portal self-service or eMudhra support.

---

## AutoApprove Plugin Parameter — Currently Dead Code

`Constants.EnrollmentParam.AutoApprove` and `ep.AutoApprove` exist and are passed to `BuildEnrollmentResult(resp, ep.AutoApprove)`, but the `autoApprove` parameter is never used inside that method. It was presumably intended to call `AgreementAcceptance` after enrollment for accounts that require a separate acceptance step, but the implementation was never completed.

**To implement**: After a successful `GenerateOrderSSL` that returns `certificateStatusId: 24` (PendingForApproverAutoApproval), call `AgreementAcceptance` with the returned `orderNumber` and the signer details from the connector config. Only do this when `ep.AutoApprove == true`.

The `signerIP` must be the real public IP — consider auto-detecting via `https://api.ipify.org` (already referenced in the Makefile) or making it a connector config field.

---

## `GetProductDetails` Requires `groupNumber`

Calling `GetProductDetails` without a `groupNumber` in the `productDetails` block returns an empty list on some accounts. The fix (already in the plugin as of `fix/p1-p3-improvements`) passes `_config.GroupNumber` when set. `GroupNumber` is now a connector config field.

This appears to be account-specific behavior — some accounts require it, others don't. Always pass it when available.

---

## Makefile Targets Added (2026-04-22)

All targets are in `/Users/sbailey/RiderProjects/certinext-caplugin/Makefile` and load credentials from `~/.env_certinext`.

| Target | Description |
|---|---|
| `make list-cas` | Documents that no Sub-CA listing API exists; probes 3 endpoint names to confirm; prints known active Sub-CAs from portal UI |
| `make create-product` | Documents that no product management API exists; probes 3 endpoint names; prints step-by-step portal instructions to create an auto-approving product |
| `make generate-order-igtf` | Places a `GenerateOrderPrivatePKI` order for product 149 (IGTF-equivalent); `SAVE_AND_HOLD=0` submits, `SAVE_AND_HOLD=1` drafts |
| `make generate-order-private-pki` | Same as above but accepts `PRIVATE_PKI_CODE=` for any product code |
| `make probe-endpoints` | POSTs minimal meta to all 18 candidate endpoint names; reports 404 vs. any other response |
| `make get-field-details [PRODUCT_CODE=149] [CATEGORY_ID=8]` | Calls `GetFieldDetails` for any product code to get field definitions |
| `make show-postman-bodies [FILTER=keyword]` | Extracts request bodies from the Postman collection; filter by keyword |
| `make probe-private-pki-payloads` | Tests 3 payload variants for `GenerateOrderPrivatePKI` to isolate EMS-939 root cause |

Supporting scripts (in `scripts/`):
- `scripts/probe_endpoints.py` — backs `probe-endpoints`
- `scripts/probe_private_pki.py` — standalone private PKI probe
- `scripts/order_private_pki_minimal.py` — backs `probe-private-pki-payloads`
- `scripts/get_field_details.py` — backs `get-field-details`
- `scripts/extract_postman_bodies.py` — backs `show-postman-bodies`

---

## `GetProductDetails` — Provisioned Products for This Account

`GetProductDetails` with `groupNumber=2171775848` returns the following products (confirmed 2026-04-22):

| Category | Product Code | Product Name |
|---|---|---|
| Document Signer | 810 | Softnet Natural Person Certificate - Soft Token 1 Year |
| S/MIME | 914 | emSign - SMIME - Simple MV-S 1 Year |
| S/MIME | 915 | emSign - SMIME - Simple MV-S 2 Years |
| S/MIME | 919–924 | emSign SMIME Personal/Professional/Corporate variants |
| SSL/TLS | 842–851 | DV/OV/EV SSL (single, wildcard, UCC) |
| eSign | 853, 854 | eSign Natural/Legal Person 10Min |
| **Private PKI** | **149** | **Sandbox emSign Intranet SSL 1 Year** |

Product 149 is the only Private PKI product. Products 104 and 108 from the Postman collection (the "standard" Intranet SSL and IGTF products) are not provisioned.

---

## Questions Still Open for eMudhra Support

1. What are the numeric `dcvMethod` codes for `GetDcv` / `VerifyDcv`? (`"3"` appears in the Postman collection but the enum is undocumented.)
2. Can IGTF product `108` be provisioned on account `9374221333` for automated testing? Or can product `149` have auto-approval enabled?
3. Is there a sandbox environment where DV SSL auto-issues without real domain ownership?
4. What is the `GetFieldDetails` `categoryID` enum? How do you look up required fields per product?
5. Is `GetGroupDetailsV2` replacing `GetGroupDetails`? What changed?
6. Why does `GenerateOrderPrivatePKI` with `saveAndHold=0` always return EMS-939 for product 149, while `saveAndHold=1` succeeds? Is immediate submission blocked for this product category?
