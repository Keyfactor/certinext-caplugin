# F3 — V2 API does not support multi-SAN certificates

**Severity:** Medium  
**Affected path:** `EnrollV2Async` → `PlaceOrderV2Async` (`CERTInext/CERTInextCAPlugin.cs`)

## Problem

The V2 API (`/api/v2/ssl/...`) is single-domain only. `V2CreateSslOrderRequest.Certificate`
has `domain` (string) and `autoSecureWww` (bool). There is no `additionalDomains` or SAN
array. A CSR carrying SANs beyond `<domain>` and `www.<domain>` has no mechanism to submit
those names to the CA — they would either be silently dropped or trigger a CA-side error.

The V1 path (`BuildOrderRequestFromLegacyEnrollRequest`) uses
`CertificateInformation.AdditionalDomains` (via `BuildAdditionalDomains`) and handles
multi-SAN CSRs correctly.

## Immediate mitigation (applied in this PR)

`EnrollV2Async` now parses DNS SANs from the CSR with BouncyCastle before calling
`PlaceOrderV2Async`. If SANs beyond the primary domain and its `www.` variant are
detected, enrollment is rejected immediately with a descriptive `FAILED` result rather
than letting the CA return an opaque error or silently issue a certificate missing names.

## Full fix options

1. **Route multi-SAN orders through V1**: detect the SAN count at `Enroll()` dispatch time
   and fall back to V1 when the CSR contains more than one DNS SAN (or more than two
   when `autoSecureWww=true`). Requires that the account still has V1 access.

2. **V2 SAN support via wildcard/UCC product variant**: investigate whether any
   CERTInext V2 product variant supports a SAN array in the order request. Not
   documented in the current OpenAPI spec; would need CA vendor confirmation.

3. **Gateway-layer refusal before V2 is attempted**: expose a `MaxSanCount` enrollment
   parameter (default 1 for V2 product codes) so administrators can constrain templates
   at the Command layer and avoid confusing enrollment failures at the CA level.

## Related

- `V2CertificateParams` — `CERTInext/API/V2/CertificateRequestV2.cs`
- `BuildAdditionalDomains` — `CERTInext/Client/CERTInextClient.cs` (V1 path)
