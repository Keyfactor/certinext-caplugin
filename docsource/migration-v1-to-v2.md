## Migrating from V1 to V2

The CERTInext V2 REST API is an opt-in, order-centric API with modern OAuth2 authentication. It is
controlled entirely by the `UseV2Api` connector flag: `false` (default) keeps the connector on the
V1 API documented above; `true` switches **all** operations — Enroll, GetSingleRecord, Revoke, and
Synchronize — to V2. The two APIs cannot be mixed on a single connector.

> **V2 is labeled Preview.** It has real functional gaps relative to V1 (see
> [Known Gaps](#known-gaps) below) — most notably that per-SAN DCV on multi-domain (UCC) orders
> hasn't been confirmed by CERTInext or verified end to end (see below), and that Document Signer
> (`ProductFamily=signature`) enrollment isn't supported yet. Read this whole document — especially
> that section — before migrating a production connector.

### Before You Begin: Confirm V2 Will Work for Your Templates

**V2 supports multi-domain (UCC) certificates**, including **DV UCC, DV Wildcard UCC, OV UCC, OV
Wildcard UCC, and EV UCC**. The plugin detects a UCC product from the live Catalog's `productTypeID`
and sends the extra SAN domains in the order's `additionalDomains` field. Per the CERTInext V2 spec,
a UCC order's SANs are taken from the order, not the CSR. `additionalDomains` takes DNS names only,
so any non-DNS SAN (IP, email, URI) is left off a UCC order and a warning is written to the gateway
log. For a non-UCC SSL product, a CSR that carries DNS SANs beyond the primary domain and its `www.`
variant is rejected with a `FAILED` result before any order is placed; UCC products are exempt from
that check.

**UCC DCV: the plugin runs DCV for each SAN, but the behavior isn't confirmed yet.** For a UCC order,
the plugin's DNS-01 DCV flow publishes, verifies, and cleans up a TXT record for each domain that
CERTInext reports as not yet validated, not just the primary domain. CERTInext hasn't yet confirmed
how per-SAN DCV is meant to work on V2, and this path hasn't been verified end to end against a live
UCC order. Test each UCC template on the sandbox before you rely on it in production, and keep it on
a V1 connector if you need that guarantee today.

### Step 1 — Create a V2 OAuth2 Credential

V2 authenticates with an OAuth2 `client_credentials` token, and the CERTInext V2 spec requires the
API key to be generated in **OAuth mode**. The credential goes in the connector's
`OAuthClientId`/`OAuthClientSecret` fields:

1. Log in to the CERTInext portal for your environment.
2. Navigate to **Integrations → APIs**.
3. Click **+ Create API Credentials**.
4. Set **API Type** to `REST` and select the **OAuth** auth type, not `Access Key`.
5. Complete the form and click **Generate**.
6. Note the client ID and client secret right away.

A V1 `Access Key` credential won't work against V2. If the key wasn't generated in OAuth mode, the
token request fails with HTTP 403 `unauthorized_client`, and the plugin reports that the key wasn't
generated in OAuth mode. A wrong client ID or secret fails with HTTP 401 `invalid_client` instead.
Nobody has checked whether a key that was already created in OAuth mode for V1's `AuthMode: OAuth`
also works on V2. If you reuse one and get the 403, create a new OAuth-mode key.

The V2 spec's token example sends the account number as `client_id`. It hasn't been verified whether
the portal ever shows a client ID that differs from the account number. The plugin never substitutes
`AccountNumber` for the client ID, so always set `OAuthClientId` explicitly, even if the value
matches your account number.

### Step 2 — Update the CA Connector

You can update the existing CA connector in place, or (recommended for a first migration) create a
second connector pointed at the same CERTInext account with `UseV2Api=true`, so you can validate V2
behavior without disrupting V1 traffic.

| V1 field | What happens when you set `UseV2Api = true` |
|---|---|
| `ApiUrl` | **Must change format.** V1 requires the `/emSignHub-API/` path segment (e.g. `https://us-api.certinext.io/emSignHub-API/`); V2 is the bare host with no trailing slash or path suffix (e.g. `https://us-api.certinext.io`). Using the V1-style URL under V2 (or vice versa) will fail every call. |
| `AccountNumber` | Not required, and not read by any V2 code path. V2 authenticates with `OAuthClientId`; the plugin doesn't reuse `AccountNumber` as the OAuth `client_id` (see Step 1). |
| `AuthMode` | Not required. V2 always authenticates via OAuth2 `client_credentials`, regardless of this setting. |
| `ApiKey` | Not required. V2 never computes an `authKey`. |
| `OAuthClientId` / `OAuthClientSecret` | **Reused, but repointed.** Set them to the OAuth-mode credential from Step 1. It's unverified whether a V1 `AuthMode: OAuth` key also works on V2 (see Step 1). |
| `OAuthTokenUrl` | Not used. V2 always requests a token from `{ApiUrl}/oauth/token`; the token URL is derived, not configured. |
| `GroupNumber` | **Honored.** Sent as `groupNumber` on V2 order create (SSL/TLS and Private PKI) and as a `groupNumber` query parameter on the catalog and orders-report calls. Omitted when blank, so the account's default group applies. It hasn't been verified live whether the catalog and report filters actually narrow results on a multi-group account. |
| `OrganizationNumber` | **Required for OV/EV, otherwise unused.** V2 OV/EV orders now send `organization.organizationNumber` (with `preVetted=true`) from this setting — CERTInext hard-rejects an OV/EV order with no organization data (HTTP 422 `EMS-1180`), so `OrganizationNumber` must be set on the connector before enrolling OV/EV certificates via V2. DV orders never send an organization block, so this setting has no effect for DV. |
| `AccountingModel` | Not used by V2 order placement. |
| `EmailNotifications` | **Honored, with one default-value difference from V1.** `1` maps to `emailNotifications: "all"`; `0` maps to `"0"` (confirmed live 2026-09-28 to suppress order-creation emails, same as V1). Blank/unset is omitted on V2 (the CA's own default of `"all"` applies) rather than sent as `"0"` the way V1's own fallback does — set `EmailNotifications=0` explicitly if you want V2 orders silent. Any other value fails the V2 enrollment before any CA call. |
| `SubscriptionAutoRenew` / `SubscriptionRenewCriteriaDays` | Honored. `SubscriptionAutoRenew=1` sets `subscription.autoRenew=true`; `SubscriptionRenewCriteriaDays` sets `subscription.renewBeforeDays` (blank omits the field, so the CA's documented default of 30 applies). An unparseable or negative `SubscriptionRenewCriteriaDays` fails the enrollment before any CA call. |
| `DefaultProductCode` | Not used for V2 renewals (see [Renewals](#renewals-and-reissuance) below) — V2 has no separate renewal call to fall back to a default code for. |
| `TechnicalContactName` / `Email` / `IsdCode` / `MobileNumber` | **Honored.** Sent as the order's `technicalPointOfContact` block on V2 SSL/TLS and Private PKI orders. Each blank field falls back to the matching `Requestor*` value, the same as V1. `designation` is always sent as `Technical Contact`. |
| `IgnoreExpired` | **Honored during V2 Synchronize.** When `true`, a report row whose `certificateExpiryDate` parses and is in the past is skipped. A row with a missing or unparseable expiry date is kept. |
| `SubmitNonDnsSans` | **SSL family (`ProductFamily=ssl`):** not consulted. A non-UCC order carries only the primary domain (plus `www.` when `AutoSecureWww` is set). A UCC order's `additionalDomains` takes DNS names only, so non-DNS SANs are left off the order with a warning in the gateway log (see [Before You Begin](#before-you-begin-confirm-v2-will-work-for-your-templates)). **Private PKI family (`ProductFamily=private-pki`):** not consulted — the order's `additionalHosts` field accepts DNS names and IPv4/IPv6 addresses natively, so IP-address SANs are always submitted; email and URI SANs cannot be expressed there and are left off the order with a warning in the gateway log. |
| `PageSize` | Still used, now against V2's `/reports/orders` paging. |
| `RequestorName` / `RequestorEmail` / `RequestorMobileNumber` / `RequestorDesignation` | Still used — carried into the V2 order's `requestor` block. `RequestorDesignation` is omitted from the order when blank (the default) rather than sent with any value. |
| `SignerPlace` / `SignerIp` | Still used — carried into the V2 order's `agreement` block. |
| `SubscriptionValidityYears` | Still used as the fallback validity when the template's `ValidityYears` parameter is not set. |
| `AutoSecureWww` | Still used — controls whether V2 adds the `www.` variant. |

New fields, `UseV2Api` and `V2SyncLookbackHours`, are documented in [V2 API (Preview)](#v2-api-preview)
above.

### Step 3 — Update Certificate Templates

For each template you're migrating:

1. Add `ProductFamily` (default `ssl`) and `ProductVariant` (`dv`/`ov`/`ev`) if not already present —
   these are V2-only parameters with no V1 equivalent. For a Private PKI template, set
   `ProductFamily=private-pki`, `ProductVariant` to `intranet-ssl` or `igtf-host`, and an explicit
   `ProductCode` (see [V2 Private PKI Orders](#v2-private-pki-orders)). `ProductFamily=signature`
   (Document Signer) enrollment is not yet supported.
2. Re-verify `ProductCode` against the V2 catalog. V1 and V2 product codes are not guaranteed to be
   the same numeric values on your account — call `GetProductDetailsV2Async` (or the equivalent live
   probe) rather than assuming the V1 code carries over. Template validation (`ValidateProductInfo`)
   automatically checks `ProductCode` against the V2 catalog once `UseV2Api=true`, so an incorrect
   code will be caught at template save time, not silently at enrollment.
3. If the template enrolls for a UCC (multi-domain) product, test it on the sandbox first. The plugin
   runs DCV for each SAN, but CERTInext hasn't confirmed that behavior yet (see
   [Before You Begin](#before-you-begin-confirm-v2-will-work-for-your-templates)).
4. If `ProductVariant` is `ov` or `ev`, set `OrganizationNumber` on the CA connector (a pre-vetted
   organization number from CERTInext's Accounts → List Organizations). It is mandatory for OV/EV
   under V2 — enrollment fails fast with a clear error if it's missing, rather than reaching the CA
   and getting back an opaque 422.

### Step 4 — Test Before Cutting Over

Run a full enroll → sync → revoke cycle against the sandbox environment with `UseV2Api=true` before
pointing a production template at the V2 connector. At minimum, confirm:

- A new enrollment issues (or parks pending DCV/approval as expected) and is retrievable via
  `GetSingleRecord`.
- A full and an incremental `Synchronize` both pick up the order.
- `Revoke` succeeds for the Command revoke reasons you actually use.

## Behavioral Differences After Migrating

- **Order identifiers.** The V2 spec's examples show `ord_`-prefixed order IDs (e.g.
  `ord_8K9mQ2vR8nP4bL`), but the orders placed through V2 against the sandbox so far have come back
  with numeric order numbers in the same format as V1 (e.g. `6625262451`). V1-placed order numbers
  also resolve through V2 Track Order and appear under the same number in the V2 orders report, so
  existing `CARequestID` values carry over. The plugin stores whatever `orderId` CERTInext returns as
  the `CARequestID`. Treat it as an opaque string in any external tooling rather than assuming either
  format.
- **Status vocabulary.** V2 reports order status as strings (`issued`, `pending-dcv`, `pending-csr`,
  `pending-agreement`, `pending-organization-verification`, `pending-documents`, `pending-approval`,
  `revoked`, `cancelled`, `rejected`, `expired`) rather than V1's numeric CERTInext status codes. The
  plugin maps both to the same Keyfactor `EndEntityStatus` values, so this is transparent to Command,
  but it changes what you'll see in gateway trace logs.
- **Synchronization source.** V2 sync reads CERTInext's `/reports/orders` endpoint instead of V1's
  `GetOrderReport`. Incremental sync queries a window starting `V2SyncLookbackHours` (default 72)
  before the last sync time rather than the exact last-sync timestamp, because it isn't confirmed
  whether the API's date filter brackets order-placement or issuance date — this trades a small
  amount of redundant re-processing for not missing a slow-issuing order.

### Renewals and Reissuance

CERTInext V2 has no *renew* endpoint, but it does document a `/reissue` endpoint (`mode:
rekey|update-sans`, with optional `revokePrevious`/`revokeReason`). The plugin intentionally does not
use it.
**Every** Command `Renew`, `Reissue`, and `RenewOrReissue` enrollment instead places a brand-new V2
order — the same call path as a new enrollment — rather than reusing V1's renewal-window logic or the
`/reissue` endpoint. The prior order and certificate are left issued, not auto-revoked; Command links
the old and new certificates via history only. If your CERTInext account is on a credit-based billing
model, **each renewal under V2 consumes a new credit**, unlike V1 where a renewal inside the
`RenewalWindowDays` window is billed as part of the existing subscription term. Factor this into your
migration decision if you rely on CERTInext's free-renewal-within-subscription behavior.

### Revocation Reason Codes

V1 sends CERTInext a numeric `revokeReasonId`; V2 sends a kebab-case string reason. The plugin
handles this translation automatically, including retrying once with `cessation-of-operation` when
CERTInext rejects the RFC 5280 "unspecified" reason (Command's default when no reason is given) — no
customer action needed for that case. On SSL/TLS orders, only `key-compromise` (1),
`affiliation-changed` (3), `superseded` (4), `cessation-of-operation` (5), and `privilege-withdrawn`
(9) were accepted in live sandbox testing. `ca-compromise` (2) and `certificate-hold` (6) are listed
in the spec for SSL/TLS but were rejected with `"Invalid Revoke Reason ID"`. `aa-compromise` (10)
isn't listed for SSL/TLS at all and was also rejected. The plugin surfaces those failures as-is,
without a retry. Revoke reasons for Private PKI orders haven't been tested live. Separately, a revoke
note containing a semicolon (`;`) is rejected with `"Invalid Revoke Remarks"`. The plugin's own
generated notes avoid semicolons, but a future customer-supplied note would need to avoid them too.

## Known Gaps

As of this writing, the following V2 limitations are known and unresolved. None of them are
show-stoppers for a single-domain, credit-tolerant deployment, but you should decide with these in
mind rather than discover them after cutting over:

- **UCC per-SAN DCV is unconfirmed.** The plugin runs DCV for each SAN on a UCC order, but CERTInext
  hasn't confirmed the per-SAN DCV behavior and the path hasn't been verified end to end. See
  [Before You Begin](#before-you-begin-confirm-v2-will-work-for-your-templates) above.
- **Document Signer (`ProductFamily=signature`) enrollment isn't supported yet.** It fails before any
  order is placed.
- **Every renewal/reissue places a new order and consumes a new credit** — see
  [Renewals and Reissuance](#renewals-and-reissuance) above.
- **`OrganizationNumber` is now required to enroll OV/EV via V2, but only unlocks acceptance, not
  V1's pre-vetting speed benefit.** V2 OV/EV orders send `organization.organizationNumber` with
  `preVetted=true` (mirroring V1's `organizationDetails.preVetting`), which is what makes CERTInext
  accept the order at all — omitting it gets a hard 422 rejection. Whether this also grants V1's
  observed vetting-queue speedup has not been independently confirmed for V2; if your account was
  relying on `OrganizationNumber` to fast-path DV issuance under V1, note that DV orders under V2
  never send an organization block, so that specific benefit does not carry over.
- **`AccountingModel` has no V2 effect.** V2 order create has no equivalent field. `GroupNumber`, the
  technical-contact fields, `EmailNotifications`, `SubscriptionAutoRenew`/`RenewCriteriaDays`, and
  `IgnoreExpired` are all honored on V2 (see the table above).
- **V2 `TrackOrder` responses omit `_links`** — a spec-shape discrepancy observed live; no functional
  impact has been identified so far, but it means any future feature that expects those links (e.g.
  a direct download link) can't rely on them yet.

## Rolling Back to V1

Rolling back is just setting `UseV2Api` back to `false` on the connector — the V1 credential fields
(`ApiKey`/`AccountNumber`/`AuthMode` or V1 `OAuth`) are unaffected by having been unused while V2 was
active, as long as you didn't overwrite them in Step 2.

**Rollback caveat (unverified):** `Enroll`, `GetSingleRecord`, `Revoke`, and `Synchronize` choose V1
or V2 purely from the connector's current `UseV2Api` flag, not from the stored `CARequestID`. What
has been observed on the sandbox runs in one direction only: V1-placed order numbers resolve through
V2 Track Order, and V2-placed orders so far have numeric order numbers in the same format as V1. The
reverse hasn't been tested. Nobody has checked whether V1 Track Order or `GetOrderReport` can see an
order that was placed through V2. Until that's confirmed, treat rolling back a connector that has
already issued V2 certificates as untested. Before you rely on it, check on the sandbox that sync,
revoke, and renewal still work for those certificates after switching back. Certificates enrolled
before the switch to V2 are V1 orders and are unaffected.

{% include 'architecture.md' %}
