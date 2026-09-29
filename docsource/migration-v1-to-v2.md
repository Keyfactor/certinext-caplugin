## Migrating from V1 to V2

The CERTInext V2 REST API is an opt-in, order-centric API with modern OAuth2 authentication. It is
controlled entirely by the `UseV2Api` connector flag: `false` (default) keeps the connector on the
V1 API documented above; `true` switches **all** operations — Enroll, GetSingleRecord, Revoke, and
Synchronize — to V2. The two APIs cannot be mixed on a single connector.

> **V2 is labeled Preview.** It has real functional gaps relative to V1 (see
> [Known Gaps](#known-gaps) below) — most notably that DCV automation for multi-domain (UCC)
> orders only drives the primary domain (see below). Read this whole document — especially that
> section — before migrating a production connector.

### Before You Begin: Confirm V2 Will Work for Your Templates

**V2 supports multi-domain (UCC) certificates**, including **DV UCC, DV Wildcard UCC, OV UCC, OV
Wildcard UCC, and EV UCC**. The plugin detects a UCC product from the live Catalog's `productTypeID`
and sends the extra SAN domains via the order's `additionalDomains` field — the CSR itself must
still carry only the primary domain (per the CERTInext V2 spec, SANs for UCC orders come from the
order, not the CSR); a CSR that carries extra SANs is rejected with a `FAILED` result regardless of
product type, the same as before.

**DCV automation does not yet cover the extra SAN domains.** The plugin's DNS-01 DCV flow only
drives the primary domain; a UCC order's additional domains are not currently validated by this
plugin's automation, so a live UCC order may stall at `pending-dcv` until that's addressed (tracked
separately). If your UCC templates require automated DCV for every SAN today, keep them on a V1
connector until that gap closes.

### Step 1 — Create a V2 OAuth2 Credential

V2 authentication is **not** the same credential as V1's `AuthMode: OAuth`, even though both end up
in the connector's `OAuthClientId`/`OAuthClientSecret` fields. You need a new credential created
specifically for V2:

1. Log in to the CERTInext portal for your environment.
2. Navigate to **Integrations → APIs**.
3. Click **+ Create API Credentials**.
4. Set **API Type** to `REST` and **Auth Type** to `OAuth2 (V2)` — not `OAuth`, not `Access Key`.
5. Complete the form and click **Generate**.
6. Note the **Client ID** and **Client Secret** immediately; the secret is shown once.

Reusing an existing V1 `AccessKey` or V1 `OAuth` credential will not work against the V2 API.

### Step 2 — Update the CA Connector

You can update the existing CA connector in place, or (recommended for a first migration) create a
second connector pointed at the same CERTInext account with `UseV2Api=true`, so you can validate V2
behavior without disrupting V1 traffic.

| V1 field | What happens when you set `UseV2Api = true` |
|---|---|
| `ApiUrl` | **Must change format.** V1 requires the `/emSignHub-API/` path segment (e.g. `https://us-api.certinext.io/emSignHub-API/`); V2 is the bare host with no trailing slash or path suffix (e.g. `https://us-api.certinext.io`). Using the V1-style URL under V2 (or vice versa) will fail every call. |
| `AccountNumber` | Not required. Ignored by every V2 code path. |
| `AuthMode` | Not required. V2 always authenticates via OAuth2 `client_credentials`, regardless of this setting. |
| `ApiKey` | Not required. V2 never computes an `authKey`. |
| `OAuthClientId` / `OAuthClientSecret` | **Reused, but repointed.** Replace the values with the V2 credential from Step 1 — do not leave V1 OAuth credentials here. |
| `OAuthTokenUrl` | Not used. V2 always requests a token from `{ApiUrl}/oauth/token`; the token URL is derived, not configured. |
| `GroupNumber` | **Not carried into V2 orders.** V1 sends this in `delegationInformation` on every order; the V2 order body has no equivalent field. If your account routes orders by group, confirm with eMudhra how group routing is handled on the V2 API before relying on it. |
| `OrganizationNumber` | **Required for OV/EV, otherwise unused.** V2 OV/EV orders now send `organization.organizationNumber` (with `preVetted=true`) from this setting — CERTInext hard-rejects an OV/EV order with no organization data (HTTP 422 `EMS-1180`), so `OrganizationNumber` must be set on the connector before enrolling OV/EV certificates via V2. DV orders never send an organization block, so this setting has no effect for DV. |
| `AccountingModel` | Not used by V2 order placement. |
| `EmailNotifications` | **Honored, with one default-value difference from V1.** `1` maps to `emailNotifications: "all"`; `0` maps to `"0"` (confirmed live 2026-09-28 to suppress order-creation emails, same as V1). Blank/unset is omitted on V2 (the CA's own default of `"all"` applies) rather than sent as `"0"` the way V1's own fallback does — set `EmailNotifications=0` explicitly if you want V2 orders silent. Any other value fails the V2 enrollment before any CA call. |
| `SubscriptionAutoRenew` / `SubscriptionRenewCriteriaDays` | Honored. `SubscriptionAutoRenew=1` sets `subscription.autoRenew=true`; `SubscriptionRenewCriteriaDays` sets `subscription.renewBeforeDays` (blank omits the field, so the CA's documented default of 30 applies). An unparseable or negative `SubscriptionRenewCriteriaDays` fails the enrollment before any CA call. |
| `DefaultProductCode` | Not used for V2 renewals (see [Renewals](#renewals-and-reissuance) below) — V2 has no separate renewal call to fall back to a default code for. |
| `TechnicalContactName` / `Email` / `IsdCode` / `MobileNumber` | Not used. The V2 order body has no technical-point-of-contact field. |
| `IgnoreExpired` | **Not honored during V2 Synchronize.** Expired certificates are always included in the V2 sync result set. |
| `SubmitNonDnsSans` | **SSL family (`ProductFamily=ssl`):** not applicable — see the single-domain limitation above; non-DNS SANs were never part of this concern for V2, DNS SANs beyond the primary domain already fail outright. **Private PKI family (`ProductFamily=private-pki`):** not consulted — the order's `additionalHosts` field accepts DNS names and IPv4/IPv6 addresses natively, so IP-address SANs are always submitted; email and URI SANs cannot be expressed there and are left off the order with a warning in the gateway log. |
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
3. Confirm the template does not enroll for a UCC/multi-domain product (see above).
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

- **Order identifiers.** V2 orders are opaque strings prefixed `ord_` (e.g. `ord_a1b2c3d4`), stored as
  `CARequestID` exactly like V1's numeric order IDs — Command itself doesn't care about the format —
  but any external tooling or scripts that parse or expect a numeric `CARequestID` will need updating.
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
customer action needed. Two narrow edge cases remain open: CRL reason `10` (`aa-compromise`) may
still be rejected for SSL-family orders (Command rarely sends this reason), and a revoke note
containing a semicolon (`;`) is rejected by CERTInext with `"Invalid Revoke Remarks"` (the plugin's
own generated notes avoid this, but a future customer-supplied note would need to avoid it too).

## Known Gaps

As of this writing, the following V2 limitations are known and unresolved. None of them are
show-stoppers for a single-domain, credit-tolerant deployment, but you should decide with these in
mind rather than discover them after cutting over:

- **Multi-domain (UCC) orders can be placed, but DCV only drives the primary domain** — see
  [Before You Begin](#before-you-begin-confirm-v2-will-work-for-your-templates) above. This is the
  most likely reason to delay migrating a UCC template until DCV automation covers every SAN.
- **Every renewal/reissue places a new order and consumes a new credit** — see
  [Renewals and Reissuance](#renewals-and-reissuance) above.
- **`GroupNumber` has no V2 effect** — group-based order routing is not available under V2.
- **`OrganizationNumber` is now required to enroll OV/EV via V2, but only unlocks acceptance, not
  V1's pre-vetting speed benefit.** V2 OV/EV orders send `organization.organizationNumber` with
  `preVetted=true` (mirroring V1's `organizationDetails.preVetting`), which is what makes CERTInext
  accept the order at all — omitting it gets a hard 422 rejection. Whether this also grants V1's
  observed vetting-queue speedup has not been independently confirmed for V2; if your account was
  relying on `OrganizationNumber` to fast-path DV issuance under V1, note that DV orders under V2
  never send an organization block, so that specific benefit does not carry over.
- **`AccountingModel` and the technical-point-of-contact fields have no V2 effect on billing/contact
  behavior beyond what's noted in the table above** — see the table for `EmailNotifications` and
  `SubscriptionAutoRenew`/`RenewCriteriaDays`, both of which are now honored on V2.
- **`IgnoreExpired` is not honored during V2 Synchronize** — expired certificates always come back in
  the V2 sync result set.
- **V2 `TrackOrder` responses omit `_links`** — a spec-shape discrepancy observed live; no functional
  impact has been identified so far, but it means any future feature that expects those links (e.g.
  a direct download link) can't rely on them yet.

## Rolling Back to V1

Rolling back is just setting `UseV2Api` back to `false` on the connector — the V1 credential fields
(`ApiKey`/`AccountNumber`/`AuthMode` or V1 `OAuth`) are unaffected by having been unused while V2 was
active, as long as you didn't overwrite them in Step 2.

**One-way caveat:** `GetSingleRecord`, `Synchronize`, and renewal lookups dispatch to V1 or V2 purely
based on the connector's current `UseV2Api` flag — not by inspecting the shape of the stored
`CARequestID`. Any certificate that was **enrolled while `UseV2Api=true`** has an `ord_`-prefixed
`CARequestID`. If you flip the connector back to `UseV2Api=false`, the V1 API path will attempt to
look that ID up as a V1 order and will not find it — future sync passes and renewals for those
specific certificates will fail until the connector is switched back to V2 (or those certificates are
otherwise resolved out of inventory). Certificates enrolled before the switch to V2 are unaffected
either way. Plan a rollback path with this in mind rather than toggling the flag back and forth on a
connector that has already issued V2 certificates.

{% include 'architecture.md' %}
