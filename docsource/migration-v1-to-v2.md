## Migrating from V1 to V2

The CERTInext V2 REST API is an opt-in, order-centric API with OAuth2 authentication. It is
controlled entirely by the `UseV2Api` connector flag: `false` (default) keeps the connector on the
V1 API documented above; `true` switches **all** operations — Ping, Enroll, GetSingleRecord, Revoke,
and Synchronize — to V2. The two APIs cannot be mixed on a single connector.

> Read [Known Gaps](#known-gaps) before migrating a production connector. The most important:
>
> - Document Signer (`ProductFamily=signature`) enrollment isn't supported.
> - DCV isn't validated end to end for per-SAN UCC domains, never-validated domains, or wildcards.
> - Every renewal places a new order.
>
> The plugin requires AnyCA Gateway REST 26.2.0 or later; see the compatibility matrix under [Requirements](#requirements).

### Before You Begin: Confirm V2 Will Work for Your Templates

- **Multi-domain (UCC) certificates are supported.** That covers DV UCC, DV Wildcard UCC, OV UCC, OV Wildcard UCC, and EV UCC. The plugin detects a UCC product from the live catalog's `productTypeID` and sends the extra SAN domains in the order's `additionalDomains` field. Per the V2 spec, a UCC order's SANs come from the order, not the CSR.
- **Only DNS SANs are sent.** `additionalDomains` takes DNS names only, so IP, email, and URI SANs are left off a UCC order and a warning is written to the gateway log.
- **Non-UCC SSL products are checked up front.** A CSR or SAN list with DNS names beyond the primary domain and its `www.` variant is rejected before any order is placed. UCC products are exempt.
- **DCV is not validated end to end in three cases.** These are per-SAN DCV on UCC orders, a domain that has never been validated, and wildcard DCV. The plugin runs the DNS-01 flow for each domain CERTInext reports as not yet validated, but test each UCC or wildcard template on the sandbox before relying on it in production. Keep it on a V1 connector if you need a validated path today.
- **DCV needs a DNS provider plugin.** `DcvEnabled` defaults to `true`. Without a DNS provider plugin for the order's domains, V2 DV orders stay pending after the order is placed. Deploy one, or set `DcvEnabled` to `false` and validate domains another way. See [DCV under V2](#dcv-under-v2).

### Step 1 — Create a V2 OAuth2 Credential

V2 authenticates with an OAuth2 `client_credentials` token, and the CERTInext V2 spec requires the API key to be generated in **OAuth mode**. The credential goes in the connector's `OAuthClientId` and `OAuthClientSecret` fields.

1. Log in to the CERTInext portal for your environment.
2. Navigate to **Integrations → APIs**.
3. Click **+ Create API Credentials**.
4. Set **API Type** to `REST` and select the **OAuth** auth type, not `Access Key`.
5. Complete the form and click **Generate**.
6. Note the client ID and client secret right away.

A V1 `Access Key` credential won't work against V2. The token request fails in one of two ways:

| Response | Meaning | Fix |
|---|---|---|
| HTTP 403 `unauthorized_client` | The key exists but wasn't generated in OAuth mode. The plugin reports this. | Create a new key in OAuth mode. |
| HTTP 401 `invalid_client` | The client ID or secret is wrong. | Re-enter the values from the portal, or regenerate the secret. |

> **Warning:** The V2 spec's token example sends the account number as `client_id`. The plugin never substitutes `AccountNumber` for the client ID, so always set `OAuthClientId` explicitly to the client ID shown in the portal, even if the value matches your account number.

### Step 2 — Update the CA Connector

You can update the existing CA connector in place, or create a second connector for the same CERTInext account with `UseV2Api=true` to validate V2 without disturbing V1 traffic.

> **Caution:** Two connectors on one account both import the same orders, and each plugin instance can run DCV for the same pending order. Use the second-connector approach on the sandbox only, not in production.

To switch a connector:

- [ ] Set `UseV2Api` to `true`.
- [ ] Change `ApiUrl` to the V2 host.
- [ ] Set `OAuthClientId` and `OAuthClientSecret`.
- [ ] Set `SignerPlace`. The connector can't be saved with it blank in V2 mode.

New fields `UseV2Api` and `V2SyncLookbackHours` are documented in [V2 API](#v2-api). The remaining V1 fields behave as follows.

**Not used on V2**

| V1 field | Behavior |
|---|---|
| `AccountNumber` | Not read by any V2 code path. The plugin never reuses it as the OAuth `client_id` (see Step 1). |
| `AuthMode` | V2 always authenticates with OAuth2 `client_credentials`. On V1, `OAuth` is legacy and unsupported: V1 does not honor OAuth, though the code still accepts it for already-saved connectors. |
| `ApiKey` | V2 never computes an `authKey`. |
| `OAuthTokenUrl` | V2 always requests a token from `{ApiUrl}/oauth/token`. Legacy and unsupported on V1, as for `AuthMode`. |
| `AccountingModel` | V2 order create has no equivalent field. |

**Used unchanged**

| V1 field | Behavior |
|---|---|
| `SubscriptionValidityYears` | Fallback validity when the template's `ValidityYears` is not set. |
| `TechnicalContactName` / `Email` / `IsdCode` / `MobileNumber` | Sent as the order's `technicalPointOfContact` on SSL/TLS and Private PKI orders. A blank field falls back to the matching `Requestor*` value, as on V1. `designation` is always `Technical Contact`. |
| `RequestorName` / `RequestorEmail` / `RequestorIsdCode` / `RequestorMobileNumber` / `RequestorDesignation` | Carried into the order's `requestor` block. The phone number is sent as `+<ISD code><number>`, and a blank `RequestorDesignation` is omitted. |
| `SignerPlace` / `SignerIp` | `SignerPlace` is carried into the order's `agreement` block and is required in V2 mode. `SignerIp` is V1 only: the V2 agreement block has no IP field, so it is never sent. |
| `AutoSecureWww` | Controls whether V2 adds the `www.` variant. |
| `PageSize` | Applies to V2 `/reports/orders` paging, capped at 100 per page. |
| `PickupRetries` / `PickupDelay` | V2 enrollment polls for a quickly issued certificate the same way V1 does. |
| `LogSensitiveRequestData` | Governs redaction of V2 request and response bodies in the gateway log. |
| `Enabled` | Unchanged. |

**Used with changed behavior**

| V1 field | What changes on V2 |
|---|---|
| `ApiUrl` | Use the bare host (for example `https://us-api.certinext.io`), not the V1 `/emSignHub-API/` URL. A trailing slash is harmless because the client trims it. A V1-style URL under V2, or the reverse, fails every call. Both modes require `https`; `http` is rejected except for a loopback host. |
| `OAuthClientId` / `OAuthClientSecret` | Set them to the OAuth-mode credential from Step 1. |
| `GroupNumber` | Sent as `groupNumber` on SSL/TLS and Private PKI order create, and as a query parameter on catalog and orders-report calls. Omitted when blank, so the account's default group applies. |
| `OrganizationNumber` | Required for OV/EV, unused for DV. V2 OV/EV orders send `organization.organizationNumber` with `preVetted=true`. CERTInext rejects an OV/EV order without organization data (HTTP 422 `EMS-1180`), so the plugin fails the enrollment before any CA call if it is blank. |
| `EmailNotifications` | `1` maps to `"all"` and `0` maps to `"0"`. Blank is omitted on V2, so the CA's default of `"all"` applies; V1 sends `"0"`. Set `0` explicitly for silent V2 orders. Any other value fails the enrollment before any CA call. |
| `SubscriptionAutoRenew` / `SubscriptionRenewCriteriaDays` | `SubscriptionAutoRenew=1` sets `subscription.autoRenew=true`. `SubscriptionRenewCriteriaDays` sets `subscription.renewBeforeDays` (blank omits it, so the CA's default of 30 applies). An unparseable or negative value fails the enrollment before any CA call. |
| `DefaultProductCode` | Not used on V2: no product code is sent unless the template sets `ProductCode` (see [V2 Product Code Resolution](#v2-product-code-resolution)). Renewals don't need it. |
| `IgnoreExpired` | Honored during V2 Synchronize: a report row with a parseable, past `certificateExpiryDate` is skipped, and a row with a missing or unparseable date is kept. Not applied on V1 yet. |
| `SubmitNonDnsSans` | SSL family: not consulted. A UCC order's `additionalDomains` takes DNS names only, so non-DNS SANs are left off with a gateway-log warning. Private PKI: not consulted. `additionalHosts` takes DNS names and IPs, so IP SANs are always submitted, and email and URI SANs are left off with a warning. |

#### DCV under V2

`DcvEnabled` defaults to `true`, and the DCV settings behave as follows under V2:

- `DcvEnabled`, `DcvTxtRecordTemplate`, `DcvPropagationDelaySeconds`, and `DcvTimeoutMinutes` are used.
- `DcvSyncMaxOrderAgeHours` and `DcvSyncMaxPerPass` bound DCV during synchronization, the same as V1.
- `DcvWaitForChallengeSeconds` and `DcvWaitForIssuanceSeconds` apply to V1 only. V2 publishes the challenge as soon as the order exists and polls the order until it leaves `pending-dcv` (bounded by `DcvTimeoutMinutes`), then runs the normal pickup poll.
- DCV applies to the SSL/TLS family. Private PKI orders have no DCV step.

### Step 3 — Update Certificate Templates

For each template you're migrating:

1. **Leave `ProductCode` blank unless you need to force a catalog product.** On V2 the plugin sends no
   `X-Product-Code` header and CERTInext resolves the product from the variant, the wildcard shape of the
   domain and any additional domains, so a template with only `ProductId` works even when the catalog has
   several products at that assurance level. Set `ProductCode` only to override that choice (for example
   to pick one of several CA profiles). See [V2 Product Code Resolution](#v2-product-code-resolution).
2. Add `ProductFamily` (default `ssl`) if not already present — this is a V2-only parameter with no
   V1 equivalent. `ProductVariant` (`dv`/`ov`/`ev`) is optional for `ssl`: if left unset, the plugin
   derives it from the selected product (an OV product sends `ov`, an EV product sends `ev`) instead
   of defaulting to `dv`; set it explicitly only to override. For a Private PKI template, set
   `ProductFamily=private-pki`, `ProductVariant` to `intranet-ssl` or `igtf-host` (required, no
   default); `ProductCode` is optional (see [V2 Private PKI Orders](#v2-private-pki-orders)).
   `ProductFamily=signature` (Document Signer) enrollment is not supported.
3. Re-verify `ProductCode` (if set explicitly) against the V2 catalog. V1 and V2 product codes are not
   guaranteed to be the same numeric values on your account — check the V2 catalog
   rather than assuming the V1 code carries over. Template validation
   (`ValidateProductInfo`) automatically checks `ProductCode` against the V2 catalog once
   `UseV2Api=true`, so an incorrect code will be caught at template save time, not silently at
   enrollment.
4. The `DomainName` template parameter takes effect in V2 only. The `SignerName` and `SignerPlace`
   template parameters take effect in both V1 and V2 (`SignerIp` is V1 only). `RenewalWindowDays` and `ValidityDays`
   are V1-only and are ignored.
5. If the template enrolls for a UCC (multi-domain) or wildcard product, test it on the sandbox first.
   The plugin runs DCV for each domain, but per-SAN, never-validated-domain, and wildcard DCV aren't
   validated end to end (see
   [Before You Begin](#before-you-begin-confirm-v2-will-work-for-your-templates)).
6. If the product is OV or EV (whether `ProductVariant` is set explicitly or left to be derived), set
   `OrganizationNumber` on the CA connector (a pre-vetted organization number from CERTInext's
   Accounts → List Organizations). It is mandatory for OV/EV under V2 — enrollment fails fast with a
   clear error if it's missing, rather than reaching the CA and getting back an opaque 422.

### Step 4 — Test Before Cutting Over

Run a full enroll → sync → revoke cycle against the sandbox environment with `UseV2Api=true` before
pointing a production template at the V2 connector. At minimum, confirm:

- A new enrollment issues (or parks pending DCV/approval as expected) and is retrievable via
  `GetSingleRecord`.
- A full and an incremental `Synchronize` both pick up the order.
- `Revoke` succeeds for the Command revoke reasons you actually use.

### Verification Checklist

- [ ] **Connection test.** Save the connector. It succeeds after a token request to `{ApiUrl}/oauth/token` and `GET /api/certinext/v2/auth/me`; a 401 or 403 is explained in Step 1.
- [ ] **Template save.** Each template saves. An explicit `ProductCode` that is missing from the catalog, or whose product type doesn't match the selected product, is rejected.
- [ ] **DV enrollment.** Enroll a single-domain DV order. It returns the certificate, or returns pending and is imported by the next sync, and its TXT record is removed.
- [ ] **UCC and wildcard.** Enroll each migrated template. One order carries every DNS SAN, and each domain reaches the validated state.
- [ ] **OV/EV.** Set `OrganizationNumber` and enroll. The order is accepted, stays pending until organization verification completes, and the next sync imports it.
- [ ] **Synchronization.** Run a full and then an incremental sync. New orders are imported with their certificates; revoked orders appear only when the gateway already holds their certificate.
- [ ] **Revocation.** Revoke a test certificate with Command's default reason (unspecified) and with key compromise. The gateway log shows the substituted reason for the first.
- [ ] **Logs.** The gateway log has no requestor names, email addresses, or request bodies unless `LogSensitiveRequestData` is on.

## Behavioral Differences After Migrating

- **Order identifiers.** The V2 spec's examples show `ord_`-prefixed IDs (for example `ord_8K9mQ2vR8nP4bL`), but V2 returns numeric order numbers in the same format as V1 (for example `6625262451`). V1-placed order numbers also resolve through V2 Track Order and appear under the same number in the V2 orders report, so existing `CARequestID` values carry over. The plugin stores whatever `orderId` CERTInext returns; treat it as an opaque string in external tooling.
- **Status vocabulary.** V2 reports order status as strings (`issued`, `pending-dcv`, `pending-csr`,
  `pending-agreement`, `pending-organization-verification`, `pending-documents`, `pending-approval`,
  `revoked`, `cancelled`, `rejected`, `expired`, `unknown`) rather than V1's numeric CERTInext status
  codes. The plugin maps both to the same Keyfactor status values, so this is transparent to
  Command, but it changes what you'll see in gateway trace logs.
- **Synchronization source.** V2 sync reads CERTInext's `/reports/orders` endpoint instead of V1's
  `GetOrderReport`. Incremental sync queries a window starting `V2SyncLookbackHours` (default 72)
  before the last sync time rather than the exact last-sync timestamp, because the API's date filter
  may bracket either the order-placement or the issuance date — this trades a small
  amount of redundant re-processing for not missing a slow-issuing order.
- **Revoked orders in sync.** CERTInext doesn't serve the certificate body of a revoked order, so a
  revoked order is imported as revoked only when the gateway already holds its certificate. Otherwise
  it is reported as failed or skipped, so the gateway never stores a revoked record with no
  certificate.
- **Orphaned orders.** If CERTInext rejects the CSR after the order was created, the plugin cancels
  the order once and returns a failed result carrying the order ID. After a timeout, the plugin
  checks the order before deciding: it cancels the order only if the CSR never arrived.

- **CSR delivery.** By default V2 enrollment creates the order and then submits the CSR, as above. The
  optional `V2InlineCsr` connector setting (SSL/TLS only, default `false`) sends the CSR inline in the
  create call instead: about 4-5 seconds faster and the same call shape as a direct single-call API
  integration, but the create call can hold about 20 seconds until issuance, and a create that times
  out or returns a 5xx can leave an order that issues and is imported by the next sync rather than
  cancelled. Private PKI always uses the two-call flow.

### Renewals and Reissuance

CERTInext V2 has no *renew* endpoint. It documents a `/reissue` endpoint (`mode: rekey|update-sans`, with optional `revokePrevious` and `revokeReason`), which the plugin does not use.

- **Every enrollment type places a new order.** `New`, `Renew`, `Reissue`, and `RenewOrReissue` all take the same path as a new enrollment, without V1's renewal-window logic.
- **The prior order is untouched.** The old order and certificate stay issued and are not auto-revoked. Command links the old and new certificates through history only.
- **Each renewal is billed as a new order.** Confirm with eMudhra how your account treats renewals before you rely on free renewals within a subscription term.

### Revocation Reasons After Migrating

V1 sends a numeric `revokeReasonId` and V2 sends a kebab-case string; the plugin translates automatically. CERTInext rejects four of the V2 reason values on SSL/TLS orders, including Command's default `unspecified`. The plugin retries each once with an accepted substitute, so no customer action is needed. The full mapping is in [Revocation Reason Codes](#revocation-reason-codes).

## Known Gaps

The following V2 limitations are known. None of them is a show-stopper for a single-domain
deployment, but decide with these in mind rather than discovering them after cutting over:

- **DCV isn't validated end to end** for per-SAN domains on UCC orders, for a domain that has never been validated, or for wildcards. The plugin runs the flow for each of these, but the paths haven't been confirmed against the CA. See [Before You Begin](#before-you-begin-confirm-v2-will-work-for-your-templates).
- **Document Signer (`ProductFamily=signature`) enrollment isn't supported.** It fails before any
  order is placed.
- **Every renewal/reissue places a new order.** See [Renewals and Reissuance](#renewals-and-reissuance)
  above.
- **`OrganizationNumber` is required to enroll OV/EV via V2.** V2 OV/EV orders send
  `organization.organizationNumber` with `preVetted=true` (mirroring V1's
  `organizationDetails.preVetting`); omitting it fails the enrollment. If your account relies on
  `OrganizationNumber` to fast-path DV issuance under V1, note that DV orders under V2 never send an
  organization block, so that benefit does not carry over.
- **`AccountingModel` has no V2 effect.** V2 order create has no equivalent field. `GroupNumber`, the
  technical-contact fields, `EmailNotifications`, `SubscriptionAutoRenew`/`SubscriptionRenewCriteriaDays`, and
  `IgnoreExpired` are all honored on V2 (see the tables in Step 2).
- **OV and OV UCC orders can exceed the plugin's fixed 120-second request timeout.** The order may
  still be created on the CA and is imported by the next sync. EV orders under V2 are not validated
  end to end.

## Rolling Back to V1

Rolling back means setting `UseV2Api` back to `false`, as long as you kept the V1 values.

1. Set `UseV2Api` to `false` on the connector.
2. Restore the V1-format `ApiUrl` (with the `/emSignHub-API/` path). Keep a copy of this value before you edit an existing connector.
3. Confirm `ApiKey` and `AccountNumber` are intact. They are unaffected by being unused while V2 was active, unless you overwrote them in Step 2.
4. Save the connector and confirm the connection test passes.

**Rollback caveat:** `Enroll`, `GetSingleRecord`, `Revoke`, and `Synchronize` choose V1 or V2 from the connector's current `UseV2Api` flag, not from the stored `CARequestID`. V1-placed order numbers resolve through V2 Track Order, and V2 order numbers use the V1 format, but V1 Track Order and `GetOrderReport` may not see an order placed through V2. Rolling back a connector that has already issued V2 certificates isn't validated: check on the sandbox that sync, revoke, and renewal still work for them. Certificates enrolled before the switch to V2 are V1 orders and are unaffected.

{% include 'architecture.md' %}
