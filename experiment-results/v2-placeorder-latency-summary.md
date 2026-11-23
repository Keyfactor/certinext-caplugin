# V2 place-order latency vs. issue 0090 (2026-10-14, CERTInext sandbox)

Test: `CERTInext.IntegrationTests/V2PlaceOrderLatencyExperimentTests.cs` (opt-in `CERTINEXT_V2_LATENCY_EXPERIMENT=1`).
The plugin's real `Enroll` (V2, DV SSL 842, DCV off, default pickup 5 x 10 s) runs through a timing proxy over
`ICERTInextClient`. Beside it, an independent client lists `/reports/orders` every 1.5 s (what Synchronize calls) and
another tracks the order every 1 s from the moment the create response lands. Times are seconds after Enroll start (t0).
Raw data: `v2-placeorder-latency-*.csv` (13 orders: 12 on the verified base domain, 1 on a fresh unverified subdomain).
All 13 orders were revoked or cancelled by the test.

## V2 order placement is three calls, and the hold moved to the second one
1. `POST create` returns the orderId after 3.5-4.7 s (median 3.9 s). It does NOT hold for ~19 s.
2. `PUT /csr` blocks 17.4-23.1 s (median 20.2 s) in 11 of 12 base-domain orders (the 12th, the first base-domain order of the day, took 2.9 s and issued ~17 s after t0 instead). The certificate is generated inside this call.
3. `GET track` + `GET certificate` + pickup: ~0.12 s + ~2.8 s. Total `Enroll` wall time: 24.6-30.4 s (median 27.9 s) for
   the 11 held orders; 39.9 s for the anomalous one.

## Per-order table (base domain `reuse` orders; seconds after t0 unless noted)
| order | create-resp status | place HTTP | csr HTTP | track 'issued' first seen | listing 'Certificate Generated' | csr resp | Enroll wall | listing-first-seen -> Enroll end |
|---|---|---|---|---|---|---|---|---|
| 1226469856 | pending-approval | 4.7 | 2.9 | 17.3 | 36.2 | 8.9 | 39.9 | 35.3 |
| 1918886693 | issued | 4.1 | 20.2 | 6.3 | 25.6 | 25.6 | 28.5 | 22.4 |
| 7313697899 | pending-approval | 3.5 | 18.8 | 5.2 | 24.1 | 22.7 | 25.6 | 20.9 |
| 3428572213 | issued | 4.3 | 20.3 | 5.0 | 25.6 | 25.2 | 28.1 | 23.5 |
| 7915224579 | issued | 3.8 | 21.5 | 4.4 | 25.6 | 25.7 | 28.5 | 23.9 |
| 8731931793 | issued | 3.7 | 18.6 | 5.9 | 24.1 | 23.6 | 26.4 | 21.8 |
| 8487123326 | issued | 3.8 | 18.7 | 4.4 | 24.2 | 23.0 | 26.0 | 21.4 |
| 7447643132 | issued | 3.8 | 17.4 | 4.4 | 22.7 | 21.6 | 24.6 | 20.0 |
| 8595485484 | issued | 4.0 | 20.3 | 4.6 | 25.6 | 24.8 | 27.9 | 23.3 |
| 2299934381 | issued | 4.0 | 20.3 | 6.3 | 25.7 | 25.5 | 28.7 | 24.0 |
| 1732815671 | issued | 3.8 | 19.1 | 4.4 | 24.2 | 23.4 | 26.2 | 21.6 |
| 7966694779 | issued | 3.9 | 23.1 | 4.5 | 28.6 | 27.4 | 30.4 | 25.2 |

Unverified fresh subdomain (3544182867): create `pending-approval`, place 4.4 s, csr 3.2 s, still `pending-approval`
>150 s later (no DCV in this run); Enroll returned EXTERNALVALIDATION after 64.7 s.

## Key datum
- In 11 of 12 base-domain orders the order is already `issued` (per the V2 track endpoint) **before the CSR PUT returns**,
  by ~17-21 s; in 10 of 12 the create response itself already says `issued`. This is the production V1 pattern (order
  already issued while the response is held), moved to `PUT /csr`.
- The sync-visible window (first sighting in `/reports/orders`, within ~1.5 s of the create response (before it in 5 of 13 orders), to Enroll return, when
  the gateway learns the CARequestID) is 20.0-25.2 s (median 22.4 s) for held orders; 35.3 s for the anomalous one.
  The listing shows `Order Accepted | Pending for Approver` or `Approved by System` for the whole window and flips to
  `Certificate Generated` only about when the CSR PUT returns.

## Caveats
- V1 sandbox did NOT reproduce production's hold, so these are suggestive, not proof, for production V2. The V2 sandbox
  does reproduce the shape (issued before response, ~20 s hold), which V1 sandbox did not.
- One account, one ~25 minute window, 13 orders; first-sighting resolution is the 1.5 s poll interval.
- Phase 1 orders share the sandbox account with the kfclab gateway, whose own sync imported at least one of them
  (gateway row 1826, order 8595485484).
