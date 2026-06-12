# Reference JSON — known-working lab state

Sanitised JSON captures of a fully-configured CERTInext lab. Useful as
**wire-format reference** when you're writing or debugging
configuration scripts: every blob here is what the live gateway and
Command returned (POST/PUT bodies aren't shown — those are documented
in [`QUICKSTART.md`](../../QUICKSTART.md)).

## Source

Generated from the `kfclab` localhost-kind reference lab on
2026-05-22 via:

```
kfclab snapshot -f examples/localhost-kind/kfclab.yaml --out /tmp/snap
```

Then trimmed to the CERTInext-relevant subset, with sensitive fields
either already masked by the upstream API (`ClientSecret`) or omitted
entirely (no access keys, no PAM literals).

## Layout

```
docs/reference/
├── README.md               (this file)
├── gateway/
│   ├── certificate-profiles.json   GET /AnyGatewayREST/config/certificateprofile
│   └── claims.json                 GET /AnyGatewayREST/config/claim
└── command/
    ├── certificate-authority.json  GET /KeyfactorAPI/CertificateAuthorities (CERTInext record)
    └── templates-certinext.json    GET /KeyfactorAPI/Templates filtered by ConfigurationTenant
```

## `gateway/certificate-profiles.json`

Eight profiles, one per CERTInext sandbox product. Each carries the
same `key_algs` block — the canonical "permit RSA 2048–8192 + ECDSA
P-256/384/521 + Ed25519/Ed448" policy. Match this `key_algs` shape on
new profiles to avoid Command's misleading `0xA0110004` "Key type
disallowed by policy" error.

> **Note:** The gateway profile defines what Command permits; CERTInext itself only
> accepts RSA 2048/3072/4096 and ECC P-256/P-384. Orders using P-521, Ed25519,
> Ed448, or RSA larger than 4096 bits are accepted by Command but rejected by
> CERTInext with `Invalid key size`.

The profiles **don't** carry CA-binding information; they're top-level
gateway resources. The CA configuration's `Templates[].CertificateProfile`
field is what binds a product to its profile by name.

## `gateway/claims.json`

The gateway authorisation table. Each row maps an OIDC subject (token
`sub`) to a gateway role. The lab seeds these on every
`init-gateway`:

- Two for the gateway's own machine client (admin + user — defensive)
- One for `akadmin` (the Authentik admin's `nameClaimType=sub`)

Production deployments add per-operator entries here. There are no
secrets in this file.

## `command/certificate-authority.json`

The single `LogicalName=certinext-caplugin` CA record after Command's
own redaction of the OAuth client secret (`ClientSecret.SecretValue` is
masked by Command on read). Useful as a shape reference for the
`POST /KeyfactorAPI/CertificateAuthorities` request body in
[QUICKSTART step 4](../../QUICKSTART.md#step-4--register-the-ca-in-command).
Read-only fields populated by Command (e.g. `Id`, `LastSyncTime`,
`SyncStatus`) are present but should not be set on create.

## `command/templates-certinext.json`

The eight Command templates created by `POST /KeyfactorAPI/Templates/Import`
(`ConfigurationTenant=certinext-caplugin`). Each is a 1-to-1 mapping
of a CERTInext sandbox product → a Command template named
`AnyCA_<ProductID>` and tied back to the CA by `ConfigurationTenant`.
Useful as a sanity check after running step 5 of the quickstart: the
template count and `CommonName` set should match this file (modulo
`Id` churn).
