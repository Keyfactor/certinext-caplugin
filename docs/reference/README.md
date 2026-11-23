# Reference JSON — known-working lab state

Sanitised JSON captures of a fully-configured CERTInext lab. Useful as
**wire-format reference** when you're writing or debugging
configuration scripts: every blob here is what the live gateway and
Command returned (POST/PUT bodies aren't shown — those are documented
in [`QUICKSTART.md`](../../QUICKSTART.md)).

## Source

Captured on 2026-05-22 from a local reference lab (a single-node
Kubernetes deployment of Command, the AnyCA REST Gateway, and an OIDC
identity provider), then trimmed to the CERTInext-relevant subset.
Sensitive fields are either already masked by the upstream API
(`ClientSecret`) or omitted entirely (no access keys, no PAM literals).
Hostnames and identity-provider values in the files are lab-specific
examples; replace them with your own.

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

Eight profiles, covering eight of the ten advertised products (the
non-EV ones). Each carries the same `key_algs` block, which is the lab's
deliberately broad policy:

| Algorithm | Permitted in this capture | Accepted by CERTInext |
|---|---|---|
| RSA | 2048, 3072, 4096, 6144, 8192 | 2048, 3072, 4096 only |
| ECDSA | P-256, P-384, P-521 | P-256, P-384 only |
| Ed25519 / Ed448 | Both | Neither |

Always include a populated `key_algs` block on new profiles, or Command
reports a misleading `0xA0110004` "Key type disallowed by policy" error.
Do **not** copy this capture's broad policy. The gateway profile defines
what Command permits; CERTInext rejects the extra key types with
`Invalid key size`. The recommended, narrower policy is in
[QUICKSTART step 2](../../QUICKSTART.md#key-algorithm-policy).

The profiles **don't** carry CA-binding information; they're top-level
gateway resources. The CA configuration's `Templates[].CertificateProfile`
field is what binds a product to its profile by name.

## `gateway/claims.json`

The gateway authorisation table. Each row maps an OIDC subject (token
`sub`) to a gateway role. The lab has three entries:

- Two for the gateway's own machine client (admin + user, defensive)
- One for the identity provider's admin user (`akadmin` in this lab)

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
(`ConfigurationTenant=certinext-caplugin`). Each maps one non-EV
CERTInext product to one Command template and is tied back to the CA
by `ConfigurationTenant`.

| Field | Value | Example |
|---|---|---|
| `CommonName` | `AnyCA_<ProductID>` | `AnyCA_DV SSL` |
| `TemplateName` / `DisplayName` | `AnyCA (<ProductID>)` | `AnyCA (DV SSL)` |

Useful as a sanity check after running step 5 of the quickstart: the
template count and `CommonName` set should match this file (modulo
`Id` churn).
