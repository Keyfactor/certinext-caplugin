# scripts/v2 — CERTInext V2 REST API dev helpers

Small curl + jq scripts for poking the CERTInext V2 API (`/api/certinext/v2/...`) by hand.
They are dev tooling only and are not shipped with the plugin. For repeatable live-API
verification, use `CERTInext.IntegrationTests` / `CERTInext.IntegrationRunner` instead
(see `CLAUDE.md`).

## Auth and credentials

The scripts use the same auth model as the plugin's V2 mode
(`CERTInextClient.GetOrRefreshV2TokenAsync`):

```
POST {CERTINEXT_API_URL}/oauth/token        (application/x-www-form-urlencoded)
grant_type=client_credentials&client_id=...&client_secret=...
```

`CERTINEXT_API_URL` is the single V2 base URL, e.g. `https://sandbox-us.certinext.io`
(no `/emSignHub-API` suffix). The old `CERTINEXT_V2_API_URL` variable and the V1 SHA256
`authKey` token exchange are gone.

Credentials are read from `~/.env_certinext_v2`, the same file the V2 integration tests
use. Set `CERTINEXT_V2_ENV_FILE=/path/to/file` to use a different file.

| Key | Required | Used by |
|-----|----------|---------|
| `CERTINEXT_API_URL` | yes | all |
| `CERTINEXT_CLIENT_ID` | yes | all |
| `CERTINEXT_CLIENT_SECRET` | yes | all |
| `CERTINEXT_REQUESTOR_EMAIL` | order-create only | `create-ssl-order`, `create-private-pki-order` |
| `CERTINEXT_REQUESTOR_NAME`, `CERTINEXT_REQUESTOR_MOBILE` | no (defaults) | order-create, `accept-agreement` |
| `CERTINEXT_SIGNER_IP` | no (auto-detected via api.ipify.org) | `create-ssl-order`, `accept-agreement` |

How the file is read (see `scripts/lib/certinext-v2-auth.sh`):

- The file is parsed as `KEY=VALUE` lines, never `source`d. It can't run code, and nothing
  from it leaks into your shell. Blank lines and `#` comments are skipped, and one pair of
  surrounding `"` or `'` quotes is stripped from each value.
- A value in the file wins over a same-named exported env var, the same way
  `V2EnvHelper.LoadEnvFile` works. A shell that sourced the V1 `~/.env_certinext` exports
  a V1 `CERTINEXT_API_URL`, and that must not leak in. Exported env vars only fill in keys
  the file doesn't define.
- A missing required key fails fast and names the key and file.
- `CERTINEXT_API_URL` must be `https://`. Plain `http://` is accepted only for
  `localhost` / `127.0.0.1` stubs. A URL containing `/emSignHub-API` is rejected as a V1 URL.

Secret handling: the client secret and the bearer token are held only in unexported shell
variables. They reach curl through process substitution (`/dev/fd` pipes), so they never
show up in `ps` output, on disk, or on stdout/stderr. On a failed token request, the scripts
print only the HTTP status and the short OAuth2 `error` code, never the response body.
Don't run these scripts with `set -x` / `bash -x`.

Requires `bash`, `curl` (7.55+ for `-H @file`), and `jq`.

## Read-only scripts

These run immediately and send only GET requests (plus the token request).

| Script | Inputs | Endpoint |
|--------|--------|----------|
| `ping.sh` | — | `GET /auth/me` |
| `list-products.sh` | — | `GET /catalog/products` |
| `get-custom-fields.sh` | `PRODUCT_CODE` | `GET /catalog/products/{code}/custom-fields` |
| `list-groups.sh` | — | `GET /groups` |
| `list-organizations.sh` | — | `GET /organizations` |
| `list-domains.sh` | — | `GET /domains` |
| `orders-report.sh` | `[PAGE=1] [SIZE=100]` | `GET /reports/orders` (1-based paging) |
| `track-order.sh` | `ORDER_ID` | `GET /ssl-certificates/{id}` |
| `get-dcv.sh` | `ORDER_ID`, `DOMAIN` | `GET /ssl-certificates/{id}/dcv?domain=` |
| `download-certificate.sh` | `ORDER_ID` | `GET /ssl-certificates/{id}/certificate` |
| `track-private-pki.sh` | `ORDER_ID` | `GET /private-pki-certificates/{id}` |
| `download-certificate-private-pki.sh` | `ORDER_ID` | `GET /private-pki-certificates/{id}/certificate` |

## Mutating scripts (`--yes-mutate` required)

These scripts change state on the CERTInext account, and some of them are irreversible or
cost money. Without `--yes-mutate`, a script prints the request it would send (method, URL,
JSON body) and exits with status 3. The preview makes no network calls: it doesn't fetch a
token or look up the signer IP.

| Script | Effect | Inputs |
|--------|--------|--------|
| `create-ssl-order.sh` | places an SSL order | `PRODUCT_CODE`, `DOMAIN`, `[VARIANT=dv]` |
| `create-private-pki-order.sh` | places a Private PKI order | `PRODUCT_CODE`, `CERT_HOSTNAME`, `CA_PROFILE_ID`, `MASTER_PRODUCT_ID` |
| `verify-dcv.sh` | asks the CA to check DCV, which can advance the order | `ORDER_ID`, `DOMAIN`, `[METHOD=http-url]` |
| `submit-csr.sh` | attaches a CSR to an SSL order, which advances it | `ORDER_ID`, `CSR_FILE` |
| `submit-csr-private-pki.sh` | attaches a CSR, and the customer CA signs immediately | `ORDER_ID`, `CSR_FILE` |
| `accept-agreement.sh` | accepts the Subscriber Agreement, and the CA issues | `ORDER_ID` |
| `cancel-ssl-order.sh` | cancels an unissued SSL order | `ORDER_ID` |
| `revoke-ssl.sh` | revokes an issued SSL certificate (irreversible) | `ORDER_ID`, `[REASON=superseded]` |
| `revoke-private-pki.sh` | revokes a Private PKI certificate (irreversible) | `ORDER_ID`, `[REASON=superseded]` |

`create-private-pki-order.sh` takes `CERT_HOSTNAME`, not `HOSTNAME`. Bash always sets
`HOSTNAME` to the local machine name, so the old input silently fell back to this
workstation's hostname.

## Examples

```bash
scripts/v2/ping.sh
ORDER_ID=1234567890 scripts/v2/track-order.sh

# Preview only (prints the request and exits 3):
ORDER_ID=1234567890 scripts/v2/revoke-ssl.sh
# Actually revoke:
ORDER_ID=1234567890 scripts/v2/revoke-ssl.sh --yes-mutate

# Via make: mutating targets forward V2_ARGS to the script.
make v2-revoke-ssl ORDER_ID=1234567890 V2_ARGS=--yes-mutate
```
