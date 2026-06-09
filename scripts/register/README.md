# CERTInext gateway/Command registration scripts

Provision the CERTInext AnyCA REST Gateway plugin into the **AnyCA REST Gateway**
and **Keyfactor Command**: gateway certificate profiles, the gateway CA
configuration, Command template import, enrollment patterns, and template
key-retention. Driven by `integration-manifest.json` (`.about.carest.product_ids`)
so it stays in sync with the plugin's products.

These scripts talk to **Command and the gateway admin API** — *not* the CERTInext
vendor API. Shared auth/host logic lives in [`../lib/command-auth.sh`](../lib/command-auth.sh).

## Stages

| Stage | Script | `make` target | Side | Notes |
|------:|--------|---------------|------|-------|
| 01 | `01-gateway-profiles.sh` | `register-profiles` | Gateway | one cert profile per product. **Verified.** |
| 02 | `02-gateway-ca-config.sh` | `register-ca-config` | Gateway | CAConnection + Templates[]. ⚠️ touches CA config — opt-in. |
| 03 | `03-gateway-claims.sh` | `register-claims` | Gateway | OAuth claim→role mappings. Unverified. |
| 04 | `04-command-register-ca.sh` | `register-command-ca` | Command | registers the CA. ⚠️ **CA config — leave alone unless asked.** |
| 05 | `05-command-import-templates.sh` | `register-import` | Command | `POST /Templates/Import`. |
| 06 | `06-command-enrollment-patterns.sh` | `register-enrollment` | Command | enrollment patterns + template key-retention. **Verified.** |
| — | `00-register-all.sh` | `register` | both | runs 01→06; skips missing stages and `SKIP_NN=1`. |

Every stage: idempotent (GET→POST/PUT), supports `DRY_RUN=1` (offline preview),
and reads `~/.env_certinext` + the env contract below.

> ⚠️ **Do not modify the CA configuration** (stage 04, and stage 02's CA-connection
> PUT) unless explicitly asked — it is fragile and easily broken. Profiles,
> template import, enrollment patterns, and key-retention are safe to re-run.

## Authentication

Three ways to authenticate, resolved per side (gateway vs Command) in this order:

1. **Session cookie** — `GATEWAY_COOKIE` / `COMMAND_COOKIE`. Paste the full
   `cookie:` header value from your browser devtools (Copy-as-cURL) into a file:
   ```sh
   pbpaste > ~/.certinext_kfcportal_cookie    # re-copy the cookie in devtools first
   chmod 600 ~/.certinext_kfcportal_cookie
   export COMMAND_COOKIE="$(tr -d '\r\n' < ~/.certinext_kfcportal_cookie)"
   ```
   The `tr -d` strips the trailing newline (a newline in the header → silent 401).
2. **Bearer token** — `GATEWAY_TOKEN` / `COMMAND_TOKEN` (e.g. copied from an API
   request's `authorization: Bearer` header).
3. **OAuth2 client_credentials** — `TOKEN_URL` + `OIDC_CLIENT_ID` +
   `OIDC_CLIENT_SECRET` (gateway uses scope `keyfactor-anyca-gateway`).

### Auth gotchas learned the hard way

- **The gateway authenticates its admin API with the session cookie directly.**
  **Command does not** — a `KeyfactorOIDC*` cookie only works against
  **`/KeyfactorProxy`** (the Portal's reverse proxy that injects the bearer),
  *not* `/KeyfactorAPI` (which returns 401 for a cookie). The lib auto-selects
  `COMMAND_BASE_PATH=/KeyfactorProxy` whenever `COMMAND_COOKIE` is set.
- Cookie mode sends the browser's CSRF headers (`x-requested-with: XMLHttpRequest`)
  automatically.
- Tokens/cookies are short-lived; a `401` mid-run usually just means re-grab.

## Environment contract

| Var | Used by | Notes |
|-----|---------|-------|
| `GATEWAY_HOST` | gateway stages | host only, no scheme |
| `GATEWAY_BASE_PATH` | gateway stages | **the gateway instance mount path** — e.g. `/certinext-0`, *not* `/AnyGatewayREST` on a multi-instance gateway. Find it in the Portal/Swagger URL. |
| `GATEWAY_COOKIE` / `GATEWAY_TOKEN` | gateway stages | see Authentication |
| `COMMAND_HOST` | command stages | host only |
| `COMMAND_BASE_PATH` | command stages | auto: `/KeyfactorProxy` if cookie, else `/KeyfactorAPI` |
| `COMMAND_COOKIE` / `COMMAND_TOKEN` | command stages | see Authentication |
| `CONFIGURATION_TENANT` | stages 04–06 | **= the gateway instance name** (e.g. `certinext-0`), which is also the templates' `ConfigurationTenant` in Command. Not the plugin name. |
| `CURL_INSECURE` | all | `1` (default) passes `-k`; set `0` to verify TLS |

## Quick start (cookie auth — the common case)

```sh
# --- gateway side ---
export GATEWAY_HOST=intdev01.lab.kfpki.com
export GATEWAY_BASE_PATH=/certinext-0
export GATEWAY_COOKIE="$(tr -d '\r\n' < ~/.certinext_gw_cookie)"
make register-profiles            # stage 01  (add CHECK=1 to verify, DRY_RUN=1 to preview)

# --- command side (after you've imported templates) ---
export COMMAND_HOST=intdev01.lab.kfpki.com
export CONFIGURATION_TENANT=certinext-0
export COMMAND_COOKIE="$(tr -d '\r\n' < ~/.certinext_kfcportal_cookie)"
make register-enrollment          # stage 06: patterns + KeyRetention=Indefinite
```

Per-stage env knobs are documented in each script's header comment.

## Stage 06 — Command EnrollmentPatterns schema (verified 2026-06-09)

The `/KeyfactorProxy/EnrollmentPatterns` (API v1) POST body that works — the stub
originally got every one of these wrong:

```json
{
  "Name": "AnyCA (DV SSL)",
  "Template": 1,                       // INTEGER, not {"Id":1}
  "AllowedEnrollmentTypes": 3,         // PLURAL (singular is ignored → 0 = no enroll). 3 = CSR+PFX
  "TemplateDefault": true,             // required for a template's default pattern
  "AssociatedRoles": ["Command Admin"],// role NAME strings that must already exist
  "Policies": {}                       // REQUIRED; empty object is accepted
}
```

- **Update** an existing pattern with `PUT /EnrollmentPatterns/{id}` (collection
  `PUT` returns **405**).
- Role names are instance-specific — this Command has **`Command Admin`**, not
  `InstanceAdmin`. Check `GET /Security/Roles` and set `ENROLL_ROLE` accordingly.

### Template key-retention

`PUT /Templates` with a **partial** body — other fields are preserved:

```json
{ "Id": 1, "KeyRetention": "Indefinite", "KeyRetentionDays": 0 }
```

Set via `TEMPLATE_KEY_RETENTION` (default `Indefinite`). Imported templates
default to `None`, so this is needed to retain private keys.

## Environment notes for whoever runs this

- **macOS ships bash 3.2** and the default shell is often **zsh**. The scripts use
  `#!/usr/bin/env bash` and avoid bash-4 features (`mapfile`) + zsh word-split
  pitfalls (loops use `while read`, not `for x in $unquoted`). Keep it that way
  if you edit them.
- `docs/reference/` holds captured "known-good" JSON (profiles, templates, CA,
  claims) used as validation oracles (`CHECK=1` on stages 01/05).
