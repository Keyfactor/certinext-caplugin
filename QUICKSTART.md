# CERTInext CA Plugin — Quickstart

End-to-end setup for the **CERTInext (eMudhra) CA plugin** running behind
the Keyfactor AnyCA REST Gateway. Walks an operator from "plugin DLL is
on the gateway pod" to "Keyfactor Command can enroll an end-entity
certificate through the plugin" with copy-pasteable scripts.

Each step is shown twice: a Bash + curl block and a PowerShell block.
Use whichever fits your shell. Variables flow forward through the doc,
so set them once and reuse them.

---

## What this guide covers

1. Authenticate to the gateway and to Command (client-credentials OAuth)
2. Create a **gateway certificate profile** for each CERTInext product
   (a top-level key-algorithm policy, not tied to any CA yet)
3. Create the **gateway CA** (the plugin connection + a `Templates[]`
   array that references the profiles from step 2 by name)
4. **Register the gateway CA in Command** so Command can talk to it
5. **Import templates from the gateway into Command** as
   `AnyCA_<ProductID>` templates Command can enroll against
6. **Enroll a test certificate** end-to-end

The CERTInext sandbox returns orders in `EXTERNAL_VALIDATION` status
(pending DCV or manual review), so the final enrollment test reports a
pending result by design — that's success.

### Data model & dependency order

It's easy to swap steps 2 and 3 by accident — both have things called
"templates" in them. The actual gateway data model is:

```
gateway certificateprofile  (top-level, independent of any CA)
        |
        | referenced by name
        v
gateway CA configuration    (one record with a Templates[] array;
                             each entry maps ProductID -> profile)
        |
        | Command queries this
        v
Command CA registration     (/KeyfactorAPI/CertificateAuthorities)
        |
        | ConfigurationTenant ties to this
        v
Command templates           (/KeyfactorAPI/Templates/Import)
```

So gateway profiles **must** exist before the gateway CA config that
references them, and the gateway CA config **must** exist before
Command can register it or import templates from it. Hence steps 2 → 3
→ 4 → 5 in that order.

### Reference JSON for each step

Each step that creates GET-able state has a sanitised JSON snapshot in
[`docs/reference/`](docs/reference/) from a known-working lab. Linked
again inline in each step's intro:

| Step | Reference file |
|---|---|
| 2 — gateway profiles | [`docs/reference/gateway/certificate-profiles.json`](docs/reference/gateway/certificate-profiles.json) |
| 3 — gateway CA config | not GET-able (HTTP 405); see [`docs/reference/gateway/claims.json`](docs/reference/gateway/claims.json) for the authz table this step seeds |
| 4 — Command CA | [`docs/reference/command/certificate-authority.json`](docs/reference/command/certificate-authority.json) |
| 5 — Command templates | [`docs/reference/command/templates-certinext.json`](docs/reference/command/templates-certinext.json) |

---

## Prerequisites

| Component | Required state |
|---|---|
| Keyfactor Command | Deployed and reachable at `${COMMAND_URL}` |
| AnyCA REST Gateway | Deployed and reachable at `${GATEWAY_URL}` |
| CERTInext plugin DLL | Already staged at `/app/Extensions/certinext-caplugin/` on the gateway pod; gateway has been restarted since |
| Identity Provider | OIDC client credentials issued for both the gateway and Command (Authentik, Keycloak, Entra, etc.) |
| CERTInext sandbox account | AccessKey, AccountNumber, GroupNumber, OrganizationNumber, registered requestor email |
| CERTInext sandbox PEM | The combined intermediate + root certificate for the CERTInext sandbox issuer (required for `GatewayCertificate.ImportedCertificate`) |

If any of those aren't true, finish the prerequisite work before
returning here. See the README's **Installation** and **Configuration**
sections for the underlying setup.

---

## Step 0 — Variables

Set these once at the top of your shell; the rest of the doc reuses them.

### Bash

```bash
# URLs
export COMMAND_URL="https://command.example.com"
export GATEWAY_URL="https://gateway.example.com"
export TOKEN_URL="https://auth.example.com/application/o/token/"

# OIDC client credentials
export CMD_CLIENT_ID="<command-client-id>"
export CMD_CLIENT_SECRET="<command-client-secret>"
export GW_CLIENT_ID="<gateway-client-id>"
export GW_CLIENT_SECRET="<gateway-client-secret>"

# CERTInext sandbox creds
export CERTINEXT_API_URL="https://sandbox-us-api.certinext.io/emSignHub-API"
export CERTINEXT_ACCESS_KEY="<your-access-key>"
export CERTINEXT_ACCOUNT_NUMBER="<your-account-number>"
export CERTINEXT_GROUP_NUMBER="<your-group-number>"
export CERTINEXT_ORG_NUMBER="<your-org-number>"
export CERTINEXT_REQUESTOR_NAME="Your Name"
export CERTINEXT_REQUESTOR_EMAIL="you@example.com"
export CERTINEXT_SIGNER_IP="$(curl -s https://api.ipify.org)"

# Names you'll reference in Command after setup
export CA_LOGICAL_NAME="certinext-caplugin"   # also used as ConfigurationTenant
export PRODUCT_ID="DV SSL"                    # the first product to register
export PRODUCT_CODE="842"                     # sandbox DV SSL product code

# Sandbox issuer chain file (PEM, intermediate + root concatenated)
export SANDBOX_CHAIN_PEM="${HOME}/certinext-sandbox-chain.pem"
```

### PowerShell

```powershell
# URLs
$CommandUrl       = "https://command.example.com"
$GatewayUrl       = "https://gateway.example.com"
$TokenUrl         = "https://auth.example.com/application/o/token/"

# OIDC client credentials
$CmdClientId      = "<command-client-id>"
$CmdClientSecret  = "<command-client-secret>"
$GwClientId       = "<gateway-client-id>"
$GwClientSecret   = "<gateway-client-secret>"

# CERTInext sandbox creds
$CertInextApiUrl         = "https://sandbox-us-api.certinext.io/emSignHub-API"
$CertInextAccessKey      = "<your-access-key>"
$CertInextAccountNumber  = "<your-account-number>"
$CertInextGroupNumber    = "<your-group-number>"
$CertInextOrgNumber      = "<your-org-number>"
$CertInextRequestorName  = "Your Name"
$CertInextRequestorEmail = "you@example.com"
$CertInextSignerIp       = (Invoke-RestMethod -Uri "https://api.ipify.org").ToString()

# Names you'll reference in Command after setup
$CaLogicalName    = "certinext-caplugin"      # also used as ConfigurationTenant
$ProductId        = "DV SSL"                  # the first product to register
$ProductCode      = "842"                     # sandbox DV SSL product code

# Sandbox issuer chain file (PEM, intermediate + root concatenated)
$SandboxChainPem  = Join-Path $HOME "certinext-sandbox-chain.pem"
```

> **TLS note.** Examples use `-k` (curl) / `-SkipCertificateCheck`
> (PowerShell 7+). Remove these when you're targeting a properly-trusted
> Command / Gateway in production.

---

## Step 1 — Get OAuth tokens

Both the gateway's `/AnyGatewayREST/config/*` API and Command's
`/KeyfactorAPI/*` API use OAuth2 client credentials. Mint one token for
each; they're independent.

### Bash

```bash
GW_TOKEN=$(curl -sk -X POST "${TOKEN_URL}" \
  -d "grant_type=client_credentials" \
  -d "client_id=${GW_CLIENT_ID}" \
  -d "client_secret=${GW_CLIENT_SECRET}" \
  -d "scope=keyfactor-anyca-gateway" \
  | jq -r '.access_token')

CMD_TOKEN=$(curl -sk -X POST "${TOKEN_URL}" \
  -d "grant_type=client_credentials" \
  -d "client_id=${CMD_CLIENT_ID}" \
  -d "client_secret=${CMD_CLIENT_SECRET}" \
  | jq -r '.access_token')

[ -n "${GW_TOKEN}"  ] || { echo "gateway token mint failed"; exit 1; }
[ -n "${CMD_TOKEN}" ] || { echo "command token mint failed"; exit 1; }
```

### PowerShell

```powershell
$GwToken = (Invoke-RestMethod -Method Post -Uri $TokenUrl -SkipCertificateCheck `
    -Body @{
        grant_type    = "client_credentials"
        client_id     = $GwClientId
        client_secret = $GwClientSecret
        scope         = "keyfactor-anyca-gateway"
    }).access_token

$CmdToken = (Invoke-RestMethod -Method Post -Uri $TokenUrl -SkipCertificateCheck `
    -Body @{
        grant_type    = "client_credentials"
        client_id     = $CmdClientId
        client_secret = $CmdClientSecret
    }).access_token

if (-not $GwToken)  { throw "gateway token mint failed"  }
if (-not $CmdToken) { throw "command token mint failed" }
```

---

## Step 2 — Create the gateway certificate profile

> **Reference state after this step:** see
> [`docs/reference/gateway/certificate-profiles.json`](docs/reference/gateway/certificate-profiles.json)
> for the final 8-profile shape (one per sandbox product) the gateway
> returns from `GET /AnyGatewayREST/config/certificateprofile` after
> all profiles are in place.

A **certificate profile** on the gateway is a top-level resource: a
named key-algorithm policy that's independent of any CA. CA
configurations (created in step 3) reference these profiles by name
through their `Templates[]` array, so the profile must exist first.

The profile sets the key constraints (allowed algorithms, sizes,
curves) the gateway enforces on incoming CSRs / key generations for any
ProductID bound to it. One profile can be shared by many CA configs;
in this guide we use a 1-to-1 profile-per-ProductID convention because
the `WirePlugin` code path in `kfclab` does the same.

Without an explicit `key_algs` block the gateway uses an empty default
that Command interprets as "no key types allowed" — PFX enrollment then
fails with `0xA0110004` ("Key type 'RSA' is unsupported or disallowed by
policy"). The body below is the canonical "permit everything we care
about" payload.

### Bash

```bash
KEY_ALGS='{
  "rsa":     {"bit_lengths":[2048,3072,4096]},
  "ecdsa":   {"curves":["1.2.840.10045.3.1.7","1.3.132.0.34","1.3.132.0.35"]},
  "ed25519": {"bit_lengths":[255]}
}'

PROFILE_BODY=$(jq -n \
  --arg name "${PRODUCT_ID}" \
  --argjson key_algs "${KEY_ALGS}" \
  '{name: $name, key_algs: $key_algs}')

curl -sk -X POST "${GATEWAY_URL}/AnyGatewayREST/config/certificateprofile" \
  -H "Authorization: Bearer ${GW_TOKEN}" \
  -H "x-keyfactor-requested-with: APIClient" \
  -H "Content-Type: application/json" \
  -d "${PROFILE_BODY}" \
  -w "\nHTTP %{http_code}\n"
```

If the profile already exists this POST returns a 4xx; that's fine.
For idempotent updates, GET the profile, extract its `id`, then PUT:

```bash
PROFILE_ID=$(curl -sk "${GATEWAY_URL}/AnyGatewayREST/config/certificateprofile" \
  -H "Authorization: Bearer ${GW_TOKEN}" \
  -H "x-keyfactor-requested-with: APIClient" \
  | jq -r --arg n "${PRODUCT_ID}" '.[] | select(.name == $n) | .id')

curl -sk -X PUT "${GATEWAY_URL}/AnyGatewayREST/config/certificateprofile" \
  -H "Authorization: Bearer ${GW_TOKEN}" \
  -H "x-keyfactor-requested-with: APIClient" \
  -H "Content-Type: application/json" \
  -d "$(echo "${PROFILE_BODY}" | jq --argjson id "${PROFILE_ID}" '. + {id: $id}')"
```

### PowerShell

```powershell
$KeyAlgs = @{
    rsa     = @{ bit_lengths = @(2048, 3072, 4096) }
    ecdsa   = @{ curves = @(
        "1.2.840.10045.3.1.7",   # secp256r1 (P-256)
        "1.3.132.0.34",          # secp384r1 (P-384)
        "1.3.132.0.35"           # secp521r1 (P-521)
    ) }
    ed25519 = @{ bit_lengths = @(255) }
}

$ProfileBody = @{
    name     = $ProductId
    key_algs = $KeyAlgs
} | ConvertTo-Json -Depth 10

$Headers = @{
    "Authorization"            = "Bearer $GwToken"
    "x-keyfactor-requested-with" = "APIClient"
    "Content-Type"             = "application/json"
}

try {
    Invoke-RestMethod -Method Post `
        -Uri "$GatewayUrl/AnyGatewayREST/config/certificateprofile" `
        -Headers $Headers -Body $ProfileBody -SkipCertificateCheck
} catch {
    # Already exists — fetch its id and PUT instead.
    $existing = Invoke-RestMethod -Method Get `
        -Uri "$GatewayUrl/AnyGatewayREST/config/certificateprofile" `
        -Headers $Headers -SkipCertificateCheck
    $profile = $existing | Where-Object { $_.name -eq $ProductId } | Select-Object -First 1
    if ($profile) {
        $UpdateBody = @{
            id       = $profile.id
            name     = $ProductId
            key_algs = $KeyAlgs
        } | ConvertTo-Json -Depth 10
        Invoke-RestMethod -Method Put `
            -Uri "$GatewayUrl/AnyGatewayREST/config/certificateprofile" `
            -Headers $Headers -Body $UpdateBody -SkipCertificateCheck
    }
}
```

> **Doing this for all 8 sandbox products?** Wrap Steps 2 and 3 in a
> loop over the (ProductID, ProductCode) pairs. The sandbox product
> codes are 842 (DV SSL), 843 (DV Wildcard), 844 (DV UCC), 845 (DV
> Wildcard UCC), 846 (OV SSL), 847 (OV Wildcard), 848 (OV UCC), 849
> (OV Wildcard UCC).

---

## Step 3 — Create the gateway CA configuration

> **Reference state after this step:**
> [`docs/reference/gateway/claims.json`](docs/reference/gateway/claims.json)
> shows the gateway authz table — the `akadmin` admin claim is added
> as part of this step on the kfclab path, so authenticated human users
> can hit the gateway UI without being denied.
>
> The CA configuration itself is **not GET-able** (the gateway returns
> HTTP 405 on `GET /config/configuration` — POST/PUT only), so there's
> no live JSON snapshot to compare against. The exact body shape this
> step submits is documented in the script blocks below.

This is the **single biggest configuration step**. It creates the
gateway-side CA record, which has four jobs:

- Tell the gateway how to authenticate to the CERTInext API
  (`CAConnection` block)
- Give the CA a logical name and an issuer chain to present to Command
  (`GatewayRegistration` block)
- Schedule sync intervals (`ServiceSettings` block)
- **Map each ProductID to the gateway certificate profile from step 2**
  (`Templates[]` array — `Templates[*].CertificateProfile` must match
  a profile name created in step 2)

The CA configuration is what Command later queries (in step 4 and
step 5) to learn about this CA. Until this POST/PUT lands, the gateway
has no CA configured and Command has nothing to register or import.

The shape uses four top-level keys:

| Key | Purpose |
|---|---|
| `CAConnection` | The CERTInext plugin's connection config (auth + identifying numbers). All `RequestorIsdCode`, `RequestorMobileNumber`, `SignerPlace`, `Enabled` etc. live here. |
| `GatewayRegistration` | `LogicalName` (what Command will see) + `GatewayCertificate.ImportedCertificate` (PEM blob, base64-of-PEM is also accepted). |
| `ServiceSettings` | Scan intervals; tune for your environment. |
| `Templates[]` | The (ProductID → CertificateProfile) mapping. Parameters carry per-product config like `ProductCode` and `ValidityYears`. |

`POST` creates; `PUT` updates an existing config. Most operators end up
using `PUT` after the first run.

### Bash

```bash
GATEWAY_CERT_PEM=$(cat "${SANDBOX_CHAIN_PEM}")

CONFIG_BODY=$(jq -n \
  --arg api_url      "${CERTINEXT_API_URL}" \
  --arg account      "${CERTINEXT_ACCOUNT_NUMBER}" \
  --arg group        "${CERTINEXT_GROUP_NUMBER}" \
  --arg org          "${CERTINEXT_ORG_NUMBER}" \
  --arg access_key   "${CERTINEXT_ACCESS_KEY}" \
  --arg req_name     "${CERTINEXT_REQUESTOR_NAME}" \
  --arg req_email   "${CERTINEXT_REQUESTOR_EMAIL}" \
  --arg signer_ip    "${CERTINEXT_SIGNER_IP}" \
  --arg logical      "${CA_LOGICAL_NAME}" \
  --arg cert         "${GATEWAY_CERT_PEM}" \
  --arg product_id   "${PRODUCT_ID}" \
  --arg product_code "${PRODUCT_CODE}" \
'{
  "CAConnection": {
    "ApiUrl":             $api_url,
    "AccountNumber":      $account,
    "GroupNumber":        $group,
    "OrganizationNumber": $org,
    "AuthMode":           "AccessKey",
    "ApiKey":             $access_key,
    "RequestorName":      $req_name,
    "RequestorEmail":     $req_email,
    "RequestorIsdCode":   "1",
    "RequestorMobileNumber": "0000000000",
    "SignerPlace":        "Gateway",
    "SignerIp":           $signer_ip,
    "Enabled":            true
  },
  "GatewayRegistration": {
    "LogicalName": $logical,
    "GatewayCertificate": {
      "Source": "FileUpload",
      "ImportedCertificate": $cert
    }
  },
  "ServiceSettings": {
    "FullScan":        {"Daily":    {"Time":    "2:00"}},
    "IncrementalScan": {"Interval": {"Minutes": 60}}
  },
  "Templates": [
    {
      "ProductID":          $product_id,
      "Parameters":         {"ProductCode": $product_code, "ValidityYears": "1"},
      "CertificateProfile": $product_id
    }
  ]
}')

# POST first; if "already exists", fall through to PUT.
RESP=$(curl -sk -X POST "${GATEWAY_URL}/AnyGatewayREST/config/configuration" \
  -H "Authorization: Bearer ${GW_TOKEN}" \
  -H "x-keyfactor-requested-with: APIClient" \
  -H "Content-Type: application/json" \
  -d "${CONFIG_BODY}" -w "\nHTTP %{http_code}")
echo "${RESP}"

if echo "${RESP}" | grep -qiE "already exists|duplicate"; then
  curl -sk -X PUT "${GATEWAY_URL}/AnyGatewayREST/config/configuration" \
    -H "Authorization: Bearer ${GW_TOKEN}" \
    -H "x-keyfactor-requested-with: APIClient" \
    -H "Content-Type: application/json" \
    -d "${CONFIG_BODY}" -w "\nHTTP %{http_code}"
fi
```

### PowerShell

```powershell
$GatewayCertPem = Get-Content -Path $SandboxChainPem -Raw

$ConfigBody = @{
    CAConnection = @{
        ApiUrl                = $CertInextApiUrl
        AccountNumber         = $CertInextAccountNumber
        GroupNumber           = $CertInextGroupNumber
        OrganizationNumber    = $CertInextOrgNumber
        AuthMode              = "AccessKey"
        ApiKey                = $CertInextAccessKey
        RequestorName         = $CertInextRequestorName
        RequestorEmail        = $CertInextRequestorEmail
        RequestorIsdCode      = "1"
        RequestorMobileNumber = "0000000000"
        SignerPlace           = "Gateway"
        SignerIp              = $CertInextSignerIp
        Enabled               = $true
    }
    GatewayRegistration = @{
        LogicalName        = $CaLogicalName
        GatewayCertificate = @{
            Source              = "FileUpload"
            ImportedCertificate = $GatewayCertPem
        }
    }
    ServiceSettings = @{
        FullScan        = @{ Daily    = @{ Time    = "2:00" } }
        IncrementalScan = @{ Interval = @{ Minutes = 60     } }
    }
    Templates = @(
        @{
            ProductID          = $ProductId
            Parameters         = @{ ProductCode = $ProductCode; ValidityYears = "1" }
            CertificateProfile = $ProductId
        }
    )
} | ConvertTo-Json -Depth 10

$ConfigUri = "$GatewayUrl/AnyGatewayREST/config/configuration"

try {
    Invoke-RestMethod -Method Post -Uri $ConfigUri `
        -Headers $Headers -Body $ConfigBody -SkipCertificateCheck
} catch {
    # Already exists — PUT update instead.
    if ($_.Exception.Message -match "already exists|duplicate") {
        Invoke-RestMethod -Method Put -Uri $ConfigUri `
            -Headers $Headers -Body $ConfigBody -SkipCertificateCheck
    } else {
        throw
    }
}
```

After this completes, the gateway is fully wired to CERTInext. Confirm
by GETting the configuration back:

```bash
curl -sk "${GATEWAY_URL}/AnyGatewayREST/config/configuration" \
  -H "Authorization: Bearer ${GW_TOKEN}" \
  -H "x-keyfactor-requested-with: APIClient" | jq '.Templates'
```

You should see your `Templates[]` array with the (ProductID,
CertificateProfile) entries from above.

---

## Step 4 — Register the CA in Command

> **Reference state after this step:** see
> [`docs/reference/command/certificate-authority.json`](docs/reference/command/certificate-authority.json)
> for the full CA record Command returns from
> `GET /KeyfactorAPI/CertificateAuthorities` (filtered to the
> `LogicalName=certinext-caplugin` entry). Useful to compare against
> when debugging — every field the API populates is present, and
> `ClientSecret.SecretValue` is masked by Command on read.

Command needs to know the gateway exists and what auth to use when
talking to it. The CA registration carries the OAuth client used for
Command-to-gateway calls (the same gateway OAuth client from Step 1) and
the `ConfigurationTenant` that ties this registration to the gateway's
plugin (the plugin name — by convention `certinext-caplugin`).

Important fields:

| Field | Value | Why |
|---|---|---|
| `HostName` | `${GATEWAY_URL}/AnyGatewayREST/ejbca/ejbca-rest-api` | All AnyCA REST Gateway plugins are served behind the EJBCA-compatible prefix; Command speaks EJBCA REST to the gateway. |
| `CAType` | `1` | HTTPS (AnyCA REST). `0` is DCOM (legacy Windows). |
| `ConfigurationTenant` | `certinext-caplugin` | Must match the LogicalName the plugin uses; also the value you'll pass to `/Templates/Import` in Step 5. |
| `Scope` | `keyfactor-anyca-gateway` | The OAuth scope the gateway's token introspection allows. |
| `ClientSecret` | `{"SecretValue": "..."}` | Command's `KeyfactorSecret` shape; raw strings are rejected with `"Invalid JSON schema. Expected: 'StartObject' Received: 'String'"`. |

### Bash

```bash
CA_BODY=$(jq -n \
  --arg logical    "${CA_LOGICAL_NAME}" \
  --arg host       "${GATEWAY_URL}/AnyGatewayREST/ejbca/ejbca-rest-api" \
  --arg tenant     "${CA_LOGICAL_NAME}" \
  --arg token_url  "${TOKEN_URL}" \
  --arg client_id  "${GW_CLIENT_ID}" \
  --arg secret     "${GW_CLIENT_SECRET}" \
'{
  "LogicalName":                    $logical,
  "HostName":                       $host,
  "CAType":                         1,
  "ConfigurationTenant":            $tenant,
  "NewEndEntityOnRenewAndReissue":  true,
  "AllowOneClickRenewals":          true,
  "UseForEnrollment":               true,
  "KeyRetention":                   "Indefinite",
  "AllowedEnrollmentTypes":         3,
  "FullScan":                       {"Interval": {"Minutes": 720}},
  "IncrementalScan":                {"Interval": {"Minutes": 5}},
  "TokenURL":                       $token_url,
  "ClientId":                       $client_id,
  "ClientSecret":                   {"SecretValue": $secret},
  "Scope":                          "keyfactor-anyca-gateway"
}')

curl -sk -X POST "${COMMAND_URL}/KeyfactorAPI/CertificateAuthorities" \
  -H "Authorization: Bearer ${CMD_TOKEN}" \
  -H "x-keyfactor-requested-with: APIClient" \
  -H "x-keyfactor-api-version: 1" \
  -H "Content-Type: application/json" \
  -d "${CA_BODY}" -w "\nHTTP %{http_code}\n"
```

### PowerShell

```powershell
$CaBody = @{
    LogicalName                   = $CaLogicalName
    HostName                      = "$GatewayUrl/AnyGatewayREST/ejbca/ejbca-rest-api"
    CAType                        = 1
    ConfigurationTenant           = $CaLogicalName
    NewEndEntityOnRenewAndReissue = $true
    AllowOneClickRenewals         = $true
    UseForEnrollment              = $true
    KeyRetention                  = "Indefinite"
    AllowedEnrollmentTypes        = 3
    FullScan                      = @{ Interval = @{ Minutes = 720 } }
    IncrementalScan               = @{ Interval = @{ Minutes = 5   } }
    TokenURL                      = $TokenUrl
    ClientId                      = $GwClientId
    ClientSecret                  = @{ SecretValue = $GwClientSecret }
    Scope                         = "keyfactor-anyca-gateway"
} | ConvertTo-Json -Depth 10

$CmdHeaders = @{
    "Authorization"              = "Bearer $CmdToken"
    "x-keyfactor-requested-with" = "APIClient"
    "x-keyfactor-api-version"    = "1"
    "Content-Type"               = "application/json"
}

Invoke-RestMethod -Method Post `
    -Uri "$CommandUrl/KeyfactorAPI/CertificateAuthorities" `
    -Headers $CmdHeaders -Body $CaBody -SkipCertificateCheck
```

Verify the CA appears in Command:

```bash
curl -sk "${COMMAND_URL}/KeyfactorAPI/CertificateAuthorities" \
  -H "Authorization: Bearer ${CMD_TOKEN}" \
  -H "x-keyfactor-requested-with: APIClient" \
  | jq --arg n "${CA_LOGICAL_NAME}" '.[] | select(.LogicalName == $n)'
```

---

## Step 5 — Import templates into Command

> **Reference state after this step:** see
> [`docs/reference/command/templates-certinext.json`](docs/reference/command/templates-certinext.json)
> for the 8 templates Command creates from the 8 ProductIDs registered
> in Step 3 (filtered from `GET /KeyfactorAPI/Templates` by
> `ConfigurationTenant=certinext-caplugin`). Confirms the
> `AnyCA_<ProductID>` naming convention, the `ExtendedKeyUsages` set,
> the `KeyTypes` list synced from the gateway profile's `key_algs`,
> and the per-template `Id` / `Oid` shape.

Command's `/Templates/Import` endpoint asks the registered gateway CA
for its template list and creates corresponding Command-side templates
named `AnyCA_<ProductID>` (e.g. `AnyCA_DV SSL`). One call covers every
template you defined under `Templates[]` in Step 3.

### Bash

```bash
curl -sk -X POST "${COMMAND_URL}/KeyfactorAPI/Templates/Import" \
  -H "Authorization: Bearer ${CMD_TOKEN}" \
  -H "x-keyfactor-requested-with: APIClient" \
  -H "x-keyfactor-api-version: 1" \
  -H "Content-Type: application/json" \
  -d "{\"ConfigurationTenant\":\"${CA_LOGICAL_NAME}\"}" \
  -w "\nHTTP %{http_code}\n"

# Confirm the templates landed:
curl -sk "${COMMAND_URL}/KeyfactorAPI/Templates" \
  -H "Authorization: Bearer ${CMD_TOKEN}" \
  -H "x-keyfactor-requested-with: APIClient" \
  | jq '[.[] | select(.ShortName | startswith("AnyCA_"))] | map({Id, ShortName, DisplayName})'
```

### PowerShell

```powershell
$ImportBody = @{ ConfigurationTenant = $CaLogicalName } | ConvertTo-Json

Invoke-RestMethod -Method Post `
    -Uri "$CommandUrl/KeyfactorAPI/Templates/Import" `
    -Headers $CmdHeaders -Body $ImportBody -SkipCertificateCheck

# Confirm:
$AllTemplates = Invoke-RestMethod -Method Get `
    -Uri "$CommandUrl/KeyfactorAPI/Templates" `
    -Headers $CmdHeaders -SkipCertificateCheck

$AllTemplates `
    | Where-Object { $_.ShortName -like "AnyCA_*" } `
    | Select-Object Id, ShortName, DisplayName
```

> **Re-run after gateway profile changes.** Any time you update the
> gateway's `certificateprofile` `key_algs`, re-run this `/Templates/Import`
> call — Command caches the allowed key types per-template in
> `dbo.KeyAlgorithms` and only refreshes them through this endpoint. If
> you skip the re-import, PFX enrollment continues to fail with
> `0xA0110004` despite the gateway being correct.

---

## Step 6 — Verify with a test enrollment

End-to-end check. The CERTInext sandbox returns orders in
`EXTERNAL_VALIDATION` status (DCV or manual review pending), so a
**successful** verification returns **HTTP 200 with a null
`Pkcs12Blob`** and a `RequestDisposition` of `EXTERNAL_VALIDATION` —
that's the expected outcome, not a failure.

### Bash (PFX)

```bash
CN="qs-test-$(date +%s).example.com"

PFX_BODY=$(jq -n \
  --arg template "AnyCA_${PRODUCT_ID}" \
  --arg ca       "${CA_LOGICAL_NAME}" \
  --arg subject  "CN=${CN},O=Quickstart,C=US" \
  --arg ts       "$(date -u +%FT%TZ)" \
'{
  Template:             $template,
  CertificateAuthority: $ca,
  Subject:              $subject,
  Password:             "Tr@nsientP@ss1",
  IncludeChain:         true,
  SANs:                 {},
  Timestamp:            $ts
}')

curl -sk -X POST "${COMMAND_URL}/KeyfactorAPI/Enrollment/PFX" \
  -H "Authorization: Bearer ${CMD_TOKEN}" \
  -H "x-keyfactor-requested-with: APIClient" \
  -H "x-keyfactor-api-version: 1" \
  -H "Content-Type: application/json" \
  -d "${PFX_BODY}" | jq '{
    RequestDisposition: .CertificateInformation.RequestDisposition,
    DispositionMessage: .CertificateInformation.DispositionMessage,
    KeyfactorRequestId: .CertificateInformation.KeyfactorRequestId,
    WorkflowReferenceId: .CertificateInformation.WorkflowReferenceId
  }'
```

Expected output:

```json
{
  "RequestDisposition": "EXTERNAL_VALIDATION",
  "DispositionMessage": "The certificate request is being processed by the CA, and will be available at a later time.",
  "KeyfactorRequestId": 1,
  "WorkflowReferenceId": 1
}
```

### PowerShell (PFX)

```powershell
$Cn = "qs-test-$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()).example.com"

$PfxBody = @{
    Template             = "AnyCA_$ProductId"
    CertificateAuthority = $CaLogicalName
    Subject              = "CN=$Cn,O=Quickstart,C=US"
    Password             = "Tr@nsientP@ss1"
    IncludeChain         = $true
    SANs                 = @{}
    Timestamp            = (Get-Date).ToUniversalTime().ToString("o")
} | ConvertTo-Json -Depth 10

$Response = Invoke-RestMethod -Method Post `
    -Uri "$CommandUrl/KeyfactorAPI/Enrollment/PFX" `
    -Headers $CmdHeaders -Body $PfxBody -SkipCertificateCheck

[PSCustomObject]@{
    RequestDisposition  = $Response.CertificateInformation.RequestDisposition
    DispositionMessage  = $Response.CertificateInformation.DispositionMessage
    KeyfactorRequestId  = $Response.CertificateInformation.KeyfactorRequestId
    WorkflowReferenceId = $Response.CertificateInformation.WorkflowReferenceId
} | Format-List
```

You should see `RequestDisposition = EXTERNAL_VALIDATION`. The
gateway's `Certificates` table will have a new row at status `90`
(pending external validation); once CERTInext completes DCV / manual
review, the status flips to `40` (issued) and Command's next inventory
sync pulls down the actual certificate.

---

## Next steps

- **More products.** Re-run Steps 2 (one POST per product) and update
  the `Templates[]` array in Step 3's PUT to include all the
  (ProductID, ProductCode, CertificateProfile) tuples you want to use.
  Then re-run Step 5 (`/Templates/Import`) so Command picks up the new
  templates.
- **Production hardening.** Drop `-k` / `-SkipCertificateCheck`, swap
  the sandbox API URL for production
  (`https://api.certinext.io/emSignHub-API`), update the
  `GatewayCertificate.ImportedCertificate` to the production issuer
  chain, and rotate the access key.
- **CSR enrollment.** `/KeyfactorAPI/Enrollment/CSR` accepts the same
  body shape but with a `CSR` field instead of `Password`/`IncludeChain`.
  Useful when the requesting system already has a keypair it doesn't
  want to surface to Command.
- **Sandbox quota.** The CERTInext sandbox enforces a burst rate limit
  that surfaces as the misleading error string `"Inactive Account
  User."`. If you're submitting many test orders in tight succession
  and start seeing that error, throttle to one order every 1-2 seconds
  and wait ~5-25 minutes for the cooldown. Tracking issue:
  [Keyfactor/certinext-caplugin#8](https://github.com/Keyfactor/certinext-caplugin/issues/8).

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Step 5 returns 0 templates imported | `ConfigurationTenant` doesn't match between Steps 3 and 4 | Re-check both call to make sure the LogicalName / ConfigurationTenant agree. |
| Step 6 returns `0xA0110004` "Key type 'RSA' disallowed by policy" | Gateway `key_algs` are empty or wrong, or Command hasn't re-imported templates after a profile change | Update `key_algs` (Step 2), re-run `/Templates/Import` (Step 5). |
| Step 6 returns `0xA0010023` "external validation" with HTTP 400 | The gateway returned a pending response and Command's exception filter translated it — Command 25.x bug | The plugin DID accept the order. Confirm via `GET ${GATEWAY_URL}/AnyGatewayREST/.../v1/certificate/<id>`. Fixed in newer Command builds; rewrite as 200 with disposition `EXTERNAL_VALIDATION`. |
| Step 6 returns `"Inactive Account User."` from the gateway log | CERTInext sandbox rate limit | Wait 5-25 minutes; retry a single order to confirm the account is alive. See [#8](https://github.com/Keyfactor/certinext-caplugin/issues/8). |
| Step 6 returns `TypeLoadException IDomainValidatorFactory` in the gateway pod log | Older plugin DLL incompatible with the host gateway's `IAnyCAPlugin` version | Rebuild the plugin from `main` and re-stage; the field re-typing fix is required for gateways shipping `IAnyCAPlugin` < v3.3. |
