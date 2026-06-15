#!/usr/bin/env bash
# Shared OAuth2 + REST helpers for Keyfactor Command / AnyCA REST Gateway
# *provisioning* scripts (scripts/register/*).
#
# This is distinct from certinext-auth.sh: that helper signs CERTInext API
# requests (SHA256 authKey). This one talks to Command and the gateway admin
# API using an OAuth2 client_credentials bearer token.
#
# Usage:
#   . ~/.env_certinext
#   . "$(dirname "$0")/lib/command-auth.sh"
#   tok=$(gateway_token)
#   gw_curl "$tok" GET /config/certificateprofile
#
# Required env (set in ~/.env_certinext or exported before sourcing):
#   TOKEN_URL            OAuth token endpoint (Authentik), e.g.
#                        https://auth.127.0.0.1.nip.io/application/o/token/
#   OIDC_CLIENT_ID       client_credentials client id
#   OIDC_CLIENT_SECRET   client_credentials client secret
#   GATEWAY_HOST         gateway ingress host (no scheme)
#   COMMAND_HOST         Command ingress host (no scheme)
# Optional env (defaults shown):
#   GATEWAY_SCHEME       https
#   GATEWAY_BASE_PATH    /AnyGatewayREST   (gateway admin API prefix)
#   GATEWAY_SCOPE        keyfactor-anyca-gateway
#   COMMAND_SCHEME       https
#   CURL_INSECURE        1  (pass -k; set 0 to verify TLS)
#   CONFIGURATION_TENANT certinext-caplugin

GATEWAY_SCHEME="${GATEWAY_SCHEME:-https}"
# GATEWAY_BASE_PATH is the gateway *instance* mount path, NOT a fixed value.
# On a multi-tenant AnyCA REST Gateway each instance lives under its own path
# (e.g. /certinext-0). Discover it from the Portal/Swagger URL. The historical
# default /AnyGatewayREST only applies to single-instance gateways.
GATEWAY_BASE_PATH="${GATEWAY_BASE_PATH:-/AnyGatewayREST}"
GATEWAY_SCOPE="${GATEWAY_SCOPE:-keyfactor-anyca-gateway}"
COMMAND_SCHEME="${COMMAND_SCHEME:-https}"
# Command API base path. A Portal *session cookie* (COMMAND_COOKIE) only works
# against /KeyfactorProxy — the Portal's reverse proxy that injects the bearer
# token server-side. Direct bearer/OAuth auth uses /KeyfactorAPI. When unset,
# cmd_base() resolves it at call time from whether a cookie is set (so it works
# regardless of env-var ordering). Set COMMAND_BASE_PATH to force either path.
COMMAND_BASE_PATH="${COMMAND_BASE_PATH:-}"
CONFIGURATION_TENANT="${CONFIGURATION_TENANT:-certinext-caplugin}"
CURL_INSECURE="${CURL_INSECURE:-1}"

_ca_require() {
    local missing=0 v
    for v in "$@"; do
        if [ -z "${!v:-}" ]; then
            echo "ERROR: required env var '$v' is not set" >&2
            missing=1
        fi
    done
    [ "$missing" -eq 0 ] || return 1
}

# Base curl flags shared by every call (bash 3.2 compatible — global array).
CA_CURL_OPTS=(-sS)
[ "$CURL_INSECURE" = "1" ] && CA_CURL_OPTS+=(-k)

# oauth_token [scope] — fetch a client_credentials bearer token.
# Echoes the raw access_token. Exits non-zero (and prints the body) on failure.
oauth_token() {
    _ca_require TOKEN_URL OIDC_CLIENT_ID OIDC_CLIENT_SECRET || return 1
    local scope="${1:-}"
    local -a form=(
        --data-urlencode "grant_type=client_credentials"
        --data-urlencode "client_id=${OIDC_CLIENT_ID}"
        --data-urlencode "client_secret=${OIDC_CLIENT_SECRET}"
    )
    [ -n "$scope" ] && form+=(--data-urlencode "scope=${scope}")

    local resp tok
    resp=$(curl "${CA_CURL_OPTS[@]}" -X POST "$TOKEN_URL" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        "${form[@]}") || { echo "ERROR: token request failed" >&2; return 1; }
    tok=$(printf '%s' "$resp" | jq -r '.access_token // empty')
    if [ -z "$tok" ]; then
        echo "ERROR: no access_token in response:" >&2
        printf '%s\n' "$resp" >&2
        return 1
    fi
    printf '%s' "$tok"
}

# Auth resolution order (per side):
#   1. A browser-session cookie (GATEWAY_COOKIE / COMMAND_COOKIE) — paste the
#      full `cookie:` header value from devtools (Copy as cURL) when the UI uses
#      OIDC session cookies instead of bearer tokens. The *_token fns return
#      empty in this mode; gw_curl/cmd_curl send the Cookie header instead.
#   2. An explicit pre-obtained bearer token (GATEWAY_TOKEN / COMMAND_TOKEN).
#   3. OAuth2 client_credentials via oauth_token (needs OIDC_CLIENT_* + TOKEN_URL).
gateway_token() {
    if [ -n "${GATEWAY_COOKIE:-}" ]; then return 0; fi   # cookie mode
    if [ -n "${GATEWAY_TOKEN:-}" ]; then printf '%s' "$GATEWAY_TOKEN"; return 0; fi
    oauth_token "$GATEWAY_SCOPE"
}
command_token() {
    if [ -n "${COMMAND_COOKIE:-}" ]; then return 0; fi   # cookie mode
    if [ -n "${COMMAND_TOKEN:-}" ]; then printf '%s' "$COMMAND_TOKEN"; return 0; fi
    oauth_token ""
}

gw_base() {
    _ca_require GATEWAY_HOST || return 1
    printf '%s://%s%s' "$GATEWAY_SCHEME" "$GATEWAY_HOST" "$GATEWAY_BASE_PATH"
}
cmd_base() {
    _ca_require COMMAND_HOST || return 1
    local bp="$COMMAND_BASE_PATH"
    if [ -z "$bp" ]; then
        if [ -n "${COMMAND_COOKIE:-}" ]; then bp="/KeyfactorProxy"; else bp="/KeyfactorAPI"; fi
    fi
    printf '%s://%s%s' "$COMMAND_SCHEME" "$COMMAND_HOST" "$bp"
}

# Display helpers for log headers: the base URL, or a clear "(unset)" note.
gw_show()  { if [ -n "${GATEWAY_HOST:-}" ]; then gw_base; else printf '(GATEWAY_HOST unset)'; fi; }
cmd_show() { if [ -n "${COMMAND_HOST:-}" ]; then cmd_base; else printf '(COMMAND_HOST unset)'; fi; }

# gw_curl <token> <method> <path> [data] [extra curl args...]
# Hits the gateway admin API. <path> is relative to GATEWAY_BASE_PATH
# (e.g. /config/certificateprofile). Echoes the response body.
gw_curl() {
    local tok="$1" method="$2" path="$3" data="${4:-}"; shift; shift; shift
    [ $# -gt 0 ] && shift || true
    # In cookie mode, mimic the browser exactly (XMLHttpRequest + CSRF header).
    local rw="APIClient"
    [ -n "${GATEWAY_COOKIE:-}" ] && rw="XMLHttpRequest"
    local -a args=("${CA_CURL_OPTS[@]}" -X "$method" "$(gw_base)$path"
        -H "x-keyfactor-requested-with: $rw"
        -H "Content-Type: application/json")
    if [ -n "${GATEWAY_COOKIE:-}" ]; then
        args+=(-H "Cookie: ${GATEWAY_COOKIE}" -H "x-requested-with: XMLHttpRequest")
    fi
    [ -n "$tok" ] && args+=(-H "Authorization: Bearer $tok")
    [ -n "$data" ] && args+=(-d "$data")
    args+=("$@")
    curl "${args[@]}"
}

# cmd_curl <token> <method> <path> [data] [api-version] [extra curl args...]
# Hits the Command KeyfactorAPI. <path> is relative to /KeyfactorAPI.
cmd_curl() {
    local tok="$1" method="$2" path="$3" data="${4:-}" ver="${5:-1}"
    shift; shift; shift
    [ $# -gt 0 ] && shift || true
    [ $# -gt 0 ] && shift || true
    local rw="APIClient"
    [ -n "${COMMAND_COOKIE:-}" ] && rw="XMLHttpRequest"
    local -a args=("${CA_CURL_OPTS[@]}" -X "$method" "$(cmd_base)$path"
        -H "x-keyfactor-api-version: $ver"
        -H "x-keyfactor-requested-with: $rw"
        -H "Content-Type: application/json")
    if [ -n "${COMMAND_COOKIE:-}" ]; then
        args+=(-H "Cookie: ${COMMAND_COOKIE}" -H "x-requested-with: XMLHttpRequest")
    fi
    [ -n "$tok" ] && args+=(-H "Authorization: Bearer $tok")
    [ -n "$data" ] && args+=(-d "$data")
    args+=("$@")
    curl "${args[@]}"
}

# manifest_product_ids [manifest-path] — emit product_ids one per line.
manifest_product_ids() {
    local manifest="${1:-$REPO_ROOT/integration-manifest.json}"
    jq -r '.about.carest.product_ids[]' "$manifest"
}
