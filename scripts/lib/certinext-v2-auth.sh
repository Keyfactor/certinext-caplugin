#!/usr/bin/env bash
# Shared helpers for the CERTInext V2 dev scripts in scripts/v2/.
#
# Source this from a scripts/v2/*.sh script; do not execute it directly:
#   . "$(dirname "$0")/../lib/certinext-v2-auth.sh"
#
# Auth model (mirrors CERTInextClient.GetOrRefreshV2TokenAsync):
#   POST {CERTINEXT_API_URL}/oauth/token
#   Content-Type: application/x-www-form-urlencoded
#   grant_type=client_credentials&client_id=...&client_secret=...
#   -> {"access_token": "...", "token_type": "...", "expires_in": N}
# CERTINEXT_API_URL is the single V2 base URL (e.g. https://sandbox-us.certinext.io,
# no /emSignHub-API suffix). There is no V1 SHA256 authKey step any more.
#
# Credentials come from the V2 env file, default ~/.env_certinext_v2, overridable with
# CERTINEXT_V2_ENV_FILE. The file is PARSED (KEY=VALUE, '#' comments, optional
# surrounding quotes), never sourced, so it cannot run code or leak variables into the
# caller's shell. Like V2EnvHelper.LoadEnvFile in the integration tests, a value in the
# file wins over a same-named process env var (a shell that sourced the V1
# ~/.env_certinext has a V1 CERTINEXT_API_URL exported). Process env is the fallback for
# keys the file doesn't define.
#
# Keys used: CERTINEXT_API_URL, CERTINEXT_CLIENT_ID, CERTINEXT_CLIENT_SECRET (required);
# CERTINEXT_REQUESTOR_NAME, CERTINEXT_REQUESTOR_EMAIL, CERTINEXT_REQUESTOR_MOBILE,
# CERTINEXT_SIGNER_IP (optional, order-body scripts only).
#
# Secret handling: the client secret and bearer token live only in unexported shell
# variables of the running script. They are handed to curl through process substitution
# (/dev/fd pipes), so they never appear in argv (ps), on disk, or on stdout/stderr.
# Do not add `set -x` to any script that sources this file.

if [ -z "${BASH_VERSION:-}" ]; then
    echo "ERROR: certinext-v2-auth.sh must be sourced from bash." >&2
    exit 1
fi

for _v2_tool in curl jq; do
    if ! command -v "$_v2_tool" >/dev/null 2>&1; then
        echo "ERROR: '$_v2_tool' is required but not installed." >&2
        exit 1
    fi
done
unset _v2_tool

V2_ENV_FILE="${CERTINEXT_V2_ENV_FILE:-$HOME/.env_certinext_v2}"
V2_MUTATE=0
V2_TOKEN=""

# _v2_trim <string> — strip leading/trailing whitespace (bash 3.2 compatible).
_v2_trim() {
    local s=$1
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

# _v2_file_value <KEY> — print KEY's value from $V2_ENV_FILE; return 1 if not defined.
# Last definition wins. Lines without '=' and '#' comments are ignored.
_v2_file_value() {
    local want=$1 line key val found=1 out=""
    [ -r "$V2_ENV_FILE" ] || return 1
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        line=$(_v2_trim "$line")
        case "$line" in ''|'#'*) continue ;; esac
        case "$line" in *=*) ;; *) continue ;; esac
        key=$(_v2_trim "${line%%=*}")
        key="${key#export }"
        key=$(_v2_trim "$key")
        [ "$key" = "$want" ] || continue
        val=$(_v2_trim "${line#*=}")
        if [ "${#val}" -ge 2 ]; then
            case "$val" in
                \"*\") val="${val#\"}"; val="${val%\"}" ;;
                \'*\') val="${val#\'}"; val="${val%\'}" ;;
            esac
        fi
        out=$val
        found=0
    done < "$V2_ENV_FILE"
    [ "$found" -eq 0 ] && printf '%s' "$out"
    return "$found"
}

# v2_cfg <KEY> [default] — value from the env file, else process env, else default.
v2_cfg() {
    local key=$1 def=${2:-} val
    if val=$(_v2_file_value "$key") && [ -n "$val" ]; then
        printf '%s' "$val"
        return 0
    fi
    val="${!key:-}"
    if [ -n "$val" ]; then printf '%s' "$val"; else printf '%s' "$def"; fi
}

# v2_require <KEY> — like v2_cfg but exits with a clear message when the key is missing.
v2_require() {
    local key=$1 val
    val=$(v2_cfg "$key")
    if [ -z "$val" ]; then
        echo "ERROR: required key $key is not set in $V2_ENV_FILE (or the environment)." >&2
        echo "       Set CERTINEXT_V2_ENV_FILE to use a different env file." >&2
        exit 1
    fi
    printf '%s' "$val"
}

# v2_base_url — validated CERTINEXT_API_URL without a trailing slash.
# Refuses plain http except for localhost stubs, so the client secret is never sent in clear.
v2_base_url() {
    local url
    url=$(v2_require CERTINEXT_API_URL) || exit 1
    url="${url%/}"
    case "$url" in
        https://*) ;;
        http://localhost|http://localhost:*|http://localhost/*|http://127.0.0.1|http://127.0.0.1:*|http://127.0.0.1/*) ;;
        *)
            echo "ERROR: CERTINEXT_API_URL must be an https:// URL (plain http is only allowed for localhost stubs)." >&2
            exit 1 ;;
    esac
    case "$url" in
        *emSignHub-API*)
            echo "ERROR: CERTINEXT_API_URL looks like a V1 URL (contains /emSignHub-API)." >&2
            echo "       V2 needs the base URL only, e.g. https://sandbox-us.certinext.io" >&2
            exit 1 ;;
    esac
    printf '%s' "$url"
}

# v2_parse_args "$@" — read-only scripts: accepts only -h/--help.
v2_parse_args() {
    local a
    for a in "$@"; do
        case "$a" in
            -h|--help) v2_usage; exit 0 ;;
            *) echo "ERROR: unknown argument '$a' (this script is read-only)" >&2; v2_usage; exit 1 ;;
        esac
    done
}

# v2_parse_mutating_args "$@" — state-changing scripts: --yes-mutate sets V2_MUTATE=1.
v2_parse_mutating_args() {
    local a
    for a in "$@"; do
        case "$a" in
            --yes-mutate) V2_MUTATE=1 ;;
            -h|--help) v2_usage; exit 0 ;;
            *) echo "ERROR: unknown argument '$a'" >&2; v2_usage; exit 1 ;;
        esac
    done
}

# v2_require_var <NAME> — exit with usage if the named script input env var is empty.
v2_require_var() {
    local name=$1
    if [ -z "${!name:-}" ]; then
        echo "ERROR: $name is required." >&2
        v2_usage
        exit 1
    fi
}

# v2_require_id <NAME> — like v2_require_var, and the value must be a safe URL path segment.
v2_require_id() {
    local name=$1
    v2_require_var "$name"
    case "${!name}" in
        *[!A-Za-z0-9_.-]*)
            echo "ERROR: $name='${!name}' contains characters not allowed in a URL path segment." >&2
            exit 1 ;;
    esac
}

# v2_signer_ip [--offline] — CERTINEXT_SIGNER_IP, else auto-detect via api.ipify.org.
# --offline returns a placeholder instead of calling out (used for the dry-run preview).
v2_signer_ip() {
    local ip
    ip=$(v2_cfg CERTINEXT_SIGNER_IP)
    if [ -n "$ip" ]; then printf '%s' "$ip"; return 0; fi
    if [ "${1:-}" = "--offline" ]; then printf '%s' "<auto-detect via api.ipify.org>"; return 0; fi
    ip=$(curl -sS --max-time 10 https://api.ipify.org) || {
        echo "ERROR: could not auto-detect signer IP; set CERTINEXT_SIGNER_IP." >&2
        exit 1
    }
    printf '%s' "$ip"
}

# Default usage; scripts redefine v2_usage after sourcing this file.
v2_usage() { echo "Usage: $(basename "$0")" >&2; }

# v2_mutation_gate <METHOD> <PATH> [body-json] — for state-changing scripts.
# Without --yes-mutate: print the planned request (no network calls, no token) and exit 3.
v2_mutation_gate() {
    local method=$1 path=$2 body=${3:-} base
    if [ "$V2_MUTATE" -eq 1 ]; then
        return 0
    fi
    base=$(v2_base_url) || exit 1
    {
        echo "REFUSING TO RUN: this script changes state on the CERTInext account."
        echo "It would send:"
        echo "  $method $base$path"
        if [ -n "$body" ]; then
            echo "  body:"
            printf '%s\n' "$body" | jq . 2>/dev/null | sed 's/^/    /' || printf '    %s\n' "$body"
        fi
        echo "Re-run with --yes-mutate to actually send it."
    } >&2
    exit 3
}

# v2_uuid — random UUID for Idempotency-Key headers.
v2_uuid() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen | tr '[:upper:]' '[:lower:]'
    else
        python3 -c 'import uuid; print(uuid.uuid4())'
    fi
}

# v2_get_token — fetch an OAuth2 client_credentials token into V2_TOKEN (unexported).
# Never prints the token, the secret, or the raw token-endpoint response.
v2_get_token() {
    local base client_id client_secret resp status body err
    base=$(v2_base_url) || exit 1
    client_id=$(v2_require CERTINEXT_CLIENT_ID) || exit 1
    client_secret=$(v2_require CERTINEXT_CLIENT_SECRET) || exit 1

    resp=$(curl -sS -X POST "$base/oauth/token" \
        -H "Accept: application/json" \
        --data-urlencode "grant_type=client_credentials" \
        --data-urlencode "client_id=$client_id" \
        --data-urlencode "client_secret@"<(printf '%s' "$client_secret") \
        -w $'\n%{http_code}') || {
        echo "ERROR: V2 token request to $base/oauth/token failed (network/TLS error)." >&2
        exit 1
    }
    client_secret=""
    status="${resp##*$'\n'}"
    body="${resp%$'\n'*}"
    resp=""

    if [ "$status" != "200" ]; then
        # Never echo the body: an error response could reflect submitted form fields.
        err=$(printf '%s' "$body" | jq -r '.error // empty' 2>/dev/null || true)
        case "$err" in
            ''|*[!A-Za-z0-9_.-]*) err="" ;;  # only print short OAuth2 error codes
        esac
        echo "ERROR: V2 token request failed: HTTP $status${err:+ ($err)} from $base/oauth/token (client_id=$client_id)." >&2
        case "$status" in
            401) echo "       Hint: CERTINEXT_CLIENT_ID / CERTINEXT_CLIENT_SECRET is wrong, or the key was revoked." >&2 ;;
            403) echo "       Hint: the access key exists but was not generated in OAuth mode in the portal." >&2 ;;
        esac
        exit 1
    fi

    V2_TOKEN=$(printf '%s' "$body" | jq -r '.access_token // empty' 2>/dev/null || true)
    body=""
    if [ -z "$V2_TOKEN" ]; then
        echo "ERROR: V2 token response from $base/oauth/token did not contain access_token." >&2
        exit 1
    fi
}

# v2_request <METHOD> <PATH> [extra curl args...] — authenticated request to the V2 API.
# Fetches a token on first use. Prints "HTTP <code>" to stderr and the response body
# (pretty-printed by jq when it is JSON) to stdout. Returns 1 on HTTP >= 400.
v2_request() {
    local method=$1 path=$2 base resp status body
    shift 2
    base=$(v2_base_url) || exit 1
    [ -n "$V2_TOKEN" ] || v2_get_token

    resp=$(curl -sS -X "$method" "$base$path" \
        -H @<(printf 'Authorization: Bearer %s\n' "$V2_TOKEN") \
        -H "Accept: application/json" \
        "$@" \
        -w $'\n%{http_code}') || {
        echo "ERROR: $method $base$path failed (network/TLS error)." >&2
        return 1
    }
    status="${resp##*$'\n'}"
    body="${resp%$'\n'*}"

    echo "HTTP $status" >&2
    if [ -n "$body" ]; then
        if printf '%s' "$body" | jq -e . >/dev/null 2>&1; then
            printf '%s' "$body" | jq .
        else
            printf '%s\n' "$body"
        fi
    fi
    [ "$status" -lt 400 ] 2>/dev/null
}
