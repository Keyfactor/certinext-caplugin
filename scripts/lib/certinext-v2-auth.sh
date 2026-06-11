#!/usr/bin/env bash
# Shared Bearer-token helper for CERTInext V2 API scripts.
#
# Usage (from a script in scripts/v2/):
#   source "$(dirname "$0")/../lib/certinext-v2-auth.sh"
#   # $CERTINEXT_V2_TOKEN is now set
#
# Requires CERTINEXT_ACCESS_KEY, CERTINEXT_ACCOUNT_NUMBER, and
# CERTINEXT_V2_API_URL to be set in the calling environment
# (sourced from ~/.env_certinext before this file is sourced).
#
# Internally reuses certinext_meta from certinext-auth.sh to compute
# the SHA256 authKey, then exchanges it for a short-lived Bearer JWT
# at POST {v2BaseURL}/oauth/token.

# shellcheck source=./certinext-auth.sh
# $0 is the calling script (in scripts/v2/), so ../lib/ reaches scripts/lib/.
. "$(dirname "$0")/../lib/certinext-auth.sh"

read -r _v2_ts _v2_txn _v2_authKey <<< "$(certinext_meta)"

_v2_token_response=$(curl -s -X POST "$CERTINEXT_V2_API_URL/oauth/token" \
    -H "Content-Type: application/json" \
    -d "$(jq -n \
        --arg grant_type "client_credentials" \
        --arg accountNumber "$CERTINEXT_ACCOUNT_NUMBER" \
        --arg authKey "$_v2_authKey" \
        --arg ver "1.0" \
        --arg ts "$_v2_ts" \
        --arg txn "$_v2_txn" \
        '{grant_type:$grant_type,accountNumber:$accountNumber,authKey:$authKey,ver:$ver,ts:$ts,txn:$txn}')")

CERTINEXT_V2_TOKEN=$(echo "$_v2_token_response" | jq -r '.tokenDetails.accessToken // empty')

if [ -z "$CERTINEXT_V2_TOKEN" ]; then
    echo "ERROR: failed to acquire V2 Bearer token. Response:" >&2
    echo "$_v2_token_response" | jq . >&2
    exit 1
fi

export CERTINEXT_V2_TOKEN

unset _v2_ts _v2_txn _v2_authKey _v2_token_response
