#!/usr/bin/env bash
# V2 ssl-certificates/{orderId}/dcv/verify — ask the CA to re-check a DCV artifact.
# MUTATING (can advance the order). Refuses to run and prints the planned request unless
# --yes-mutate is passed.
# Required env vars: ORDER_ID, DOMAIN
# Optional env var:  METHOD (default http-url; also: dns-txt, email)
#
# 204 No Content = DCV passed; order advances to pending-csr.
# 422 = CA could not find the artifact; check file path or DNS propagation.
# Credentials: see scripts/v2/README.md.
set -euo pipefail
# shellcheck source=scripts/lib/certinext-v2-auth.sh
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"
v2_usage() { echo "Usage: ORDER_ID=<orderId> DOMAIN=<domain> [METHOD=http-url] scripts/v2/verify-dcv.sh [--yes-mutate]" >&2; }
v2_parse_mutating_args "$@"

ORDER_ID="${ORDER_ID:-}"
DOMAIN="${DOMAIN:-}"
METHOD="${METHOD:-http-url}"
v2_require_id ORDER_ID
v2_require_var DOMAIN

path="/api/certinext/v2/ssl-certificates/$ORDER_ID/dcv/verify"
body=$(jq -n --arg domain "$DOMAIN" --arg method "$METHOD" '{domain:$domain,method:$method}')
v2_mutation_gate POST "$path" "$body"

echo "V2 POST $path  domain=$DOMAIN  method=$METHOD" >&2
v2_request POST "$path" -H "Content-Type: application/json" --data-binary "$body"
