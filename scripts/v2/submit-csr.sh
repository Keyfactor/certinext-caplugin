#!/usr/bin/env bash
# V2 ssl-certificates/{orderId}/csr — attach a PEM CSR to an SSL order. MUTATING
# (advances the order). Refuses to run and prints the planned request unless
# --yes-mutate is passed.
# Required env vars: ORDER_ID, CSR_FILE (path to PEM file)
#
# 204 No Content = CSR accepted; order advances to pending-agreement.
# Credentials: see scripts/v2/README.md.
set -euo pipefail
# shellcheck source=scripts/lib/certinext-v2-auth.sh
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"
v2_usage() { echo "Usage: ORDER_ID=<orderId> CSR_FILE=<path> scripts/v2/submit-csr.sh [--yes-mutate]" >&2; }
v2_parse_mutating_args "$@"

ORDER_ID="${ORDER_ID:-}"
CSR_FILE="${CSR_FILE:-}"
v2_require_id ORDER_ID
v2_require_var CSR_FILE
if [ ! -f "$CSR_FILE" ]; then
    echo "ERROR: CSR_FILE '$CSR_FILE' not found" >&2
    exit 1
fi

path="/api/certinext/v2/ssl-certificates/$ORDER_ID/csr"
body=$(jq -n --rawfile csr "$CSR_FILE" '{csr:$csr,attested:false}')
v2_mutation_gate PUT "$path" "$body"

echo "V2 PUT $path  csrFile=$CSR_FILE" >&2
v2_request PUT "$path" -H "Content-Type: application/json" --data-binary "$body"
