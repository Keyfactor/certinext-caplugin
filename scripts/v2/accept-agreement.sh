#!/usr/bin/env bash
# V2 ssl-certificates/{orderId}/agreement — record Subscriber Agreement acceptance.
# MUTATING: the CA proceeds to issue the certificate. Refuses to run and prints the
# planned request unless --yes-mutate is passed.
# Required env var: ORDER_ID
# Env-file keys: CERTINEXT_REQUESTOR_NAME, CERTINEXT_SIGNER_IP (else api.ipify.org lookup)
#
# 204 No Content = recorded. Then poll track-order.sh until status=issued, and run
# download-certificate.sh.
# Credentials: see scripts/v2/README.md.
set -euo pipefail
# shellcheck source=scripts/lib/certinext-v2-auth.sh
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"
v2_usage() { echo "Usage: ORDER_ID=<orderId> scripts/v2/accept-agreement.sh [--yes-mutate]" >&2; }
v2_parse_mutating_args "$@"

ORDER_ID="${ORDER_ID:-}"
v2_require_id ORDER_ID

name=$(v2_cfg CERTINEXT_REQUESTOR_NAME "Keyfactor Gateway Test")

build_body() {
    jq -n --arg name "$name" --arg ip "$1" \
        '{agreement:{signerName:$name,signerIp:$ip,signerPlace:"Gateway",accepted:true}}'
}

path="/api/certinext/v2/ssl-certificates/$ORDER_ID/agreement"
v2_mutation_gate POST "$path" "$(build_body "$(v2_signer_ip --offline)")"

body=$(build_body "$(v2_signer_ip)")
echo "V2 POST $path  signerName=$name" >&2
v2_request POST "$path" -H "Content-Type: application/json" --data-binary "$body"
