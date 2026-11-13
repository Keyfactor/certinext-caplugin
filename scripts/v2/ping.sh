#!/usr/bin/env bash
# V2 auth/me — returns the account context the Bearer token resolves to.
# Mirrors ICERTInextClient.PingAsync via the V2 API. Read-only.
# Credentials: see scripts/v2/README.md.
set -euo pipefail
# shellcheck source=scripts/lib/certinext-v2-auth.sh
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"
v2_usage() { echo "Usage: scripts/v2/ping.sh" >&2; }
v2_parse_args "$@"

echo "V2 GET /api/certinext/v2/auth/me" >&2
v2_request GET "/api/certinext/v2/auth/me"
