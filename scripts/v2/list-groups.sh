#!/usr/bin/env bash
# V2 groups — list billing groups accessible to this account. Read-only.
# Use a groupNumber from here in order bodies to charge a specific cost centre.
# Credentials: see scripts/v2/README.md.
set -euo pipefail
# shellcheck source=scripts/lib/certinext-v2-auth.sh
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"
v2_usage() { echo "Usage: scripts/v2/list-groups.sh" >&2; }
v2_parse_args "$@"

echo "V2 GET /api/certinext/v2/groups" >&2
v2_request GET "/api/certinext/v2/groups"
