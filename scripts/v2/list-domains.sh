#!/usr/bin/env bash
# V2 domains — list domains already pre-validated under this account. Read-only.
# DCV does not need to be repeated for domains in this list.
# Credentials: see scripts/v2/README.md.
set -euo pipefail
# shellcheck source=scripts/lib/certinext-v2-auth.sh
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"
v2_usage() { echo "Usage: scripts/v2/list-domains.sh" >&2; }
v2_parse_args "$@"

echo "V2 GET /api/certinext/v2/domains" >&2
v2_request GET "/api/certinext/v2/domains"
