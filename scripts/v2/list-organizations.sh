#!/usr/bin/env bash
# V2 organizations — list pre-vetted organizations available for OV/EV SSL. Read-only.
# Reference an organizationNumber in order bodies to skip re-vetting.
# Credentials: see scripts/v2/README.md.
set -euo pipefail
# shellcheck source=scripts/lib/certinext-v2-auth.sh
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"
v2_usage() { echo "Usage: scripts/v2/list-organizations.sh" >&2; }
v2_parse_args "$@"

echo "V2 GET /api/certinext/v2/organizations" >&2
v2_request GET "/api/certinext/v2/organizations"
