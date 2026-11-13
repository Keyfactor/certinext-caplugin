#!/usr/bin/env bash
# V2 reports/orders — one page of order history. Read-only.
# This is the endpoint the plugin's V2 Synchronize pages through.
# Optional env vars: PAGE (default 1; paging is 1-based, page=0 is treated as 1),
#                    SIZE (default 100; the server clamps to 100)
# Credentials: see scripts/v2/README.md.
set -euo pipefail
# shellcheck source=scripts/lib/certinext-v2-auth.sh
. "$(dirname "$0")/../lib/certinext-v2-auth.sh"
v2_usage() { echo "Usage: [PAGE=1] [SIZE=100] scripts/v2/orders-report.sh" >&2; }
v2_parse_args "$@"

PAGE="${PAGE:-1}"
SIZE="${SIZE:-100}"
case "$PAGE$SIZE" in
    *[!0-9]*) echo "ERROR: PAGE and SIZE must be non-negative integers." >&2; exit 1 ;;
esac

echo "V2 GET /api/certinext/v2/reports/orders?page=$PAGE&size=$SIZE" >&2
v2_request GET "/api/certinext/v2/reports/orders?page=$PAGE&size=$SIZE"
