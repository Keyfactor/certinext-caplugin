#!/usr/bin/env bash
set -euo pipefail

python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/probe_endpoints.py" \
    | while IFS= read -r line; do echo "$line"; done
