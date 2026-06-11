#!/usr/bin/env bash
set -euo pipefail

python3 /Users/sbailey/RiderProjects/certinext-caplugin/scripts/probe_endpoints.py \
    | while IFS= read -r line; do echo "$line"; done
