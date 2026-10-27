#!/usr/bin/env bash
# Orchestrator — run the full gateway + Command registration in order.
#
# Each stage is an independent script and can be run on its own. This driver
# runs them in sequence, skipping any stage whose script does not yet exist
# (stages 02-06 are added incrementally) or whose SKIP_<NN> flag is set to 1.
#
#   make register
#   SKIP_03=1 make register      # skip claims
#   DRY_RUN=1 make register      # forwarded to every stage
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# stage number -> script basename
STAGES=(
    "01:01-gateway-profiles.sh"
    "02:02-gateway-ca-config.sh"
    "03:03-gateway-claims.sh"
    "04:04-command-register-ca.sh"
    "05:05-command-import-templates.sh"
    "06:06-command-enrollment-patterns.sh"
)

for entry in "${STAGES[@]}"; do
    num="${entry%%:*}"
    script="${entry#*:}"
    skip_var="SKIP_${num}"
    path="$SCRIPT_DIR/$script"

    if [ "${!skip_var:-0}" = "1" ]; then
        echo ">> stage $num ($script): SKIPPED (${skip_var}=1)"
        continue
    fi
    if [ ! -x "$path" ]; then
        echo ">> stage $num ($script): not yet implemented — skipping"
        continue
    fi

    echo ">> stage $num ($script): running"
    "$path"
    echo
done

echo ">> registration complete"
