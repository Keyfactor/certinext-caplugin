#!/usr/bin/env bash
# Stage 05 — import gateway templates into Keyfactor Command.
#
# POSTs /Templates/Import for the configured ConfigurationTenant, pulling the
# gateway's product/profile set into Command as AnyCA_<ProductID> templates.
# (Confirmed working for this tenant by docs/reference/command/templates-certinext.json.)
#
# Env (in addition to the command-auth.sh contract):
#   CONFIGURATION_TENANT   default certinext-caplugin
#   CHECK=1                after import, list templates for the tenant
#   DRY_RUN=1              print intended call, no writes
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
export REPO_ROOT

# shellcheck disable=SC1090
[ -f ~/.env_certinext ] && . ~/.env_certinext
# shellcheck source=../lib/command-auth.sh
. "$SCRIPT_DIR/../lib/command-auth.sh"

DRY_RUN="${DRY_RUN:-0}"
CHECK="${CHECK:-0}"

echo "== Stage 05: Command template import =="
echo "   command : $(cmd_show)"
echo "   tenant  : $CONFIGURATION_TENANT"

BODY="$(jq -n --arg t "$CONFIGURATION_TENANT" '{ConfigurationTenant: $t}')"

if [ "$DRY_RUN" = "1" ]; then
    echo "   (dry run) POST /Templates/Import $BODY"
    echo "== done (dry run): no calls made =="
    exit 0
fi

TOK="$(command_token)"
resp="$(cmd_curl "$TOK" POST /Templates/Import "$BODY" 1)"
echo "   response: $resp"

if [ "$CHECK" = "1" ]; then
    echo "== CHECK: templates for tenant $CONFIGURATION_TENANT =="
    cmd_curl "$TOK" GET /Templates "" 1 \
        | jq -r --arg t "$CONFIGURATION_TENANT" \
            '.[] | select(.ConfigurationTenant==$t) | "   - \(.CommonName)"'
fi
echo "== done: import requested for $CONFIGURATION_TENANT =="
