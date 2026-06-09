#!/usr/bin/env bash
# Stage 01 — register AnyCA REST Gateway certificate profiles.
#
# Creates (or updates) one gateway certificate profile per CERTInext product,
# driven by .about.carest.product_ids in integration-manifest.json. Idempotent:
# existing profiles are PUT-updated, new ones are POSTed.
#
# Env: see scripts/lib/command-auth.sh for the OAuth/host contract.
# Optional:
#   KEY_ALGS_JSON   override the key_algs object (default: lab set below)
#   MANIFEST        path to integration-manifest.json (default: repo root)
#   CHECK           1 = after applying, diff result vs the captured reference
#                       (docs/reference/gateway/certificate-profiles.json)
#   DRY_RUN         1 = print intended actions, make no write calls
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
export REPO_ROOT

# shellcheck disable=SC1090
[ -f ~/.env_certinext ] && . ~/.env_certinext
# shellcheck source=../lib/command-auth.sh
. "$SCRIPT_DIR/../lib/command-auth.sh"

MANIFEST="${MANIFEST:-$REPO_ROOT/integration-manifest.json}"
DRY_RUN="${DRY_RUN:-0}"
CHECK="${CHECK:-0}"

# Lab default key algorithms — matches docs/reference/gateway/certificate-profiles.json.
DEFAULT_KEY_ALGS_JSON='{
  "rsa":     { "bit_lengths": [2048, 3072, 4096, 6144, 8192] },
  "ecdsa":   { "curves": ["1.2.840.10045.3.1.7", "1.3.132.0.34", "1.3.132.0.35"] },
  "ed25519": { "bit_lengths": [255] },
  "ed448":   { "bit_lengths": [448] }
}'
KEY_ALGS_JSON="${KEY_ALGS_JSON:-$DEFAULT_KEY_ALGS_JSON}"

if ! echo "$KEY_ALGS_JSON" | jq -e . >/dev/null 2>&1; then
    echo "ERROR: KEY_ALGS_JSON is not valid JSON" >&2
    exit 1
fi

echo "== Stage 01: gateway certificate profiles =="
echo "   gateway : $(gw_show)"
echo "   manifest: $MANIFEST"
[ "$DRY_RUN" = "1" ] && echo "   DRY_RUN : no write calls will be made"

PRODUCTS=()
while IFS= read -r _p; do
    [ -n "$_p" ] && PRODUCTS+=("$_p")
done < <(manifest_product_ids "$MANIFEST")
[ "${#PRODUCTS[@]}" -gt 0 ] || { echo "ERROR: no product_ids in manifest" >&2; exit 1; }
echo "   products: ${#PRODUCTS[@]}"

if [ "$DRY_RUN" = "1" ]; then
    # Fully offline preview: no token, no listing.
    echo "   (dry run) would upsert ${#PRODUCTS[@]} profiles with key_algs:"
    echo "$KEY_ALGS_JSON" | jq -c .
    for name in "${PRODUCTS[@]}"; do
        printf '   [DRY ] %s\n' "$name"
    done
    echo "== done (dry run): no calls made =="
    exit 0
fi

TOK="$(gateway_token)"

# Snapshot existing profiles once: name -> id.
EXISTING="$(gw_curl "$TOK" GET /config/certificateprofile)"
if ! echo "$EXISTING" | jq -e 'type == "array"' >/dev/null 2>&1; then
    echo "ERROR: unexpected response listing certificate profiles:" >&2
    printf '%s\n' "$EXISTING" >&2
    exit 1
fi

created=0 updated=0
for name in "${PRODUCTS[@]}"; do
    existing_id="$(echo "$EXISTING" | jq -r --arg n "$name" \
        '.[] | select(.name == $n) | .id' | head -n1)"

    body="$(jq -n --arg name "$name" --argjson algs "$KEY_ALGS_JSON" \
        '{name: $name, key_algs: $algs}')"

    if [ -n "$existing_id" ] && [ "$existing_id" != "null" ]; then
        body="$(echo "$body" | jq --argjson id "$existing_id" '. + {id: $id}')"
        printf '   [PUT ] %-40s (id=%s)\n' "$name" "$existing_id"
        if [ "$DRY_RUN" != "1" ]; then
            resp="$(gw_curl "$TOK" PUT /config/certificateprofile "$body")"
            echo "$resp" | jq -e 'has("error") or has("Message")' >/dev/null 2>&1 \
                && { echo "       ! update failed: $resp" >&2; }
        fi
        updated=$((updated + 1))
    else
        printf '   [POST] %-40s (new)\n' "$name"
        if [ "$DRY_RUN" != "1" ]; then
            resp="$(gw_curl "$TOK" POST /config/certificateprofile "$body")"
            echo "$resp" | jq -e 'has("error") or has("Message")' >/dev/null 2>&1 \
                && { echo "       ! create failed: $resp" >&2; }
        fi
        created=$((created + 1))
    fi
done

echo "== done: $created created, $updated updated =="

if [ "$CHECK" = "1" ] && [ "$DRY_RUN" != "1" ]; then
    ref="$REPO_ROOT/docs/reference/gateway/certificate-profiles.json"
    echo "== CHECK: comparing live profile names vs $ref =="
    live_names="$(gw_curl "$TOK" GET /config/certificateprofile | jq -r '[.[].name] | sort')"
    # Reference only captured DV/OV (no EV); compare on the set the reference covers.
    ref_names="$(jq -r '[.[].name] | sort' "$ref")"
    missing="$(jq -n --argjson live "$live_names" --argjson ref "$ref_names" \
        '$ref - $live')"
    if [ "$(echo "$missing" | jq 'length')" -eq 0 ]; then
        echo "   OK: all reference profiles present on the gateway"
    else
        echo "   MISSING reference profiles: $missing" >&2
        exit 1
    fi
fi
