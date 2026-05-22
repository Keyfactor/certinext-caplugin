#!/usr/bin/env bash
# Shared HMAC authentication helper for CERTInext API scripts.
#
# Usage:
#   source "$(dirname "$0")/lib/certinext-auth.sh"
#   read -r ts txn authKey <<< "$(certinext_meta)"
#
# Requires CERTINEXT_ACCESS_KEY to be set in the calling environment
# (sourced from ~/.env_certinext before this function is called).

certinext_meta() {
    local ts txn authKey
    ts=$(TZ=Asia/Kolkata date +%Y-%m-%dT%H:%M:%S+05:30)
    txn=$(python3 -c "import random; print(str(random.randint(1000000000000000,9999999999999999)))")
    authKey=$(python3 -c "import hashlib,sys; print(hashlib.sha256((sys.argv[1]+sys.argv[2]+sys.argv[3]).encode()).hexdigest())" \
        "$CERTINEXT_ACCESS_KEY" "$ts" "$txn")
    echo "$ts" "$txn" "$authKey"
}
