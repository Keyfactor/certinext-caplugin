#!/usr/bin/env python3
"""
get_field_details.py — Call GetFieldDetails for one or more product codes.

Prints the full field definition for each product so we know which
certificateInformation fields are mandatory vs. optional for Private PKI orders.

Usage:
    python3 scripts/get_field_details.py [--product 149] [--category 8]

Credentials are read from ~/.env_certinext (shell key=value format).
"""

import argparse
import hashlib
import json
import os
import random
import subprocess
import urllib.error
import urllib.request


def load_env(path: str) -> dict:
    env = {}
    with open(os.path.expanduser(path)) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip('"')
    return env


def make_meta(account_number: str, access_key: str) -> dict:
    ts = subprocess.check_output(
        "TZ=Asia/Kolkata date +%Y-%m-%dT%H:%M:%S+05:30", shell=True
    ).decode().strip()
    txn = str(random.randint(1_000_000_000_000_000, 9_999_999_999_999_999))
    auth_key = hashlib.sha256((access_key + ts + txn).encode()).hexdigest()
    return {"ver": "1.0", "ts": ts, "txn": txn, "accountNumber": account_number, "authKey": auth_key}


def post(base_url: str, endpoint: str, payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        base_url.rstrip("/") + "/" + endpoint,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return json.loads(body)
        except Exception:
            return {"_http_error": e.code, "_body": body[:500]}
    except Exception as ex:
        return {"_error": str(ex)}


def main():
    parser = argparse.ArgumentParser(description="Get CERTInext field details for a product")
    parser.add_argument("--product", default="149", help="Product code (default: 149)")
    parser.add_argument("--category", default="8", help="Category ID (default: 8 = Private PKI)")
    args = parser.parse_args()

    env = load_env("~/.env_certinext")
    base_url    = env["CERTINEXT_API_URL"]
    access_key  = env["CERTINEXT_ACCESS_KEY"]
    account_num = env["CERTINEXT_ACCOUNT_NUMBER"]
    group_num   = env["CERTINEXT_GROUP_NUMBER"]

    meta = make_meta(account_num, access_key)
    payload = {
        "meta": meta,
        "productDetails": {
            "groupNumber": group_num,
            "categoryID": args.category,
            "productCode": args.product,
        },
    }

    print(f"GetFieldDetails  product={args.product}  category={args.category}")
    result = post(base_url, "GetFieldDetails", payload)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
