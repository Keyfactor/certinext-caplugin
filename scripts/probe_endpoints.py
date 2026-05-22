#!/usr/bin/env python3
"""
probe_endpoints.py — Probe CERTInext API for undocumented product management
and CA listing endpoints.

Posts a minimal meta block to each candidate endpoint name.  A 404 means the
endpoint does not exist on this server.  Any other response (even an
application-level error with an errorCode) means the endpoint exists.

Usage:
    python3 scripts/probe_endpoints.py

Credentials are read from ~/.env_certinext (shell key=value format).
"""

import hashlib
import json
import os
import random
import subprocess
import urllib.error
import urllib.request


CANDIDATES = [
    # Product management
    "ConfigureProduct",
    "CreateProduct",
    "AddProduct",
    "RegisterProduct",
    "GetProductConfiguration",
    "UpdateProduct",
    "DeleteProduct",
    "AddCertificateProfile",
    "CreateCertificateProfile",
    "ConfigureCertificate",
    "AddCertificateTemplate",
    # CA listing
    "GetCAList",
    "ListCAs",
    "GetSubCAList",
    "GetCADetails",
    "GetPrivateCAList",
    "ListSubCAs",
    "GetIssuerList",
]


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


def probe(base_url: str, endpoint: str, account_number: str, access_key: str) -> tuple:
    """Returns (exists: bool, http_status: int, summary: str)."""
    meta = make_meta(account_number, access_key)
    payload = json.dumps({"meta": meta}).encode()
    req = urllib.request.Request(
        base_url.rstrip("/") + "/" + endpoint,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode())
            err_code = body.get("meta", {}).get("errorCode", "")
            err_msg = body.get("meta", {}).get("errorMessage", "")[:60]
            status = body.get("meta", {}).get("status", "?")
            return True, 200, f"status={status}  errorCode={err_code}  msg={err_msg}"
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False, 404, "not found"
        body = e.read().decode()[:200]
        return True, e.code, body
    except Exception as ex:
        return False, 0, str(ex)


def main():
    env = load_env("~/.env_certinext")
    base_url    = env["CERTINEXT_API_URL"]
    access_key  = env["CERTINEXT_ACCESS_KEY"]
    account_num = env["CERTINEXT_ACCOUNT_NUMBER"]

    print(f"Probing {len(CANDIDATES)} candidate endpoints against {base_url}\n")

    found = []
    not_found = []

    for endpoint in CANDIDATES:
        exists, http_code, summary = probe(base_url, endpoint, account_num, access_key)
        if exists:
            print(f"  EXISTS   HTTP={http_code}  {endpoint}  {summary}")
            found.append(endpoint)
        else:
            print(f"  404      {endpoint}")
            not_found.append(endpoint)

    print(f"\n=== Results: {len(found)} endpoints found, {len(not_found)} returned 404 ===")
    if found:
        print("  Found:", ", ".join(found))
    else:
        print("  No undocumented endpoints discovered.")


if __name__ == "__main__":
    main()
