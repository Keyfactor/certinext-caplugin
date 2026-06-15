#!/usr/bin/env python3
"""
probe_private_pki.py — Probe CERTInext Private PKI order endpoints.

Tests GenerateOrderPrivatePKI for products 149 (Intranet SSL) and 108 (IGTF Host),
and captures the full API response so we know whether orders auto-issue or require
DCV / manual approval.

Usage:
    python3 scripts/probe_private_pki.py [--csr /path/to/csr.pem]

Credentials are read from ~/.env_certinext (shell key=value format).
"""

import argparse
import hashlib
import json
import os
import random
import subprocess
import sys
import urllib.error
import urllib.request


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return json.loads(body)
        except Exception:
            return {"_http_error": e.code, "_body": body[:500]}
    except Exception as ex:
        return {"_error": str(ex)}


def get_public_ip() -> str:
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as r:
            return r.read().decode().strip()
    except Exception:
        return "127.0.0.1"


def build_private_pki_payload(
    meta: dict,
    product_code: str,
    csr: str,
    domain: str,
    group_number: str,
    org_name: str,
    requestor_name: str,
    requestor_email: str,
    requestor_mobile: str,
    signer_ip: str,
    save_and_hold: str = "0",
) -> dict:
    return {
        "meta": meta,
        "orderDetails": {
            "productCode": product_code,
            "accountingModel": "2",
            "saveAndHold": save_and_hold,
            "emailNotifications": "0",
            "delegationInformation": {"groupNumber": group_number},
            "requestorInformation": {
                "requestorName": requestor_name,
                "requestorIsdCode": "1",
                "requestorMobileNumber": requestor_mobile,
                "requestorEmail": requestor_email,
            },
            "certificateInformation": {
                "domainName": domain,
                "organizationName": org_name,
                "dnsType": "1",
                "additionalDomains": [],
            },
            "additionalInformation": {
                "remarks": "Keyfactor private-PKI probe — integration test",
            },
            "csr": csr,
            "agreementDetails": {
                "acceptAgreement": "1",
                "signerName": requestor_name,
                "signerPlace": "Gateway",
                "signerIP": signer_ip,
            },
        },
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Probe CERTInext Private PKI endpoints")
    parser.add_argument("--csr", default="/tmp/certinext-igtf-test.csr",
                        help="Path to PEM CSR file")
    parser.add_argument("--domain", default="test-igtf.example.com",
                        help="Domain name for the certificate request")
    parser.add_argument("--save-and-hold", default="0",
                        help="saveAndHold flag: 0=submit, 1=draft")
    args = parser.parse_args()

    env = load_env("~/.env_certinext")
    base_url    = env["CERTINEXT_API_URL"]
    access_key  = env["CERTINEXT_ACCESS_KEY"]
    account_num = env["CERTINEXT_ACCOUNT_NUMBER"]
    group_num   = env["CERTINEXT_GROUP_NUMBER"]
    email       = env.get("CERTINEXT_REQUESTOR_EMAIL", "plugin-test@keyfactor.com")
    req_name    = env.get("CERTINEXT_REQUESTOR_NAME", "Keyfactor Plugin Test")
    req_mobile  = env.get("CERTINEXT_REQUESTOR_MOBILE", "0000000000")
    signer_ip   = env.get("CERTINEXT_SIGNER_IP", "").strip() or get_public_ip()

    if not os.path.isfile(args.csr):
        print(f"CSR file not found: {args.csr}", file=sys.stderr)
        print("Run:  make generate-test-csr  to create one.", file=sys.stderr)
        sys.exit(1)

    with open(args.csr) as f:
        csr_pem = f.read()

    results = {}

    # -----------------------------------------------------------------------
    # Test product 149 — Sandbox emSign Intranet SSL (known to be provisioned)
    # -----------------------------------------------------------------------
    print("\n=== GenerateOrderPrivatePKI  product=149  saveAndHold={} ===".format(args.save_and_hold))
    meta = make_meta(account_num, access_key)
    payload = build_private_pki_payload(
        meta=meta,
        product_code="149",
        csr=csr_pem,
        domain=args.domain,
        group_number=group_num,
        org_name="Keyfactor Inc",
        requestor_name=req_name,
        requestor_email=email,
        requestor_mobile=req_mobile,
        signer_ip=signer_ip,
        save_and_hold=args.save_and_hold,
    )
    resp_149 = post(base_url, "GenerateOrderPrivatePKI", payload)
    print(json.dumps(resp_149, indent=2))
    results["product_149"] = resp_149

    # -----------------------------------------------------------------------
    # Test product 108 — IGTF Host Certificate (may not be provisioned)
    # -----------------------------------------------------------------------
    print("\n=== GenerateOrderPrivatePKI  product=108  saveAndHold=1 (draft) ===")
    meta = make_meta(account_num, access_key)
    payload_108 = build_private_pki_payload(
        meta=meta,
        product_code="108",
        csr=csr_pem,
        domain=args.domain,
        group_number=group_num,
        org_name="Keyfactor Inc",
        requestor_name=req_name,
        requestor_email=email,
        requestor_mobile=req_mobile,
        signer_ip=signer_ip,
        save_and_hold="1",  # always draft for unprovisioned product
    )
    resp_108 = post(base_url, "GenerateOrderPrivatePKI", payload_108)
    print(json.dumps(resp_108, indent=2))
    results["product_108"] = resp_108

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    print("\n=== Summary ===")
    for code, resp in results.items():
        status = resp.get("meta", {}).get("status", "?")
        err_code = resp.get("meta", {}).get("errorCode", "")
        err_msg = resp.get("meta", {}).get("errorMessage", "")
        order_num = resp.get("orderDetails", {}).get("orderNumber", "")
        req_num = resp.get("orderDetails", {}).get("requestNumber", "")
        cert_status = resp.get("orderDetails", {}).get("orderStatus", "")
        print(f"  {code}: status={status}  orderNumber={order_num}  requestNumber={req_num}"
              f"  orderStatus={cert_status}  errorCode={err_code}  errorMsg={err_msg[:80]}")

    # Write JSON results for later inspection
    out_path = "/tmp/certinext-private-pki-probe.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nFull results written to {out_path}")


if __name__ == "__main__":
    main()
