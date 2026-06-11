#!/usr/bin/env python3
"""
order_private_pki_minimal.py — Place a GenerateOrderPrivatePKI order using
the minimal Postman-style request body (no accountingModel, no subscriptionDetails,
no agreementDetails).

This variant mirrors the exact field set shown in the Postman collection for
the emSign Intranet SSL product.  It is used to determine whether EMS-939
("Something went Wrong") is caused by extra fields in the full payload, or by
a server-side configuration issue with the product.

Usage:
    python3 scripts/order_private_pki_minimal.py [--csr PATH] [--domain DOMAIN]
        [--product 149] [--save-and-hold 0]

Credentials are read from ~/.env_certinext.
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


def main():
    parser = argparse.ArgumentParser(description="Place minimal Private PKI order")
    parser.add_argument("--csr", default="/tmp/certinext-igtf-test.csr")
    parser.add_argument("--domain", default="test-igtf.example.com")
    parser.add_argument("--product", default="149")
    parser.add_argument("--save-and-hold", default="0", dest="save_and_hold")
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
        sys.exit(1)

    with open(args.csr) as f:
        csr_pem = f.read()

    # -----------------------------------------------------------------------
    # Variant 1: Minimal — mirrors Postman body exactly (no agreementDetails,
    # no accountingModel, no delegationInformation, no subscriptionDetails)
    # -----------------------------------------------------------------------
    print(f"\n=== Variant 1: Minimal (Postman-style)  product={args.product}  saveAndHold={args.save_and_hold} ===")
    meta = make_meta(account_num, access_key)
    payload_minimal = {
        "meta": meta,
        "orderDetails": {
            "productCode": args.product,
            "requestorInformation": {
                "requestorName": req_name,
                "requestorIsdCode": "1",
                "requestorMobileNumber": req_mobile,
                "requestorEmail": email,
            },
            "certificateInformation": {
                "domainName": args.domain,
                "organizationName": "Keyfactor Inc",
                "organizationUnit": "IT",
                "state": "Ohio",
                "countryCode": "US",
                "dnsType": "1",
                "additionalDomains": [],
            },
            "additionalInformation": {
                "remarks": "Keyfactor minimal Private PKI probe",
                "tags": [],
            },
            "csr": csr_pem,
            "saveAndHold": args.save_and_hold,
        },
    }
    resp1 = post(base_url, "GenerateOrderPrivatePKI", payload_minimal)
    print(json.dumps(resp1, indent=2))

    # -----------------------------------------------------------------------
    # Variant 2: With agreementDetails added (in case it's required)
    # -----------------------------------------------------------------------
    print(f"\n=== Variant 2: With agreementDetails  product={args.product}  saveAndHold={args.save_and_hold} ===")
    meta = make_meta(account_num, access_key)
    payload_with_agreement = {
        "meta": meta,
        "orderDetails": {
            "productCode": args.product,
            "requestorInformation": {
                "requestorName": req_name,
                "requestorIsdCode": "1",
                "requestorMobileNumber": req_mobile,
                "requestorEmail": email,
            },
            "certificateInformation": {
                "domainName": args.domain,
                "organizationName": "Keyfactor Inc",
                "organizationUnit": "IT",
                "state": "Ohio",
                "countryCode": "US",
                "dnsType": "1",
                "additionalDomains": [],
            },
            "additionalInformation": {
                "remarks": "Keyfactor minimal Private PKI probe with agreement",
                "tags": [],
            },
            "csr": csr_pem,
            "saveAndHold": args.save_and_hold,
            "agreementDetails": {
                "acceptAgreement": "1",
                "signerName": req_name,
                "signerPlace": "Gateway",
                "signerIP": signer_ip,
            },
        },
    }
    resp2 = post(base_url, "GenerateOrderPrivatePKI", payload_with_agreement)
    print(json.dumps(resp2, indent=2))

    # -----------------------------------------------------------------------
    # Variant 3: With delegationInformation (groupNumber)
    # -----------------------------------------------------------------------
    print(f"\n=== Variant 3: With delegationInformation  product={args.product}  saveAndHold={args.save_and_hold} ===")
    meta = make_meta(account_num, access_key)
    payload_with_group = {
        "meta": meta,
        "orderDetails": {
            "productCode": args.product,
            "delegationInformation": {"groupNumber": group_num},
            "requestorInformation": {
                "requestorName": req_name,
                "requestorIsdCode": "1",
                "requestorMobileNumber": req_mobile,
                "requestorEmail": email,
            },
            "certificateInformation": {
                "domainName": args.domain,
                "organizationName": "Keyfactor Inc",
                "organizationUnit": "IT",
                "state": "Ohio",
                "countryCode": "US",
                "dnsType": "1",
                "additionalDomains": [],
            },
            "additionalInformation": {
                "remarks": "Keyfactor probe with groupNumber",
                "tags": [],
            },
            "csr": csr_pem,
            "saveAndHold": args.save_and_hold,
        },
    }
    resp3 = post(base_url, "GenerateOrderPrivatePKI", payload_with_group)
    print(json.dumps(resp3, indent=2))

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    print("\n=== Summary ===")
    for label, resp in [
        ("Variant1 (minimal)", resp1),
        ("Variant2 (+agreement)", resp2),
        ("Variant3 (+group)", resp3),
    ]:
        s = resp.get("meta", {}).get("status", "?")
        ec = resp.get("meta", {}).get("errorCode", "")
        em = resp.get("meta", {}).get("errorMessage", "")
        on = resp.get("orderDetails", {}).get("orderNumber", "")
        rn = resp.get("orderDetails", {}).get("requestNumber", "")
        os_ = resp.get("orderDetails", {}).get("orderStatus", "")
        print(f"  {label}: status={s}  orderNumber={on}  requestNumber={rn}"
              f"  orderStatus={os_}  errorCode={ec}  msg={em[:80]}")

    out_path = "/tmp/certinext-private-pki-minimal.json"
    with open(out_path, "w") as f:
        json.dump({"v1": resp1, "v2": resp2, "v3": resp3}, f, indent=2)
    print(f"\nFull results written to {out_path}")


if __name__ == "__main__":
    main()
