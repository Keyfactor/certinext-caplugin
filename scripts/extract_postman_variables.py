#!/usr/bin/env python3
"""
extract_postman_variables.py — Extract all variable definitions from the
CERTInext Postman collection (collection-level and environment-level variables).

Shows what values PrivatePKI_IntranetSSL, PrivatePKI_IGTF, SSL_DV, etc. resolve to.

Usage:
    python3 scripts/extract_postman_variables.py [--collection PATH]
"""

import argparse
import json
import os


DEFAULT_COLLECTION = os.path.expanduser("~/Downloads/CERTInext APIs.postman_collection.json")


def main():
    parser = argparse.ArgumentParser(description="Extract Postman collection variables")
    parser.add_argument(
        "--collection",
        default=DEFAULT_COLLECTION,
        help=f"Path to Postman collection JSON (default: {DEFAULT_COLLECTION})",
    )
    args = parser.parse_args()

    with open(args.collection) as f:
        data = json.load(f)

    # Collection-level variables
    variables = data.get("variable", [])
    if variables:
        print("=== Collection-level variables ===")
        for v in variables:
            key = v.get("key", "")
            val = v.get("value", "")
            typ = v.get("type", "")
            print(f"  {key} = {val!r}  (type={typ})")
        print()
    else:
        print("No collection-level variables found.\n")

    # Auth block
    auth = data.get("auth", {})
    if auth:
        print("=== Auth block ===")
        print(json.dumps(auth, indent=2))
        print()

    # Info block
    info = data.get("info", {})
    print("=== Collection info ===")
    print(f"  Name:   {info.get('name','')}")
    print(f"  Schema: {info.get('schema','')}")
    print()


if __name__ == "__main__":
    main()
