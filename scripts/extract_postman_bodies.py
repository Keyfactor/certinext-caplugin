#!/usr/bin/env python3
"""
extract_postman_bodies.py — Extract full request bodies from the CERTInext
Postman collection for inspection.

Usage:
    python3 scripts/extract_postman_bodies.py [--filter KEYWORD] [--collection PATH]

By default prints all endpoints.  Use --filter to narrow by endpoint name or
folder name (case-insensitive substring match).

Examples:
    # Print everything
    python3 scripts/extract_postman_bodies.py

    # Print only Private PKI endpoints
    python3 scripts/extract_postman_bodies.py --filter "private pki"

    # Print only IGTF endpoints
    python3 scripts/extract_postman_bodies.py --filter igtf

    # Print only intranet SSL
    python3 scripts/extract_postman_bodies.py --filter intranet
"""

import argparse
import json
import os


DEFAULT_COLLECTION = os.path.expanduser("~/Downloads/CERTInext APIs.postman_collection.json")


def walk(items, path="", filter_kw=""):
    for item in items:
        name = item.get("name", "")
        full = path + "/" + name if path else name
        if "item" in item:
            walk(item["item"], full, filter_kw)
        else:
            if filter_kw and filter_kw.lower() not in full.lower():
                continue
            req = item.get("request", {})
            url = req.get("url", "")
            if isinstance(url, dict):
                url = url.get("raw", "")
            body = req.get("body", {})
            print(f"=== {full} ===")
            print(f"URL: {url}")
            if body and body.get("raw"):
                print(f"BODY:\n{body['raw']}")
            print()


def main():
    parser = argparse.ArgumentParser(description="Extract Postman request bodies")
    parser.add_argument(
        "--filter", default="", help="Case-insensitive substring filter on endpoint path"
    )
    parser.add_argument(
        "--collection",
        default=DEFAULT_COLLECTION,
        help=f"Path to Postman collection JSON (default: {DEFAULT_COLLECTION})",
    )
    args = parser.parse_args()

    with open(args.collection) as f:
        data = json.load(f)

    walk(data.get("item", []), filter_kw=args.filter)


if __name__ == "__main__":
    main()
