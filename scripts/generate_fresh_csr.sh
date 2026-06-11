#!/bin/sh
# Generates a fresh RSA-2048 CSR with a timestamp-unique CN to avoid EMS-1099
# (duplicate CSR rejection). Writes CSR to /tmp/certinext-unique.csr.
CN="test-$(date +%s).example.com"
openssl req -new -newkey rsa:2048 -nodes \
    -subj "/CN=${CN}" \
    -addext "subjectAltName=DNS:${CN}" \
    -out /tmp/certinext-unique.csr \
    -keyout /tmp/certinext-unique.key 2>/dev/null
echo "${CN}"