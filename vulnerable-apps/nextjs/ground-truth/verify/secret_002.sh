#!/usr/bin/env bash
# SECRET-002 (CWE-798/CWE-200): a cloud object-store credential pair is committed
# base64-encoded and shipped in the public browser bundle. Base64 is encoding,
# not secrecy — fetch the chunk, decode, and the access key falls out.
set -e; . "$(dirname "$0")/_lib.sh"

B64="QUtJQUlPU0ZPRE5ON0VYQU1QTEU6d0phbHJYVXRuRkVNSS9LN01ERU5HL2JQeFJmaUNZRVhBTVBMRUtFWQ=="

bundle_text /integrations | grep -q "$B64"
b64dec "$B64" | grep -q '^AKIA[A-Z0-9]*:.\+'
