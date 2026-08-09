#!/usr/bin/env bash
# REDIRECT-001 (CWE-601): /go?next= is redirected to verbatim (open redirect).
set -eu
. "$(dirname "$0")/_lib.sh"
curl -s -o /dev/null -D - "$TARGET/go?next=https://evil.example/pwn" \
  | grep -i '^location:' | grep -q 'https://evil.example/pwn'
