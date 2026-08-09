#!/usr/bin/env bash
# SECRET-001 (CWE-538/CWE-200): a leftover .env backup is served from the web
# root, leaking app secrets. The safe twin does not ship it.
set -eu
. "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/.env.backup" | grep -q 'BENCH-ENV-LEAK-9c2e'
