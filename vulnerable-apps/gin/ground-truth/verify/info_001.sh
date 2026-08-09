#!/usr/bin/env bash
# INFO-001: /api/debug/info leaks the process environment (APP_SECRET + DB creds).
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/api/debug/info" | grep -q 'GIN-DEBUG-SECRET-9c2e'
