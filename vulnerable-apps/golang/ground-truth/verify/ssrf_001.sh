#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -sG "$TARGET/api/fetch" --data-urlencode "url=http://127.0.0.1:3000/api/_verify/health" | grep -q '"status":"ok"'
