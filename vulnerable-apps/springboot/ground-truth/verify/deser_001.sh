#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
payload=$(python3 - <<'PY'
import base64
s=b'DESER-PWN-7b1'
print(base64.b64encode(bytes.fromhex('aced0005')+b't'+len(s).to_bytes(2,'big')+s).decode())
PY
)
curl -fsS -X POST "$TARGET/api/import/object" -H 'content-type: text/plain' --data "$payload" | grep -q 'DESER-PWN-7b1'
