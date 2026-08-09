#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
data=$(python3 - <<'PY'
import base64
s=b'DESER-MARKER-jsp'
raw=bytes.fromhex('aced0005')+b't'+len(s).to_bytes(2,'big')+s
print(base64.b64encode(raw).decode())
PY
)
curl -s -X POST "$TARGET/import?type=obj" --data-urlencode "data=$data" | grep -F 'DESER-MARKER-jsp'
