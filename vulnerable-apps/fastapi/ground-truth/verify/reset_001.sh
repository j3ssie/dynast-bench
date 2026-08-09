#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
resp=$(curl -s -X POST "$TARGET/api/auth/reset" -H 'content-type: application/json' -d '{"email":"user1@bench.local"}')
token=$(printf '%s' "$resp" | python3 -c 'import sys,json,re; s=json.load(sys.stdin).get("resetLink",""); print(s.rsplit("=",1)[-1] if "=" in s else "")')
[ -n "$token" ]
python3 - "$token" <<'PY'
import hashlib,sys,time
email='user1@bench.local'
tok=sys.argv[1]
now=int(time.time())
for t in range(now-3, now+4):
    if hashlib.md5(f'{email}{t}'.encode()).hexdigest()==tok:
        sys.exit(0)
sys.exit(1)
PY
