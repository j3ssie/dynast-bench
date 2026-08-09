#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
extract() { python3 -c 'import sys,json,urllib.parse; link=json.load(sys.stdin).get("resetLink",""); print(urllib.parse.parse_qs(urllib.parse.urlparse(link).query).get("token",[""])[0])'; }
t1=$(curl -s -X POST "$TARGET/api/auth/reset" -H 'content-type: application/json' -d '{"email":"user1@bench.local"}' | extract)
t2=$(curl -s -X POST "$TARGET/api/auth/reset" -H 'content-type: application/json' -d '{"email":"user1@bench.local"}' | extract)
[ -n "$t1" ] && [ "$t1" = "$t2" ]
