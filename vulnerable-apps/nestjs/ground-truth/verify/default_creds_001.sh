#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
body=$(curl -s -X POST "$TARGET/api/auth/login" -H 'content-type: application/json' -d '{"email":"admin","password":"admin"}')
grep -q '"ok":true' <<<"$body"
