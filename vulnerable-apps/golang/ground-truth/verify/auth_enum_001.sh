#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
body=$(curl -s -X POST "$TARGET/api/auth/login" -H 'content-type: application/json' -d '{"email":"missing-auth-enum@bench.local","password":"nope"}')
grep -q 'user not found' <<<"$body"
