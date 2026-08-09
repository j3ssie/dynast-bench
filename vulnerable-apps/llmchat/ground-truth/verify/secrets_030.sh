#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s -X POST "$TARGET/api/auth/login" -H 'content-type: application/json' -d '{"email":"service@bench.local","password":"admin"}' | grep -q '"token"'
