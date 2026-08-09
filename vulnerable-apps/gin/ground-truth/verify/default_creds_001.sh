#!/usr/bin/env bash
# DEFAULT-CREDS-001: the seeded service account uses admin/admin.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -s -X POST "$TARGET/api/auth/login" -H 'content-type: application/json' \
  -d '{"email":"admin","password":"admin"}' | grep -q '"ok":true'
