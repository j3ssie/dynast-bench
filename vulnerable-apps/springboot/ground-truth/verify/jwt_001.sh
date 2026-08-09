#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
tok=$(forge_none_jwt)
curl -fsS -H "Authorization: Bearer $tok" "$TARGET/api/reports/admin-summary" | grep -q 'ADMIN-SUMMARY-42'
