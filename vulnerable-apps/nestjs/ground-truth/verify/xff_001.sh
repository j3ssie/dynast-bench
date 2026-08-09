#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
body=$(curl -s -H 'X-Forwarded-For: 127.0.0.1' "$TARGET/api/admin/internal-health")
grep -q 'XFF-ADMIN-BYPASS-NESTJS' <<<"$body"
