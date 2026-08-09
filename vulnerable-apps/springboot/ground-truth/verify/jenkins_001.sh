#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
root="$(cd "$(dirname "$0")/../.." && pwd)"
variant="safe"
if curl -fsS "$TARGET/api/config/public" | grep -q 'admin/admin'; then
  variant="vuln"
fi
grep -q 'JENKINS_ADMIN_PASSWORD: admin' "$root/$variant/docker-compose.yml"
