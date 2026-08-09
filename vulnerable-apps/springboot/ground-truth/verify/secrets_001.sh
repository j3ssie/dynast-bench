#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -fsS "$TARGET/api/config/public" | grep -Eq 'springboot-public-secret-key-17|admin/admin'
