#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -fsS "$TARGET/api/admin/users" | grep -q 'admin@bench.local'
