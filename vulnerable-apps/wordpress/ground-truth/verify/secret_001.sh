#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login_user1
curl -s -b "$JAR" "$TARGET/wp-admin/admin.php?page=bench_options" | grep -q "BENCH_WEBHOOK_SECRET"
