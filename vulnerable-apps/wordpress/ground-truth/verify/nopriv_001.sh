#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
reset_state
curl -s "$TARGET/wp-admin/admin-ajax.php?action=bench_promote_user&email=user1@bench.local" >/dev/null
[ "$(user_role user1@bench.local)" = "admin" ]
