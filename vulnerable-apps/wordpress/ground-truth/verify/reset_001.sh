#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
resp=$(curl -s "$TARGET/wp-login.php?action=lostpassword&user_login=user1@bench.local")
token=$(printf '%s' "$resp" | sed -n 's/.*reset token: \([a-f0-9][a-f0-9]*\).*/\1/p')
[ -n "$token" ]
curl -s --get "$TARGET/wp-login.php" \
  --data-urlencode 'action=rp' \
  --data-urlencode 'login=user1@bench.local' \
  --data-urlencode "key=$token" | grep -q "reset-token-valid"
