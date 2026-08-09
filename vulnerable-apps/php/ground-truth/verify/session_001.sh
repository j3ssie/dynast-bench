#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
sid="benchfix$RANDOM"
curl -s -X POST -H "Cookie: PHPSESSID=$sid" "$TARGET/login.php" -d 'email=user1@bench.local' -d 'password=User123!' >/dev/null
curl -s -H "Cookie: PHPSESSID=$sid" "$TARGET/me.php" | grep -q 'user1@bench.local'
