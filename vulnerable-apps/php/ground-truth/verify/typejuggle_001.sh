#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s -c "$JAR" -X POST "$TARGET/login.php" -d 'email=admin@bench.local' -d 'magic_token=0' >/dev/null
curl -s -b "$JAR" "$TARGET/me.php" | grep -q 'admin@bench.local'
