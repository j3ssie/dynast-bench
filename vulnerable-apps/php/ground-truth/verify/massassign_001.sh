#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
curl -s -b "$JAR" -X POST "$TARGET/profile.php" -d 'display_name=Mass Assign' -d 'role=admin' >/dev/null
ok=1
curl -s -b "$JAR" "$TARGET/me.php" | grep -q '"role":"admin"' || ok=0
curl -s -b "$JAR" -X POST "$TARGET/profile.php" -d 'role=user' >/dev/null || true
[ "$ok" = 1 ]
