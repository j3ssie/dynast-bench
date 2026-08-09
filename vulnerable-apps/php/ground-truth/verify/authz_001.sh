#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
curl -s -b "$JAR" "$TARGET/admin_users.php" | grep -q 'admin@bench.local'
