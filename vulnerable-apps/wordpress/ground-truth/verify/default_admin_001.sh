#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s -c "$JAR" -X POST "$TARGET/wp-login.php" -d "log=admin&pwd=admin" | grep -q "default admin credential"
