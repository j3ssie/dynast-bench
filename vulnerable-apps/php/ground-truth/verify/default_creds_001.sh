#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login admin admin
curl -s -b "$JAR" "$TARGET/me.php" | grep -q '"email":"admin"'
