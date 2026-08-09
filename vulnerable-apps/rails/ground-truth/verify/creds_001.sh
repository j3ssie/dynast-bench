#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login admin admin
out=$(curl -s -b "$JAR" "$TARGET/api/users/me")
echo "$out" | grep -q 'admin@bench.local'
