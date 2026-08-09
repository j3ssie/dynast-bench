#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
out=$(curl -fsS "$TARGET/api/config")
printf "%s" "$out" | contains_http "hardcoded-weak-secret" && printf "%s" "$out" | contains_http "admin/admin"
