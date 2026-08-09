#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
out=$(curl -s "$TARGET/api/secrets")
echo "$out" | grep -q 'rails-hardcoded-secret-key-base'
echo "$out" | grep -q 'admin/admin'
