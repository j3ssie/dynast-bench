#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
out=$(curl -sG "$TARGET/api/export" --data-urlencode 'name=ok; printf RAILS-CMD-INJECTED-8bf2')
echo "$out" | grep -q 'RAILS-CMD-INJECTED-8bf2'
