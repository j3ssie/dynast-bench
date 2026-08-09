#!/usr/bin/env bash
# SSTI-001 (CWE-1336): user input is compiled as a Blade template, so an
# arithmetic expression is evaluated server-side (49) rather than echoed.
set -eu
. "$(dirname "$0")/_lib.sh"
OUT=$(curl -s -G --data-urlencode 'tpl={{ 7*7 }}' "$TARGET/tools/preview")
[ "$(printf '%s' "$OUT" | tr -d '[:space:]')" = "49" ]
