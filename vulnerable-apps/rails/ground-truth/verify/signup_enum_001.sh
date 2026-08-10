#!/usr/bin/env bash
# SIGNUP-ENUM-001 (CWE-204): step 1 answers differently for a registered address.
set -eu; . "$(dirname "$0")/_lib.sh"
start() { curl -s -o /dev/null -w '%{http_code}' -X POST "$TARGET/api/signup/start" \
  -H 'content-type: application/json' -d "{\"email\":\"$1\"}"; }
[ "$(start user1@bench.local)" != "$(start "nobody-$$@bench.local")" ]
