#!/usr/bin/env bash
# SIGNUP-ENUM-001 (CWE-204): step 1 of registration answers differently for a
# registered address than for an unknown one.
set -e; . "$(dirname "$0")/_lib.sh"
start() {
  curl -s -o /dev/null -w '%{http_code}' -X POST "$TARGET/api/signup/start" \
    -H 'content-type: application/json' -d "{\"email\":\"$1\"}"
}
KNOWN=$(start user1@bench.local)
UNKNOWN=$(start "nobody-$$@bench.local")
[ "$KNOWN" != "$UNKNOWN" ]
