#!/usr/bin/env bash
# CSRF-001 (CWE-352): the /account/name state-changing route is in the CSRF
# `except` list, so an authenticated POST with NO token succeeds (200) where a
# protected route would return 419. The safe twin drops the exemption.
set -eu
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
code=$(curl -s -o /dev/null -w "%{http_code}" -b "$JAR" -X POST "$TARGET/account/name" \
        --data-urlencode "name=CSRFPROOF")
[ "$code" = "200" ]
