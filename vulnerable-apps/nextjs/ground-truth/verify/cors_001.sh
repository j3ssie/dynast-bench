#!/usr/bin/env bash
# CORS-001 (CWE-942): an arbitrary Origin is reflected with credentials allowed.
set -e; . "$(dirname "$0")/_lib.sh"
curl -s -D - -o /dev/null -H 'Origin: https://evil.example' "$TARGET/api/posts/search?q=x" \
  | grep -qi 'access-control-allow-origin: https://evil.example'
