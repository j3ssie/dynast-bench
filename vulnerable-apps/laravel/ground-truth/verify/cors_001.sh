#!/usr/bin/env bash
# CORS-001 (CWE-942): the app reflects any Origin AND allows credentials.
set -eu
. "$(dirname "$0")/_lib.sh"
H=$(curl -s -o /dev/null -D - -H "Origin: https://evil.example" "$TARGET/api/_verify/health")
printf '%s' "$H" | grep -iq 'access-control-allow-origin: https://evil.example' \
  && printf '%s' "$H" | grep -iq 'access-control-allow-credentials: true'
