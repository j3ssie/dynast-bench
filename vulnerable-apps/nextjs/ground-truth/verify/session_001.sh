#!/usr/bin/env bash
# SESSION-001 (CWE-330/384): session ids come from Math.random().toString(36),
# not a CSPRNG. Observable without any source access: the ids use the base36
# alphabet and their LENGTH VARIES between sessions, which is the signature of
# stringifying a float (leading zeros vanish). A CSPRNG token is fixed width.
set -e; . "$(dirname "$0")/_lib.sh"

LENS=""
for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
  J="$(mktemp)"
  curl -s -c "$J" -X POST "$TARGET/api/auth/login" -H 'content-type: application/json' \
    -d '{"email":"user1@bench.local","password":"User123!"}' >/dev/null
  SID=$(awk '$6=="sid"{print $7}' "$J")
  rm -f "$J"
  [ -n "$SID" ] || exit 1
  # base36 only - a hex/uuid/base64url token would fail this
  echo "$SID" | grep -Eq '^[0-9a-z]+$' || exit 1
  # and far too short to be 256 bits of anything
  [ "${#SID}" -lt 40 ] || exit 1
  LENS="$LENS ${#SID}"
done

# variable width across samples = a stringified float, not a fixed-width token
DISTINCT=$(echo $LENS | tr ' ' '\n' | sort -u | wc -l | tr -d ' ')
[ "$DISTINCT" -ge 2 ]
