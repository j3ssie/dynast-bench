#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
reset_state
tok=$(login_token user1@bench.local User123!)
tmp=$(mktemp)
for i in 1 2 3 4; do
  (gql "mutation { inviteUser(email:\"race$i@bench.local\") { ok } }" "$tok" >> "$tmp") &
done
wait
python3 - "$tmp" <<'PY'
import sys
s=open(sys.argv[1]).read()
sys.exit(0 if s.count('"ok":true') >= 2 else 1)
PY
rm -f "$tmp"
