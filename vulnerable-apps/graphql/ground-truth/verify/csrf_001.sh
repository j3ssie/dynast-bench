#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
python3 - <<'PY' "$TARGET" | sh | grep -q 'token'
from urllib.parse import quote
import sys
q='mutation { login(email:"admin", password:"admin") { token } }'
print('curl -s "'+sys.argv[1]+'/graphql?query='+quote(q)+'"')
PY
