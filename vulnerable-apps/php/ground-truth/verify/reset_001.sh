#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
email='user1@bench.local'
expected=$(python3 - <<'PY'
import hashlib
print(hashlib.md5(b'user1@bench.localbench-reset').hexdigest())
PY
)
curl -s -X POST "$TARGET/request_reset.php" -d "email=$email" | grep -q "$expected"
