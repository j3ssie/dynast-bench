#!/usr/bin/env bash
set -u
MODE="${1:-expect-vuln}"
DIR="$(cd "$(dirname "$0")/verify" && pwd)"
export TARGET="${TARGET:-http://127.0.0.1:13311}"
pass=0; fail=0; bad=""
for f in "$DIR"/*.sh; do
  [ "$(basename "$f")" = "_lib.sh" ] && continue
  name=$(basename "$f")
  if python3 - "$f" "$MODE" "$name" <<'PY' >/dev/null 2>&1
import subprocess, sys
script, mode, name = sys.argv[1], sys.argv[2], sys.argv[3]
if mode == 'expect-vuln':
    timeout = 75
else:
    timeout = 35 if name == 'quota_race_001.sh' else 8
try:
    sys.exit(subprocess.run(['bash', script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout).returncode)
except subprocess.TimeoutExpired:
    sys.exit(124)
PY
  then exploitable=1; else exploitable=0; fi
  if [ "$MODE" = "expect-vuln" ]; then
    if [ "$exploitable" = 1 ]; then echo "  ok  $name (exploitable)"; pass=$((pass+1));
    else echo "  XX  $name (NOT exploitable — expected vuln)"; fail=$((fail+1)); bad="$bad $name"; fi
  else
    if [ "$exploitable" = 0 ]; then echo "  ok  $name (fixed)"; pass=$((pass+1));
    else echo "  XX  $name (STILL exploitable — expected safe)"; fail=$((fail+1)); bad="$bad $name"; fi
  fi
done
echo "----  mode=$MODE  target=$TARGET  ok=$pass  bad=$fail"
[ "$fail" = 0 ] || { echo "FAILURES:$bad"; exit 1; }
