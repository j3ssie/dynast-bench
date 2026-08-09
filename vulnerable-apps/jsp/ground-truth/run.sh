#!/usr/bin/env bash
set -u
MODE="${1:-expect-vuln}"
DIR="$(cd "$(dirname "$0")/verify" && pwd)"
export TARGET="${TARGET:-http://127.0.0.1:13311}"
pass=0; fail=0; bad=""
for f in $(find "$DIR" -maxdepth 1 -name '*.sh' ! -name '_lib.sh' | sort); do
  name=$(basename "$f")
  if bash "$f" >/dev/null 2>&1; then exploitable=1; else exploitable=0; fi
  if [ "$MODE" = "expect-vuln" ]; then
    if [ "$exploitable" = 1 ]; then echo "  ok  $name (exploitable)"; pass=$((pass+1)); else echo "  XX  $name (NOT exploitable — expected vuln)"; fail=$((fail+1)); bad="$bad $name"; fi
  else
    if [ "$exploitable" = 0 ]; then echo "  ok  $name (fixed)"; pass=$((pass+1)); else echo "  XX  $name (STILL exploitable — expected safe)"; fail=$((fail+1)); bad="$bad $name"; fi
  fi
done
echo "----  mode=$MODE  target=$TARGET  ok=$pass  bad=$fail"
[ "$fail" = 0 ] || { echo "FAILURES:$bad"; exit 1; }
