#!/usr/bin/env bash
# Run every ground-truth PoC against $TARGET and check the outcome.
# A PoC exits 0 when the target is vulnerable.
set -u
MODE="${1:-expect-vuln}"
DIR="$(cd "$(dirname "$0")/verify" && pwd)"
export TARGET="${TARGET:-http://127.0.0.1:13311}"
pass=0; fail=0; bad=""
for f in $(find "$DIR" -maxdepth 1 -name '*.sh' ! -name '_lib.sh' | sort); do
  name=$(basename "$f")
  if bash "$f" >/dev/null 2>&1; then exploitable=1; else exploitable=0; fi
  if [ "$MODE" = "expect-vuln" ]; then
    if [ "$exploitable" = 1 ]; then printf '  ok  %s (exploitable)\n' "$name"; pass=$((pass+1));
    else printf '  XX  %s (NOT exploitable — expected vuln)\n' "$name"; fail=$((fail+1)); bad="$bad $name"; fi
  else
    if [ "$exploitable" = 0 ]; then printf '  ok  %s (fixed)\n' "$name"; pass=$((pass+1));
    else printf '  XX  %s (STILL exploitable — expected safe)\n' "$name"; fail=$((fail+1)); bad="$bad $name"; fi
  fi
done
printf '%s\n' "----  mode=$MODE  target=$TARGET  ok=$pass  bad=$fail"
[ "$fail" = 0 ] || { printf 'FAILURES:%s\n' "$bad"; exit 1; }
