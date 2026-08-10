#!/usr/bin/env bash
# Run every ground-truth PoC against $TARGET and check the outcome.
#   run.sh expect-vuln   -> every PoC must be exploitable (exit 0)
#   run.sh expect-safe   -> every PoC must be fixed (non-zero)
# A PoC exits 0 when the target is vulnerable.
set -u
MODE="${1:-expect-vuln}"
DIR="$(cd "$(dirname "$0")/verify" && pwd)"
export TARGET="${TARGET:-http://127.0.0.1:13311}"

# Some PoCs drive a real browser. Build that image once, up front: doing it
# lazily inside the first such PoC would bill its ~1min build to that PoC's
# timeout, and a missing image would surface as "NOT exploitable" — a wrong
# answer about the app — instead of "the harness could not run".
if grep -q 'browser_' "$DIR"/*.sh 2>/dev/null; then
  # shellcheck source=/dev/null
  . "$DIR/_lib.sh"
  if ! browser_require; then
    echo "!! browser PoCs cannot run — see the message above" >&2
    exit 2
  fi
fi

pass=0; fail=0; bad=""
for f in $(ls "$DIR"/*.sh | grep -v '/_lib.sh'); do
  name=$(basename "$f")
  if bash "$f" >/dev/null 2>&1; then exploitable=1; else exploitable=0; fi
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
