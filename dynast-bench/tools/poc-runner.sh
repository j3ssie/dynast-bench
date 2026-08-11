# Shared ground-truth PoC runner.  Sourced by every app's ground-truth/run.sh.
#
#   run.sh expect-vuln   -> every PoC must demonstrate the bug
#   run.sh expect-safe   -> every PoC must be cleanly rejected
#
# WHY THIS EXISTS
#
# Each app used to run its own copy of `if bash poc.sh; then exploitable=1; else
# exploitable=0; fi`, which reduces every failure to "not exploitable". On the
# expect-safe leg that is the wrong answer for a whole class of events: point the
# suite at a port nothing is listening on and 5 of gin's 11 PoCs exit 1, exactly
# as they would if the bug were genuinely fixed. `make validate` would call that
# a pass.
#
# Exit status alone cannot separate the two - curl exits 1 for "no match" and 7
# for "could not connect", and a PoC ending in `grep -q` passes either through.
# So the runner owns an independent oracle instead: it proves the target is
# still answering before it believes any rejection.
#
#   0        the exploit worked            -> vulnerable
#   2        the PoC says it could not run -> harness (browser helpers use this)
#   124      the runner's deadline expired -> harness
#   126/127  not executable / no such cmd  -> harness
#   anything else, target still healthy    -> cleanly rejected -> fixed
#   anything else, target NOT healthy      -> harness
#
# A harness result is a failure in BOTH modes. "The suite could not run" must
# never be recorded as "the vulnerability is fixed".
#
# APP HOOKS - set before sourcing this file:
#   POC_SKIP="a.sh b.sh"     extra helpers in verify/ that are not PoCs
#   POC_HEALTH=/path         health endpoint (default /api/_verify/health)
#   POC_TIMEOUT=N            per-PoC deadline in seconds (default 120)
#   poc_timeout() { ... }    function: $1=poc name, $2=mode -> seconds, for apps
#                            whose PoCs need individual budgets

POC_HEALTH="${POC_HEALTH:-/api/_verify/health}"
POC_TIMEOUT="${POC_TIMEOUT:-120}"
POC_SKIP="${POC_SKIP:-}"

# So a PoC that needs the repo root (the browser helpers) does not have to walk
# up to find it - this file already knows where it is.
export DYNAST_BENCH_ROOT="${DYNAST_BENCH_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

# GNU coreutils where it exists (Linux, brew), otherwise a watchdog subshell.
# Not a micro-optimisation: without a deadline a hung PoC hangs the whole run,
# and llmagent was paying a python interpreter per PoC to get one.
if command -v timeout >/dev/null 2>&1; then _poc_timeout_cmd=timeout
elif command -v gtimeout >/dev/null 2>&1; then _poc_timeout_cmd=gtimeout
else _poc_timeout_cmd=""; fi

# Milliseconds without forking: bash 5 has EPOCHREALTIME (microseconds, as
# "seconds.micros"). Bash 3.2 - which is what macOS still ships as /bin/bash -
# does not, and BSD date has no %N, so that falls back to one perl per reading.
if [ -n "${EPOCHREALTIME:-}" ]; then
  _poc_now_ms() { local t="${EPOCHREALTIME/[.,]/}"; echo $(( ${t%???} )); }
elif ! date +%s%3N 2>/dev/null | grep -q 'N$'; then
  _poc_now_ms() { date +%s%3N; }
else
  _poc_now_ms() { perl -MTime::HiRes=time -e 'printf "%.0f\n", time()*1000' 2>/dev/null || echo $(( $(date +%s) * 1000 )); }
fi

_poc_secs() { printf '%d.%02d' $(( $1 / 1000 )) $(( $1 % 1000 / 10 )); }

# 0 = the app is up and serving. This is the oracle that lets a nonzero PoC be
# read as "the exploit was rejected" rather than "nothing was listening", so it
# has to distinguish a real response from a refused connection (000) and from an
# app that is answering but broken (5xx).
poc_healthy() {
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
    -H "X-Verify-Token: ${VERIFY_TOKEN:-benchsecret}" "${TARGET}${POC_HEALTH}" 2>/dev/null)"
  case "$code" in
    ""|000|5??) return 1 ;;
    *) return 0 ;;
  esac
}

_poc_run_one() {  # $1 = script path, $2 = seconds, $3 = stderr file -> exit code
  local script="$1" secs="$2" errfile="$3" rc pid guard
  if [ -n "$_poc_timeout_cmd" ]; then
    "$_poc_timeout_cmd" -k 5 "$secs" bash "$script" >/dev/null 2>"$errfile"
    rc=$?
  else
    bash "$script" >/dev/null 2>"$errfile" &
    pid=$!
    # A PoC has no state to flush, so the watchdog does not bother with TERM.
    ( sleep "$secs"; kill -KILL "$pid" 2>/dev/null ) >/dev/null 2>&1 &
    guard=$!
    wait "$pid" 2>/dev/null
    rc=$?
    # kill the subshell AND the sleep it forked: killing only the parent leaves
    # the sleep reparented to init, running out its full budget - one orphan per
    # PoC, hundreds alive at once over a full leg
    kill -KILL "$guard" 2>/dev/null
    pkill -P "$guard" 2>/dev/null
    wait "$guard" 2>/dev/null
  fi
  # both paths agree on one rule: killed by the deadline reads as 124
  case "$rc" in 137|143) rc=124 ;; esac
  return $rc
}

poc_run() {
  local mode="${1:-expect-vuln}"
  local dir="$POC_GT_DIR/verify"
  export TARGET="${TARGET:-http://127.0.0.1:13311}"

  case "$mode" in
    expect-vuln|expect-safe) ;;
    *) echo "usage: run.sh expect-vuln|expect-safe (got: $mode)" >&2; return 2 ;;
  esac

  # Nothing below can mean anything if the app is not up, so establish that once
  # rather than discovering it 40 PoCs later as 40 "fixed" verdicts.
  if ! poc_healthy; then
    echo "!! ${TARGET}${POC_HEALTH} is not answering - the app is not up" >&2
    echo "   every PoC would report 'not exploitable', which is not the same as 'fixed'" >&2
    return 2
  fi

  local list f name
  list="$(find "$dir" -maxdepth 1 -name '*.sh' ! -name '_lib.sh' | sort)"
  if [ -z "$list" ]; then
    echo "!! no PoCs found in $dir" >&2
    return 2
  fi

  # Build the browser image up front when any PoC drives one. Doing it lazily
  # bills a ~1min build to the first such PoC's deadline, and a missing image
  # would surface as "NOT exploitable" - a wrong answer about the app rather
  # than about us.
  if grep -q 'browser_' $list 2>/dev/null; then
    # shellcheck source=/dev/null
    . "$dir/_lib.sh"
    if ! browser_require; then
      echo "!! browser PoCs cannot run - see the message above" >&2
      return 2
    fi
  fi

  # An app that needs per-PoC budgets defines poc_timeout; everyone else gets the
  # flat one. Resolved once - the answer cannot change between PoCs.
  declare -F poc_timeout >/dev/null || poc_timeout() { echo "$POC_TIMEOUT"; }

  local pass=0 fail=0 harness=0 bad="" broke="" secs rc started elapsed why mark label
  # Not `trap ... EXIT`: several apps' _lib.sh set their own EXIT trap (to clean
  # up a cookie jar) and this shell has just sourced one of them.
  local errfile="${TMPDIR:-/tmp}/dynast-poc-err.$$"

  for f in $list; do
    name="${f##*/}"
    case " $POC_SKIP " in *" $name "*) continue ;; esac
    secs="$(poc_timeout "$name" "$mode")"

    started="$(_poc_now_ms)"
    _poc_run_one "$f" "$secs" "$errfile"
    rc=$?
    elapsed=$(( $(_poc_now_ms) - started ))

    why=""
    case "$rc" in
      0)   why="" ;;
      2)   why="the PoC reported it could not run" ;;
      124) why="timed out after ${secs}s" ;;
      126) why="not executable" ;;
      127) why="a command it needs is missing" ;;
      *)   poc_healthy || why="target stopped answering ${POC_HEALTH}" ;;
    esac

    if [ -n "$why" ]; then
      mark="!!"; label="harness: $why"; harness=$((harness+1)); broke="$broke $name"
    elif { [ "$mode" = expect-vuln ] && [ "$rc" = 0 ]; } ||
         { [ "$mode" = expect-safe ] && [ "$rc" != 0 ]; }; then
      mark="ok"; pass=$((pass+1))
      [ "$mode" = expect-vuln ] && label="exploitable" || label="fixed"
    else
      mark="XX"; fail=$((fail+1)); bad="$bad $name"
      [ "$mode" = expect-vuln ] && label="NOT exploitable - expected vuln" \
                                || label="STILL exploitable - expected safe"
    fi
    printf '  %s  %s (%s)  %ss\n' "$mark" "$name" "$label" "$(_poc_secs "$elapsed")"

    if [ -n "$why" ]; then
      tail -5 "$errfile" 2>/dev/null | sed 's/^/      /'
      # a dead target makes every later verdict meaningless too
      case "$why" in "target stopped"*) echo "   aborting: nothing after this can be trusted" >&2; break ;; esac
    fi
  done
  rm -f "$errfile"

  printf -- '----  mode=%s  target=%s  ok=%s  bad=%s  harness=%s\n' \
    "$mode" "$TARGET" "$pass" "$fail" "$harness"
  [ "$fail" = 0 ] || printf 'FAILURES:%s\n' "$bad"
  [ "$harness" = 0 ] || printf 'HARNESS:%s\n' "$broke"
  [ "$fail" = 0 ] && [ "$harness" = 0 ]
}
