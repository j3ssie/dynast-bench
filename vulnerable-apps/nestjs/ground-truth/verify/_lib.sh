# Shared helpers for the nestjs ground-truth PoCs.
# Each PoC exits 0 if the target is VULNERABLE, non-zero if not.
TARGET="${TARGET:-http://127.0.0.1:13311}"
VT="x-verify-token: ${VERIFY_TOKEN:-benchsecret}"
JAR="$(mktemp)"
trap 'rm -f "$JAR" "$JAR.headers" "$JAR.body" 2>/dev/null || true' EXIT

# Headless-browser helpers, for the bugs whose sink only exists once the page's
# own JS has run (DOM XSS, postMessage). Walk up to the repo root.
_dynast_root() {
  [ -n "${DYNAST_BENCH_ROOT:-}" ] && { printf '%s' "$DYNAST_BENCH_ROOT"; return; }
  local d
  d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  while [ -n "$d" ]; do
    [ -f "$d/dynast-bench/tools/browser/browser.sh" ] && { printf '%s' "$d"; return; }
    d="${d%/*}"
  done
}
# shellcheck source=/dev/null
_DYNAST_BROWSER_LIB="$(_dynast_root)/dynast-bench/tools/browser/browser.sh"
[ -f "$_DYNAST_BROWSER_LIB" ] && . "$_DYNAST_BROWSER_LIB"

login() {
  curl -s -c "$JAR" -b "$JAR" -X POST "$TARGET/api/auth/login" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$1\",\"password\":\"$2\"}" >/dev/null
}

json_get()  { python3 -c 'import sys,json; print(json.load(sys.stdin).get(sys.argv[1], ""))' "$1"; }
post_id()   { curl -s -H "$VT" "$TARGET/api/_verify/post?slug=$1"  | json_get id; }
user_role() { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | json_get role; }
org_field() { curl -s -H "$VT" "$TARGET/api/_verify/org?slug=$1" | python3 -c 'import sys,json;print(json.load(sys.stdin).get(sys.argv[1],""))' "$2"; }
cleanup_invites() { curl -s -X DELETE -H "$VT" "$TARGET/api/_verify/invites?prefix=$1" >/dev/null || true; }
invite_count() { curl -s -H "$VT" "$TARGET/api/_verify/invites?prefix=$1" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("count",0))'; }
b64url()    { python3 -c 'import base64,sys;print(base64.urlsafe_b64encode(sys.argv[1].encode()).rstrip(b"=").decode())' "$1"; }
cookie_val() { awk '$6=="bench.sid" {print $7}' "$1" | tail -1; }
user_id() { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | json_get id; }
