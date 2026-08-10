# Shared helpers for Rails ground-truth PoCs.
# Every PoC exits 0 if the target is VULNERABLE, non-zero if fixed.
TARGET="${TARGET:-http://127.0.0.1:13311}"
VT="X-Verify-Token: ${VERIFY_TOKEN:-benchsecret}"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

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
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "email=$1" --data-urlencode "password=$2" >/dev/null
}
post_id() { curl -s -H "$VT" "$TARGET/api/_verify/post?slug=$1" | json_get id; }
user_id() { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | json_get id; }
user_role() { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | json_get role; }
user_display() { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | json_get displayName; }
json_get() { python3 -c 'import sys,json; print(json.load(sys.stdin).get(sys.argv[1], ""))' "$1"; }
urlenc() { python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$1"; }
