# Shared helpers for the gin ground-truth PoCs.
# Each PoC exits 0 if the target is VULNERABLE, non-zero if not.
TARGET="${TARGET:-http://127.0.0.1:13311}"
VT="x-verify-token: ${VERIFY_TOKEN:-benchsecret}"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

# Headless-browser helpers, for the one bug whose sink only exists once the
# page's own JS has run. Walk up to the repo root rather than hardcoding a
# depth, so this keeps working if the app is moved.
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

# percent-encode $1 for use in a query string
urlenc() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1"; }

login() {
  curl -s -c "$JAR" -X POST "$TARGET/api/auth/login" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$1\",\"password\":\"$2\"}" >/dev/null
}

post_id()   { curl -s -H "$VT" "$TARGET/api/_verify/post?slug=$1"  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id",""))'; }
user_id()   { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id",""))'; }
user_role() { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("role",""))'; }
json_get()  { python3 -c 'import sys,json; print(json.load(sys.stdin).get(sys.argv[1], ""))' "$1"; }
reset()     { curl -s -X POST -H "$VT" "$TARGET/api/_verify/reset" >/dev/null; }
