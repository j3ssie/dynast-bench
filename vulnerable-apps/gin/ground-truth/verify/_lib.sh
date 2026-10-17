# Shared helpers for the gin ground-truth PoCs.
# Each PoC exits 0 if the target is VULNERABLE, non-zero if not.
TARGET="${TARGET:-http://127.0.0.1:13311}"
VT="x-verify-token: ${VERIFY_TOKEN:-benchsecret}"
JAR="$(mktemp)"
# Every cookie jar a PoC opens (new_jar adds to this) goes when it exits.
_JARS="$JAR"
trap 'rm -f $_JARS' EXIT

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

login() { login_as "$JAR" "$1" "$2"; }

post_id()   { post_field "$1" id; }
user_id()   { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id",""))'; }
user_role() { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("role",""))'; }
json_get()  { python3 -c 'import sys,json; print(json.load(sys.stdin).get(sys.argv[1], ""))' "$1"; }
reset()     { curl -s -X POST -H "$VT" "$TARGET/api/_verify/reset" >/dev/null; }

# A cookie jar per actor, for PoCs that hold two sessions at once.
# new_jar must run in the PoC's own shell (`new_jar ED`), not in $(...), or the
# jar never reaches _JARS and is not cleaned up.
new_jar()  { local f; f="$(mktemp)"; _JARS="$_JARS $f"; eval "$1=\$f"; }
login_as() {
  curl -s -c "$1" -X POST "$TARGET/api/auth/login" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$2\",\"password\":\"$3\"}" >/dev/null
}
post_field() { curl -s -H "$VT" "$TARGET/api/_verify/post?slug=$1" | json_get "$2"; }
org_field()  { curl -s -H "$VT" "$TARGET/api/_verify/org?slug=$1" | json_get "$2"; }
# A JSON request as the session in jar $1: req JAR METHOD PATH [BODY]; prints the body.
req() {
  local body='{}'; [ -n "${4:-}" ] && body="$4"
  curl -s -b "$1" -c "$1" -X "$2" "$TARGET$3" -H 'content-type: application/json' -d "$body"
}
