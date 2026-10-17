# Shared helpers for the nextjs ground-truth PoCs.
# Each PoC exits 0 if the target is VULNERABLE, non-zero if not (i.e. it PASSes
# against vuln/ and FAILs against safe/). Point at a variant with TARGET=...
TARGET="${TARGET:-http://127.0.0.1:13311}"
VT="x-verify-token: ${VERIFY_TOKEN:-benchsecret}"
JAR="$(mktemp)"
# Every cookie jar a PoC opens (new_jar adds to this) goes when it exits.
_JARS="$JAR"
trap 'rm -f $_JARS' EXIT

# Headless-browser helpers, for the few bugs whose sink only exists once the
# page's own JS has run. Walk up to the repo root rather than hardcoding a depth,
# so this keeps working if the app is moved.
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

login() { login_as "$JAR" "$1" "$2"; }
post_id()   { curl -s -H "$VT" "$TARGET/api/_verify/post?slug=$1"  | json_get id; }
user_id()   { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | json_get id; }
user_role() { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | json_get role; }
json_get() { python3 -c 'import sys,json; print(json.load(sys.stdin).get(sys.argv[1], ""))' "$1"; }
b64url()    { python3 -c 'import base64,sys;print(base64.urlsafe_b64encode(sys.argv[1].encode()).rstrip(b"=").decode())' "$1"; }
b64dec()    { python3 -c 'import base64,sys;sys.stdout.write(base64.b64decode(sys.argv[1]).decode("utf-8","replace"))' "$1"; }

# Every /_next/static/chunks/*.js referenced by page $1 (default "/"), fetched
# with the PoC's session so signed-in pages list their chunks too.
chunk_urls() {
  curl -s -b "$JAR" "$TARGET${1:-/}" | grep -o '/_next/static/chunks/[A-Za-z0-9._/%-]*\.js' | sort -u
}
# The concatenated browser bundle for page $1 — what a visitor can actually read.
bundle_text() {
  local c; for c in $(chunk_urls "${1:-/}"); do curl -s "$TARGET$c"; done
}

# A cookie jar per actor, for PoCs that hold two sessions at once (the second
# actor is usually the one granting, approving or revoking something).
# new_jar must run in the PoC's own shell (`new_jar ED`), not in $(...), or the
# jar never reaches _JARS and is not cleaned up.
new_jar()  { local f; f="$(mktemp)"; _JARS="$_JARS $f"; eval "$1=\$f"; }
login_as() {
  curl -s -c "$1" -X POST "$TARGET/api/auth/login" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$2\",\"password\":\"$3\"}" >/dev/null
}
# POST a JSON body as the session in jar $1; prints the HTTP status only.
post_status() {
  local body='{}'; [ -n "${3:-}" ] && body="$3"
  curl -s -o /dev/null -w '%{http_code}' -b "$1" -c "$1" -X POST "$TARGET$2" \
    -H 'content-type: application/json' -d "$body"
}
post_field()    { curl -s -H "$VT" "$TARGET/api/_verify/post?slug=$1" | json_get "$2"; }
comment_field() { curl -s -H "$VT" "$TARGET/api/_verify/comment?id=$1" | json_get "$2"; }
