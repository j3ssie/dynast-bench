# Shared helpers for the fastapi ground-truth PoCs.
# Each PoC exits 0 if the target is VULNERABLE, non-zero if not.
TARGET="${TARGET:-http://127.0.0.1:13311}"

# Headless-browser helpers (DOM XSS, postMessage). Walk up to the repo root.
_dynast_root() {
  [ -n "${DYNAST_BENCH_ROOT:-}" ] && { printf '%s' "$DYNAST_BENCH_ROOT"; return; }
  local d; d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  while [ -n "$d" ]; do
    [ -f "$d/dynast-bench/tools/browser/browser.sh" ] && { printf '%s' "$d"; return; }
    d="${d%/*}"
  done
}
# shellcheck source=/dev/null
_DYNAST_BROWSER_LIB="$(_dynast_root)/dynast-bench/tools/browser/browser.sh"
[ -f "$_DYNAST_BROWSER_LIB" ] && . "$_DYNAST_BROWSER_LIB"
VT="x-verify-token: ${VERIFY_TOKEN:-benchsecret}"
JAR="$(mktemp)"

login() {
  curl -s -c "$JAR" -X POST "$TARGET/api/auth/login" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$1\",\"password\":\"$2\"}" >/dev/null
}

json_get()  { python3 -c 'import sys,json; print(json.load(sys.stdin).get(sys.argv[1], ""))' "$1"; }

api_login_token() {
  curl -s -X POST "$TARGET/api/auth/token" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$1\",\"password\":\"$2\"}" | json_get token
}

post_id()   { curl -s -H "$VT" "$TARGET/api/_verify/post?slug=$1"  | json_get id; }
user_id()   { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | json_get id; }
user_role() { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | json_get role; }
b64url()    { python3 -c 'import base64,sys;print(base64.urlsafe_b64encode(sys.argv[1].encode()).rstrip(b"=").decode())' "$1"; }
b64dec()    { python3 -c 'import base64,sys;sys.stdout.write(base64.b64decode(sys.argv[1]).decode("utf-8","replace"))' "$1"; }
