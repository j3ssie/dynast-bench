# Shared helpers for the php ground-truth PoCs.
# Each PoC exits 0 if the target is VULNERABLE, non-zero if not.
TARGET="${TARGET:-http://127.0.0.1:13311}"

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
  curl -s -c "$JAR" -X POST "$TARGET/login.php" \
    -d "email=$1" -d "password=$2" >/dev/null
}
json_get() { python3 -c 'import sys,json; print(json.load(sys.stdin).get(sys.argv[1], ""))' "$1"; }
post_id() { curl -s -H "$VT" "$TARGET/api/_verify/post.php?slug=$1" | json_get id; }
user_id() { curl -s -H "$VT" "$TARGET/api/_verify/user.php?email=$1" | json_get id; }
pma_url() { python3 - "$TARGET" <<'PY'
import sys, urllib.parse
u=urllib.parse.urlparse(sys.argv[1])
host=u.hostname or '127.0.0.1'
print(f"{u.scheme or 'http'}://{host}:8081")
PY
}
user_role() { curl -s -H "$VT" "$TARGET/api/_verify/user.php?email=$1" | json_get role; }
