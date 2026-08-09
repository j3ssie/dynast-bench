# Shared helpers for the golang ground-truth PoCs.
# Each PoC exits 0 if the target is VULNERABLE, non-zero if not.
TARGET="${TARGET:-http://127.0.0.1:13311}"
VT="x-verify-token: ${VERIFY_TOKEN:-benchsecret}"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

login() {
  curl -s -c "$JAR" -X POST "$TARGET/api/auth/login" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$1\",\"password\":\"$2\"}" >/dev/null
}

api_login_token() {
  curl -s -X POST "$TARGET/api/auth/token" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$1\",\"password\":\"$2\"}" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("token", ""))'
}

post_id()   { curl -s -H "$VT" "$TARGET/api/_verify/post?slug=$1"  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id",""))'; }
user_id()   { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id",""))'; }
user_role() { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("role",""))'; }
json_get()  { python3 -c 'import sys,json; print(json.load(sys.stdin).get(sys.argv[1], ""))' "$1"; }
reset_acme(){ curl -s -X POST -H "$VT" "$TARGET/api/_verify/reset-acme" >/dev/null; }

grafana_url() {
  python3 - "$TARGET" <<'PYLIB'
from urllib.parse import urlparse
import sys
u=urlparse(sys.argv[1])
print(f"{u.scheme}://{u.hostname}:3001")
PYLIB
}
