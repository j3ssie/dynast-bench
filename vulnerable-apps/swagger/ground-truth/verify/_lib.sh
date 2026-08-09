# Shared helpers for the swagger ground-truth PoCs.
# Each PoC exits 0 if the target is VULNERABLE, non-zero if not.
TARGET="${TARGET:-http://127.0.0.1:13311}"
VT="x-verify-token: ${VERIFY_TOKEN:-benchsecret}"
JAR="$(mktemp)"

cleanup() { rm -f "$JAR" 2>/dev/null || true; }
trap cleanup EXIT

login() {
  curl -s -c "$JAR" -X POST "$TARGET/api/auth/login" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$1\",\"password\":\"$2\"}" >/dev/null
}

api_token() {
  curl -s -X POST "$TARGET/api/v1/auth/token" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$1\",\"password\":\"$2\"}" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token", ""))'
}

user_id() { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("id", ""))'; }
user_role() { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("role", ""))'; }
post_id() { curl -s -H "$VT" "$TARGET/api/_verify/post?slug=$1" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("id", ""))'; }
reset_state() { curl -s -X POST -H "$VT" "$TARGET/api/_verify/reset-state" >/dev/null || true; }
b64url() { python3 -c 'import base64,sys; print(base64.urlsafe_b64encode(sys.argv[1].encode()).rstrip(b"=").decode())' "$1"; }
