# Shared helpers for the fastapi ground-truth PoCs.
# Each PoC exits 0 if the target is VULNERABLE, non-zero if not.
TARGET="${TARGET:-http://127.0.0.1:13311}"
VT="x-verify-token: ${VERIFY_TOKEN:-benchsecret}"
JAR="$(mktemp)"

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
b64url()    { python3 -c 'import base64,sys;print(base64.urlsafe_b64encode(sys.argv[1].encode()).rstrip(b"=").decode())' "$1"; }
b64dec()    { python3 -c 'import base64,sys;sys.stdout.write(base64.b64decode(sys.argv[1]).decode("utf-8","replace"))' "$1"; }
