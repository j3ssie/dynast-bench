TARGET="${TARGET:-http://127.0.0.1:13311}"
VT="X-Verify-Token: ${VERIFY_TOKEN:-benchsecret}"
JAR="$(mktemp)"
cleanup() { rm -f "$JAR"; }
trap cleanup EXIT
login() { curl -s -c "$JAR" -X POST "$TARGET/api/auth/login" -H 'content-type: application/json' -d "{\"email\":\"$1\",\"password\":\"$2\"}" >/dev/null; }
post_id() { curl -s -H "$VT" "$TARGET/api/_verify/post?slug=$1" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id",""))'; }
b64url() { python3 -c 'import base64,sys;print(base64.urlsafe_b64encode(sys.argv[1].encode()).rstrip(b"=").decode())' "$1"; }
json_string() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"; }
