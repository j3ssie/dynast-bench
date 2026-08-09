# Shared helpers for the jsp ground-truth PoCs.
TARGET="${TARGET:-http://127.0.0.1:13311}"
VT="X-Verify-Token: ${VERIFY_TOKEN:-benchsecret}"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT
login() {
  curl -s -c "$JAR" -b "$JAR" -X POST "$TARGET/login" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "email=$1" --data-urlencode "password=$2" >/dev/null
}
post_id() { curl -s -H "$VT" "$TARGET/api/_verify/post?slug=$1" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("id",""))'; }
user_id() { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("id",""))'; }
urlenc() { python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$1"; }
b64url() { python3 -c 'import base64,sys; print(base64.urlsafe_b64encode(sys.argv[1].encode()).rstrip(b"=").decode())' "$1"; }
