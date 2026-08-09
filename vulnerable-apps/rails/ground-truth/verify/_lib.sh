# Shared helpers for Rails ground-truth PoCs.
# Every PoC exits 0 if the target is VULNERABLE, non-zero if fixed.
TARGET="${TARGET:-http://127.0.0.1:13311}"
VT="X-Verify-Token: ${VERIFY_TOKEN:-benchsecret}"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

login() {
  curl -s -c "$JAR" -b "$JAR" -X POST "$TARGET/api/auth/login" \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode "email=$1" --data-urlencode "password=$2" >/dev/null
}
post_id() { curl -s -H "$VT" "$TARGET/api/_verify/post?slug=$1" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("id", ""))'; }
user_id() { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("id", ""))'; }
user_role() { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("role", ""))'; }
user_display() { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("displayName", ""))'; }
urlenc() { python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$1"; }
