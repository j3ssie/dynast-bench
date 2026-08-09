# Shared helpers for the nestjs ground-truth PoCs.
# Each PoC exits 0 if the target is VULNERABLE, non-zero if not.
TARGET="${TARGET:-http://127.0.0.1:13311}"
VT="x-verify-token: ${VERIFY_TOKEN:-benchsecret}"
JAR="$(mktemp)"
trap 'rm -f "$JAR" "$JAR.headers" "$JAR.body" 2>/dev/null || true' EXIT

login() {
  curl -s -c "$JAR" -b "$JAR" -X POST "$TARGET/api/auth/login" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$1\",\"password\":\"$2\"}" >/dev/null
}

post_id()   { curl -s -H "$VT" "$TARGET/api/_verify/post?slug=$1"  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id",""))'; }
user_role() { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("role",""))'; }
org_field() { curl -s -H "$VT" "$TARGET/api/_verify/org?slug=$1" | python3 -c 'import sys,json;print(json.load(sys.stdin).get(sys.argv[1],""))' "$2"; }
cleanup_invites() { curl -s -X DELETE -H "$VT" "$TARGET/api/_verify/invites?prefix=$1" >/dev/null || true; }
invite_count() { curl -s -H "$VT" "$TARGET/api/_verify/invites?prefix=$1" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("count",0))'; }
json_get()  { python3 -c 'import sys,json; print(json.load(sys.stdin).get(sys.argv[1], ""))' "$1"; }
b64url()    { python3 -c 'import base64,sys;print(base64.urlsafe_b64encode(sys.argv[1].encode()).rstrip(b"=").decode())' "$1"; }
cookie_val() { awk '$6=="bench.sid" {print $7}' "$1" | tail -1; }
