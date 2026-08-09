# Shared helpers for llmchat ground-truth PoCs.
# A PoC exits 0 when the target is vulnerable, non-zero when fixed.
TARGET="${TARGET:-http://127.0.0.1:13311}"
VT="x-verify-token: ${VERIFY_TOKEN:-benchsecret}"
JAR="$(mktemp)"
cleanup_jar() { rm -f "$JAR"; }
trap cleanup_jar EXIT

login() {
  local email="$1" password="$2"
  TOKEN=$(curl -s -c "$JAR" -X POST "$TARGET/api/auth/login" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$email\",\"password\":\"$password\"}" \
    | python3 -c 'import sys,json; print(json.load(sys.stdin).get("token",""))')
  [ -n "$TOKEN" ]
}

auth_json() {
  curl -s -b "$JAR" -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' "$@"
}

get_auth() {
  curl -s -b "$JAR" -H "authorization: Bearer $TOKEN" "$@"
}

verify_get() {
  curl -s -H "$VT" "$TARGET$1"
}

conv_id_by_title() {
  verify_get "/api/_verify/conversation?title=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$1")" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("id",""))'
}

doc_id_by_slug() {
  verify_get "/api/_verify/document?slug=$(python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$1")" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("id",""))'
}

flush_cache() {
  curl -s -X POST -H "$VT" "$TARGET/api/_verify/flush_cache" >/dev/null
}

reset_quota() {
  curl -s -X POST -H "$VT" "$TARGET/api/_verify/reset_quota" >/dev/null
}

json_escape() {
  python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"
}
