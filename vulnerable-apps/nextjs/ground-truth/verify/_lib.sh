# Shared helpers for the nextjs ground-truth PoCs.
# Each PoC exits 0 if the target is VULNERABLE, non-zero if not (i.e. it PASSes
# against vuln/ and FAILs against safe/). Point at a variant with TARGET=...
TARGET="${TARGET:-http://127.0.0.1:13311}"
VT="x-verify-token: ${VERIFY_TOKEN:-benchsecret}"
JAR="$(mktemp)"

login() {
  curl -s -c "$JAR" -X POST "$TARGET/api/auth/login" \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$1\",\"password\":\"$2\"}" >/dev/null
}
post_id()   { curl -s -H "$VT" "$TARGET/api/_verify/post?slug=$1"  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id",""))'; }
user_id()   { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id",""))'; }
user_role() { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("role",""))'; }
b64url()    { python3 -c 'import base64,sys;print(base64.urlsafe_b64encode(sys.argv[1].encode()).rstrip(b"=").decode())' "$1"; }
b64dec()    { python3 -c 'import base64,sys;sys.stdout.write(base64.b64decode(sys.argv[1]).decode("utf-8","replace"))' "$1"; }

# Every /_next/static/chunks/*.js referenced by page $1 (default "/").
chunk_urls() {
  curl -s "$TARGET${1:-/}" | grep -o '/_next/static/chunks/[A-Za-z0-9._/-]*\.js' | sort -u
}
# The concatenated browser bundle for page $1 — what a visitor can actually read.
bundle_text() {
  local c; for c in $(chunk_urls "${1:-/}"); do curl -s "$TARGET$c"; done
}
