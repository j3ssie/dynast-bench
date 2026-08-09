# Shared helpers for the php ground-truth PoCs.
# Each PoC exits 0 if the target is VULNERABLE, non-zero if not.
TARGET="${TARGET:-http://127.0.0.1:13311}"
VT="x-verify-token: ${VERIFY_TOKEN:-benchsecret}"
JAR="$(mktemp)"
login() {
  curl -s -c "$JAR" -X POST "$TARGET/login.php" \
    -d "email=$1" -d "password=$2" >/dev/null
}
post_id() { curl -s -H "$VT" "$TARGET/api/_verify/post.php?slug=$1" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id", ""))'; }
user_id() { curl -s -H "$VT" "$TARGET/api/_verify/user.php?email=$1" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("id", ""))'; }
json_get() { python3 -c 'import sys,json; print(json.load(sys.stdin).get(sys.argv[1], ""))' "$1"; }
pma_url() { python3 - "$TARGET" <<'PY'
import sys, urllib.parse
u=urllib.parse.urlparse(sys.argv[1])
host=u.hostname or '127.0.0.1'
print(f"{u.scheme or 'http'}://{host}:8081")
PY
}
