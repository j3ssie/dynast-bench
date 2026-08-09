#!/usr/bin/env bash
set -u
TARGET="${TARGET:-http://127.0.0.1:13311}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WS_TARGET="${TARGET/http:/ws:}"
login_token() {
  local email="$1" password="$2" ttl="${3:-3600}"
  curl -sS -X POST "$TARGET/api/auth/login" -H 'content-type: application/json' \
    --data "{\"email\":\"$email\",\"username\":\"$email\",\"password\":\"$password\",\"ttl\":$ttl}" \
    | node -e "let s='';process.stdin.on('data',c=>s+=c);process.stdin.on('end',()=>{try{let j=JSON.parse(s); if(j.token) console.log(j.token); else process.exit(1)}catch(e){process.exit(1)}})"
}
post_id() {
  curl -sS "$TARGET/api/_verify/post?slug=$1" -H 'X-Verify-Token: benchsecret'     | node -e "let s='';process.stdin.on('data',c=>s+=c);process.stdin.on('end',()=>{let j=JSON.parse(s); if(j.id) console.log(j.id); else process.exit(1)})"
}
ws_send() { node "$DIR/ws.mjs" "$@"; }
user_token() { login_token user1@bench.local User123! "${1:-3600}"; }
admin_token() { login_token admin@bench.local Admin123! "${1:-3600}"; }
service_token() { login_token admin admin "${1:-3600}"; }
