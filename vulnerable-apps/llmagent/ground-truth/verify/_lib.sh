#!/usr/bin/env bash
set -u
TARGET="${TARGET:-http://127.0.0.1:13311}"
VERIFY_TOKEN="${VERIFY_TOKEN:-benchsecret}"
# A URL the AGENT dials is dialled from inside the container, so it keeps the
# container port - $TARGET is a host address the container cannot reach, and a
# PoC that hands the agent one only ever gets "fetch failed" back.
SELF_INTERNAL="${SELF_INTERNAL:-http://127.0.0.1:3000}"

tmp_json() { mktemp "${TMPDIR:-/tmp}/llmagent.XXXXXX"; }
json_get() { curl -fsS "$TARGET$1"; }
json_post() { curl -fsS -H 'content-type: application/json' -X POST -d "$2" "$TARGET$1"; }
login() {
  local email="$1" pass="${2:-User123!}"
  curl -fsS -H 'content-type: application/json' -X POST -d "{\"email\":\"$email\",\"password\":\"$pass\"}" "$TARGET/api/login" \
    | node -e "let s='';process.stdin.on('data',c=>s+=c);process.stdin.on('end',()=>{let j=JSON.parse(s);process.stdout.write(j.token||'')})"
}
start_run() {
  local token="$1" prompt="$2" options="${3:-{}}"
  curl -fsS -H 'content-type: application/json' -H "authorization: Bearer $token" -X POST \
    -d "{\"prompt\":$(node -e 'process.stdout.write(JSON.stringify(process.argv[1]))' "$prompt"),\"options\":$options}" \
    "$TARGET/api/runs" \
    | node -e "let s='';process.stdin.on('data',c=>s+=c);process.stdin.on('end',()=>{let j=JSON.parse(s);process.stdout.write(j.id||'')})"
}
verify_run() { curl -fsS -H "X-Verify-Token: $VERIFY_TOKEN" "$TARGET/api/_verify/run?id=$1"; }
contains_in_run() {
  local id="$1" needle="$2"
  verify_run "$id" | NEEDLE="$needle" node -e "let s='';process.stdin.on('data',c=>s+=c);process.stdin.on('end',()=>{process.exit(s.includes(process.env.NEEDLE)?0:1)})"
}
contains_http() {
  node -e "let s='';process.stdin.on('data',c=>s+=c);process.stdin.on('end',()=>process.exit(s.includes(process.argv[1])?0:1))" -- "$1"
}
reset_app() { curl -fsS -H "X-Verify-Token: $VERIFY_TOKEN" -X POST "$TARGET/api/_verify/reset" >/dev/null || true; }
