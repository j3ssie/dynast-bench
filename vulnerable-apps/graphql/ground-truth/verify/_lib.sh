# Shared helpers for GraphQL ground-truth PoCs.
# Each PoC exits 0 if the target is VULNERABLE, non-zero if not.
TARGET="${TARGET:-http://127.0.0.1:13311}"
VT="x-verify-token: ${VERIFY_TOKEN:-benchsecret}"

json_escape() { python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'; }

gql() {
  local query="$1" token="${2:-}" vars="${3:-}"
  [ -n "$vars" ] || vars='{}'
  if [ -n "$token" ]; then
    python3 - "$query" "$vars" <<'PY' | curl -s -X POST "$TARGET/graphql" -H 'content-type: application/json' -H "authorization: Bearer $token" --data-binary @-
import json,sys
print(json.dumps({"query": sys.argv[1], "variables": json.loads(sys.argv[2])}))
PY
  else
    python3 - "$query" "$vars" <<'PY' | curl -s -X POST "$TARGET/graphql" -H 'content-type: application/json' --data-binary @-
import json,sys
print(json.dumps({"query": sys.argv[1], "variables": json.loads(sys.argv[2])}))
PY
  fi
}

gql_raw() {
  curl -s -X POST "$TARGET/graphql" -H 'content-type: application/json' "$@"
}

login_token() {
  local email="$1" password="$2"
  local q='mutation($e:String!,$p:String!){ login(email:$e,password:$p){ token } }'
  local vars
  vars=$(python3 - "$email" "$password" <<'PY'
import json,sys
print(json.dumps({"e": sys.argv[1], "p": sys.argv[2]}))
PY
)
  gql "$q" "" "$vars" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("data",{}).get("login",{}).get("token", ""))'
}

user_id() { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id", ""))'; }
post_id() { curl -s -H "$VT" "$TARGET/api/_verify/post?slug=$1" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id", ""))'; }
reset_state() { curl -s -X POST -H "$VT" "$TARGET/api/_verify/reset" >/dev/null; }

gid() { python3 -c 'import base64,sys; print(base64.b64encode(sys.argv[1].encode()).decode())' "$1"; }
contains() { grep -q "$1"; }
