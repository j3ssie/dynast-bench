# Shared helpers for the laravel ground-truth PoCs.
# Each PoC exits 0 if the target is VULNERABLE, non-zero if not (PASS on vuln/,
# FAIL on safe/). Point at a variant with TARGET=...
TARGET="${TARGET:-http://127.0.0.1:13311}"
VT="x-verify-token: ${VERIFY_TOKEN:-benchsecret}"
JAR="$(mktemp)"
TOKEN=""

# Scrape a CSRF token (and seat a session cookie) from a Blade form page.
csrf_from() {
  curl -s -c "$JAR" -b "$JAR" "$TARGET${1:-/login}" \
    | sed -n 's/.*name="_token"[^>]*value="\([^"]*\)".*/\1/p' | head -1
}

# Log in as $1/$2 over the CSRF-protected web form; keeps cookies in $JAR and a
# fresh session CSRF token in $TOKEN (the token rotates when the session is
# regenerated at login, so we re-scrape one from an authenticated page).
login() {
  TOKEN="$(csrf_from /login)"
  curl -s -c "$JAR" -b "$JAR" -X POST "$TARGET/login" \
    -d "_token=$TOKEN" --data-urlencode "email=$1" --data-urlencode "password=$2" \
    -o /dev/null
  TOKEN="$(csrf_from /dashboard)"
}

# Authenticated form POST that carries the CSRF token. Args: path then curl args.
post() {
  local path="$1"; shift
  curl -s -c "$JAR" -b "$JAR" -X POST "$TARGET$path" -d "_token=$TOKEN" "$@"
}

jget()      { python3 -c 'import sys,json;print(json.load(sys.stdin).get(sys.argv[1],""))' "$1"; }
post_id()   { curl -s -H "$VT" "$TARGET/api/_verify/post?slug=$1"  | jget id; }
user_id()   { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | jget id; }
user_admin(){ curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | jget isAdmin; }
user_email(){ curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | jget email; }
