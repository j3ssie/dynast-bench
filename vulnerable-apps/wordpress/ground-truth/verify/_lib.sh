# Shared helpers for wordpress ground-truth PoCs.
# Each PoC exits 0 if the target is VULNERABLE and non-zero if fixed.
TARGET="${TARGET:-http://127.0.0.1:13311}"
VT="X-Verify-Token: ${VERIFY_TOKEN:-benchsecret}"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT
reset_state() { curl -s -H "$VT" "$TARGET/api/_verify/reset" >/dev/null; }
login_user1() { curl -s -c "$JAR" -X POST "$TARGET/wp-login.php" -d 'log=user1@bench.local&pwd=User123!' >/dev/null; }
login_editor() { curl -s -c "$JAR" -X POST "$TARGET/wp-login.php" -d 'log=editor@bench.local&pwd=Editor123!' >/dev/null; }
login_admin() { curl -s -c "$JAR" -X POST "$TARGET/wp-login.php" -d 'log=admin@bench.local&pwd=Admin123!' >/dev/null; }
user_role() { curl -s -H "$VT" "$TARGET/api/_verify/user?email=$1" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("role",""))'; }
task_id() { curl -s -H "$VT" "$TARGET/api/_verify/task?slug=$1" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("id",""))'; }
contains_marker() { grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'; }
