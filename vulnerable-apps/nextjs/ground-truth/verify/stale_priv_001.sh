#!/usr/bin/env bash
# STALE-PRIV-001 (CWE-613): a session keeps the role it was minted with. The
# editor signs in, an admin demotes them to user, and the editor's existing
# session still manages member roles - something a user cannot do.
set -u; . "$(dirname "$0")/_lib.sh"
new_jar ED; new_jar AD
EID=$(user_id editor@bench.local); U1=$(user_id user1@bench.local)

login_as "$ED" editor@bench.local Editor123!                              # 1. session minted as editor
login_as "$AD" admin@bench.local Admin123!
demoted=$(post_status "$AD" "/api/org/members/$EID/role" '{"role":"user"}') # 2. admin demotes them
code=000; ROLE=""
if [ "$demoted" = 200 ]; then
  code=$(post_status "$ED" "/api/org/members/$U1/role" '{"role":"editor"}') # 3. the old session acts
  ROLE=$(user_role user1@bench.local)
fi

post_status "$AD" "/api/org/members/$EID/role" '{"role":"editor"}' >/dev/null
post_status "$AD" "/api/org/members/$U1/role" '{"role":"user"}' >/dev/null
[ "$demoted" = 200 ] || { echo "admin could not demote the editor ($demoted)" >&2; exit 2; }
[ "$code" = 200 ] && [ "$ROLE" = editor ]
