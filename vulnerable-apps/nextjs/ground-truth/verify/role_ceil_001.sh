#!/usr/bin/env bash
# ROLE-CEIL-001 (CWE-269): editors may manage member roles, and the endpoint
# never caps the role they hand out - an editor makes a plain user an admin.
set -u; . "$(dirname "$0")/_lib.sh"
new_jar ED
login_as "$ED" editor@bench.local Editor123!
U1=$(user_id user1@bench.local)

code=$(post_status "$ED" "/api/org/members/$U1/role" '{"role":"admin"}')
ROLE=$(user_role user1@bench.local)

# back to the seeded role (the same editor can, on the twin where this worked)
post_status "$ED" "/api/org/members/$U1/role" '{"role":"user"}' >/dev/null
[ "$code" = 200 ] && [ "$ROLE" = admin ]
