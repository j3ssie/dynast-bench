#!/usr/bin/env bash
# MEMBERSHIP-STATE-001 (CWE-863): an Acme user asks to join Globex, nobody
# approves it, and the pending request is still enough to switch the session
# into Globex - where the ordinary, correctly org-scoped draft list hands over
# Globex's confidential draft.
set -u; . "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!

post_status "$JAR" /api/orgs/globex/join-requests >/dev/null                # 1. pending request
post_status "$JAR" /api/session/org '{"slug":"globex"}' >/dev/null          # 2. switch on it
OUT=$(curl -s -b "$JAR" "$TARGET/api/posts?status=draft")                    # 3. read as a member

post_status "$JAR" /api/session/org '{"slug":"acme"}' >/dev/null
curl -s -b "$JAR" -X DELETE "$TARGET/api/orgs/globex/join-requests" >/dev/null
echo "$OUT" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
