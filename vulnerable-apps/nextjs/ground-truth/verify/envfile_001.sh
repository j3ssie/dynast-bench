#!/usr/bin/env bash
# ENVFILE-001 (CWE-538/CWE-540): the production env file sits under public/, so
# it is served unauthenticated from the web root with the DB URL and the JWT
# signing key in it.
set -e; . "$(dirname "$0")/_lib.sh"

ENVBODY=$(curl -sf "$TARGET/env.production")
printf '%s' "$ENVBODY" | grep -q 'ENVFILE-LEAK-MARKER-5d2c'
printf '%s' "$ENVBODY" | grep -q '^JWT_SECRET='
printf '%s' "$ENVBODY" | grep -q '^DATABASE_URL=postgresql://'
