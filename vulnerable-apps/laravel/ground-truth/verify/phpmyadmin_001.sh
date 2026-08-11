#!/usr/bin/env bash
# PHPMYADMIN-001 (CWE-798): phpMyAdmin is published on localhost with the
# bench/bench database credentials preconfigured. Primary check hits the
# published sidecar; the SSRF fallback covers solo mode (fake sidecar on 8081).
set -eu
. "$(dirname "$0")/_lib.sh"
PMA_HOST=$(python3 - "$TARGET" <<'PY'
import sys, urllib.parse
print((urllib.parse.urlparse(sys.argv[1]).hostname) or '127.0.0.1')
PY
)
body=$(curl -fsS --max-time 3 "http://$PMA_HOST:${DYNAST_PORT_PHPMYADMIN_80:-13312}/" 2>/dev/null || true)
if printf '%s' "$body" | grep -qi 'phpmyadmin'; then exit 0; fi
# solo fallback: reach the internal phpMyAdmin surface via the SSRF sink.
body=$({ curl -s -G --data-urlencode 'url=http://phpmyadmin/' "$TARGET/tools/fetch";
         curl -s -G --data-urlencode 'url=http://phpmyadmin:8081/' "$TARGET/tools/fetch"; } || true)
printf '%s' "$body" | grep -qi 'phpmyadmin'
