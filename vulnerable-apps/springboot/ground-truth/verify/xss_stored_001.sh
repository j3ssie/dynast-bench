#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
pid=$(post_id acme-welcome)
curl -fsS -X POST "$TARGET/api/posts/$pid/comments" -H "$json_ct" -d '{"body":"<img src=x onerror=alert(7)>"}' >/dev/null
curl -fsS "$TARGET/posts/$pid/view" | grep -q '<img src=x onerror=alert(7)>'
