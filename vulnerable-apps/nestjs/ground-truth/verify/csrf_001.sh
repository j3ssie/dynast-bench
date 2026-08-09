#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
body=$(curl -s -b "$JAR" -X POST "$TARGET/api/settings/email" -H 'content-type: application/json' -d '{"email":"attacker@evil.example"}')
grep -q '"ok":true' <<<"$body"
