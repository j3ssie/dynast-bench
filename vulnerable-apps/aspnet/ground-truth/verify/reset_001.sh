#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
curl -s -X POST "$TARGET/api/auth/reset/request" -H 'content-type: application/json' -d '{"email":"user1@bench.local"}' | grep -q 'reset-user1'
