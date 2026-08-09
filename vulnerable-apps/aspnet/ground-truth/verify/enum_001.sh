#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
curl -s -X POST "$TARGET/api/auth/login" -H 'content-type: application/json' -d '{"email":"nobody@bench.local","password":"x"}' | grep -q 'No such user'
