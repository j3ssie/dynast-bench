#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
curl -s -X POST "$TARGET/graphql" -H 'content-type: application/json' -d '{"query":"{ me { passwordHas } }"}' | grep -q 'passwordHash'
