#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
curl -s -D - -o /dev/null -H 'Origin: https://evil.example' "$TARGET/api/cors/secret" | tr -d '\r' | grep -qi '^Access-Control-Allow-Origin: https://evil.example'
curl -s -D - -o /dev/null -H 'Origin: https://evil.example' "$TARGET/api/cors/secret" | tr -d '\r' | grep -qi '^Access-Control-Allow-Credentials: true'
