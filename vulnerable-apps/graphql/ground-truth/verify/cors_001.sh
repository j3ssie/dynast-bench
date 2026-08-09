#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
out=$(curl -si -X OPTIONS "$TARGET/graphql" -H 'Origin: https://evil.example' -H 'Access-Control-Request-Method: POST')
echo "$out" | grep -qi 'access-control-allow-origin: https://evil.example' && echo "$out" | grep -qi 'access-control-allow-credentials: true'
