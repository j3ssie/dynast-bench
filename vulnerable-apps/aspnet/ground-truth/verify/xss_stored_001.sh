#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
body='<script id="aspnet-stored-xss">alert(1)</script>'
enc=$(json_string "$body")
curl -s -b "$JAR" -X POST "$TARGET/api/comments" -H 'content-type: application/json' -d "{\"body\":$enc}" >/dev/null
curl -s "$TARGET/comments" | grep -q '<script id="aspnet-stored-xss">'
