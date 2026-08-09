#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -s -c "$JAR" "$TARGET/reflect.jsp?q=x" >/dev/null
before=$(awk '$6=="JSESSIONID"{print $7}' "$JAR" | tail -1)
curl -s -b "$JAR" -c "$JAR" -X POST "$TARGET/login" --data-urlencode 'email=user2@bench.local' --data-urlencode 'password=User123!' >/dev/null
after=$(awk '$6=="JSESSIONID"{print $7}' "$JAR" | tail -1)
[ -n "$before" ] && [ "$before" = "$after" ]
