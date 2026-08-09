#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
marker="csrf-rails-$(date +%s)"
code=$(curl -s -o /tmp/rails-csrf-out.$$ -w '%{http_code}' -b "$JAR" -X POST "$TARGET/api/csrf/profile" --data-urlencode "display_name=$marker")
trap 'rm -f /tmp/rails-csrf-out.$$' EXIT
[ "$code" = "200" ]
user_display user1@bench.local | grep -q "$marker"
