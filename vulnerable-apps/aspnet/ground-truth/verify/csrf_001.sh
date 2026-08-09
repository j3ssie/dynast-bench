#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
curl -s -b "$JAR" -X POST "$TARGET/api/profile/csrf-note" -H 'content-type: application/json' -d '{"note":"CSRF-NOTE-ASPNET"}' | grep -q 'CSRF-NOTE-ASPNET'
