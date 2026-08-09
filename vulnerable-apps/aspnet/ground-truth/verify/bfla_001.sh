#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
curl -s -b "$JAR" "$TARGET/api/admin/users" | grep -q 'all-users'
