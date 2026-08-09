#!/usr/bin/env bash
# AUTHZ-001 (CWE-862): a non-admin promotes another user (no function-level authz).
set -e; . "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
U2=$(user_id user2@bench.local)
curl -s -b "$JAR" -X POST "$TARGET/api/users/$U2/promote" | grep -q '"ok":true'
