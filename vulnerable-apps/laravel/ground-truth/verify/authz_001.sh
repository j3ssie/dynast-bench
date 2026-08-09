#!/usr/bin/env bash
# AUTHZ-001 (CWE-862): /admin/users is only behind `auth`, not `admin`, so a
# plain user lists every account across tenants.
set -eu
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
curl -s -b "$JAR" "$TARGET/admin/users" | grep -q 'user2@bench.local'
