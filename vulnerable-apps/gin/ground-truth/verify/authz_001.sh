#!/usr/bin/env bash
# AUTHZ-001: broken function-level authz. A non-admin user reaches the admin user
# listing because the handler never checks the admin role.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
login user2@bench.local 'User123!'
curl -s -b "$JAR" "$TARGET/api/admin/users" | grep -q 'admin@bench.local'
