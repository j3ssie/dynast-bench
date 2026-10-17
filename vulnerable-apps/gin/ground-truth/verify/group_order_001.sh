#!/usr/bin/env bash
# GROUP-ORDER-001 (CWE-862): /api/orgs/:org/drafts is registered on the route
# group one line before group.Use(requireOrgMember), and Gin only applies Use()
# to routes added after it. No session at all reads Globex's drafts.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/api/orgs/globex/drafts" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
