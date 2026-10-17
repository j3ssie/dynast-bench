#!/usr/bin/env bash
# TENANT-SRC-001 (CWE-639): the workspace middleware authorizes the org in the
# path; the listing queries the org in ?org_id=. An Acme member asks for their
# own workspace's posts with Globex's id in the query string.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
login user1@bench.local 'User123!'
GLOBEX=$(org_field globex id)
curl -s -b "$JAR" "$TARGET/api/orgs/acme/posts?status=draft&org_id=$GLOBEX" \
  | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
