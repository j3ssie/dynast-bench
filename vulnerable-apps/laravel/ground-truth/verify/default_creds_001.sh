#!/usr/bin/env bash
# DEFAULT-CREDS-001 (CWE-1392): a weak service account admin/admin is seeded.
set -eu
. "$(dirname "$0")/_lib.sh"
login admin admin
curl -s -b "$JAR" "$TARGET/dashboard" | grep -q 'Signed in as admin (service)'
