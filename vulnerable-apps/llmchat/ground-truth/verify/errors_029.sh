#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/api/errors/langchain" | grep -Eq 'DATABASE_URL|hardcoded-weak-secret|admin/admin'
