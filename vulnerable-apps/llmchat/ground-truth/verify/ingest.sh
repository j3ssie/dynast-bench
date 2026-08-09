#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
slug="$1"; text="$2"; collection="${3:-acme-support}"
auth_json -X POST "$TARGET/api/documents" -d "{\"slug\":$(json_escape "$slug"),\"text\":$(json_escape "$text"),\"collection_id\":$(json_escape "$collection") }"
