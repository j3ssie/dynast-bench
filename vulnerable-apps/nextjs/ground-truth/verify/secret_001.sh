#!/usr/bin/env bash
# SECRET-001 (CWE-200): a NEXT_PUBLIC_ secret is rendered into the homepage HTML.
set -e; . "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/" | grep -q 'leaked-public-key-abc123'
