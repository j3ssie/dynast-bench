#!/usr/bin/env bash
# REDIRECT-001 (CWE-601): /goto redirects to an arbitrary external URL.
set -e; . "$(dirname "$0")/_lib.sh"
loc=$(curl -s -o /dev/null -w '%{redirect_url}' "$TARGET/goto?next=https://evil.example/")
[ "$loc" = "https://evil.example/" ]
