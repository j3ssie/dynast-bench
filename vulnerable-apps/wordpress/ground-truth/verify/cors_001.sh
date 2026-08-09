#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s -I -H "Origin: https://evil.example" "$TARGET/wp-json/bench-tasks/v1/cors" | tr -d "\r" | grep -q "Access-Control-Allow-Origin: https://evil.example"
