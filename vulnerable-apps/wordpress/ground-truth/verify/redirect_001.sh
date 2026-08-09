#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s -I "$TARGET/go?to=https://evil.example/path" | tr -d "\r" | grep -qi "^Location: https://evil.example/path"
