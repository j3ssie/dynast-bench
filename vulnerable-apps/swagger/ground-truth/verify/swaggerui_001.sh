#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -sf "$TARGET/api/docs/?url=https://evil.test/owned.json" | grep -q 'https://evil.test/owned.json'
