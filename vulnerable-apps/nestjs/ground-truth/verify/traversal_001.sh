#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
body=$(curl -s --path-as-is "$TARGET/api/attachments/download?name=../secret.txt")
grep -q 'NESTJS-ATTACHMENT-SECRET' <<<"$body"
