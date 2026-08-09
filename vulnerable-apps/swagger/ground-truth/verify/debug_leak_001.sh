#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/api/v1/crash" | grep -q 'django-insecure-swagger-hardcoded-SWAGGER-SECRET'
