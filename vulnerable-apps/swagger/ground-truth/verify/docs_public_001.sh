#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
curl -sf "$TARGET/api/schema/" | grep -q 'Swagger Inventory Benchmark'
curl -sf "$TARGET/api/docs/" | grep -q 'Swagger UI loading'
