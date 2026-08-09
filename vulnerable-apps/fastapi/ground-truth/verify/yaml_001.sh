#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s -X POST "$TARGET/api/import/yaml" --data-binary '!!python/tuple [FASTAPI_YAML_42]' | grep -q 'FASTAPI_YAML_42'
