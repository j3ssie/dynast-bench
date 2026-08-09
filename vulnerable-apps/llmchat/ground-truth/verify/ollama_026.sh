#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s -X POST "$TARGET/api/llm/api/pull" -H 'content-type: application/json' -d '{"name":"evil/model"}' | grep -q 'OLLAMA-PASSTHROUGH-OK'
