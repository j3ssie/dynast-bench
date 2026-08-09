#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
id=$(task_id globex-internal)
curl -s "$TARGET/tasks?id=$id" | grep -q "<script>window.BENCH_STORED_XSS=1</script>"
