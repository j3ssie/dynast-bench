#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -fsS "$TARGET/actuator/prometheus" | grep -Eq 'application_ready_time_seconds|jvm_info|executor_active_threads'
