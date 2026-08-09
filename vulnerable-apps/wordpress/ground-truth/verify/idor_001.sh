#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
login_user1
id=$(task_id globex-internal)
curl -s -b "$JAR" "$TARGET/wp-json/bench-tasks/v1/private-task?id=$id" | contains_marker
