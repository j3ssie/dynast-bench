#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -fsS "$TARGET/actuator/env" | grep -Eq 'hardcoded-weak-secret|actuator-secret-from-env-42|SPRINGBOOT_ACTUATOR_SECRET'
