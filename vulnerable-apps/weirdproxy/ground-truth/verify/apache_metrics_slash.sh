#!/usr/bin/env bash
# APACHE-METRICS-SLASH (CWE-436): anchored ^/metrics$ misses /metrics/.
set -eu
. "$(dirname "$0")/_lib.sh"
leak "$APACHE" '/metrics/'
