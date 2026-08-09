#!/usr/bin/env bash
# NGINX-METRICS-SLASH (CWE-436): same exact-match pitfall on /metrics -> /metrics/.
set -eu
. "$(dirname "$0")/_lib.sh"
leak "$NGINX" '/metrics/'
