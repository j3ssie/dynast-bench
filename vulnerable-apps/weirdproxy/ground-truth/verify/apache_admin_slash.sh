#!/usr/bin/env bash
# APACHE-ADMIN-SLASH (CWE-436): anchored <LocationMatch ^/admin$> misses /admin/.
set -eu
. "$(dirname "$0")/_lib.sh"
leak "$APACHE" '/admin/'
