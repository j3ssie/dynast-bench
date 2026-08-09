#!/usr/bin/env bash
# NGINX-ADMIN-SLASH (CWE-436): `location = /admin` is exact-match, so /admin/ slips past.
set -eu
. "$(dirname "$0")/_lib.sh"
leak "$NGINX" '/admin/'
