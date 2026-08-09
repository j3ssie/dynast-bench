#!/usr/bin/env bash
# NGINX-INTERNAL-CASE (CWE-436): case-sensitive prefix, so /INTERNAL bypasses.
set -eu
. "$(dirname "$0")/_lib.sh"
leak "$NGINX" '/INTERNAL'
