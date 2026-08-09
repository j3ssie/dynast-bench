#!/usr/bin/env bash
# APACHE-ADMIN-CASE (CWE-436): case-sensitive LocationMatch, so /ADMIN bypasses.
set -eu
. "$(dirname "$0")/_lib.sh"
leak "$APACHE" '/ADMIN'
