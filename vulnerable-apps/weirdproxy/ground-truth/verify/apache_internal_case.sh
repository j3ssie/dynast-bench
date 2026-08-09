#!/usr/bin/env bash
# APACHE-INTERNAL-CASE (CWE-436): case-sensitive <Location /internal>, so /INTERNAL bypasses.
set -eu
. "$(dirname "$0")/_lib.sh"
leak "$APACHE" '/INTERNAL'
