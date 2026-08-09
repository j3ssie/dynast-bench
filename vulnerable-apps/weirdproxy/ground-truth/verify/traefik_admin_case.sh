#!/usr/bin/env bash
# TRAEFIK-ADMIN-CASE (CWE-436): PathPrefix is case-sensitive, so /ADMIN bypasses.
set -eu
. "$(dirname "$0")/_lib.sh"
leak "$TRAEFIK" '/ADMIN'
