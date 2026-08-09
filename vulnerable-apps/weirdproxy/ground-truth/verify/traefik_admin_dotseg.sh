#!/usr/bin/env bash
# TRAEFIK-ADMIN-DOTSEG (CWE-436): Traefik does not resolve /./ , so /./admin bypasses.
set -eu
. "$(dirname "$0")/_lib.sh"
leak "$TRAEFIK" '/./admin'
