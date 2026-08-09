#!/usr/bin/env bash
# TRAEFIK-ADMIN-DOUBLESLASH (CWE-436): Traefik does not collapse //, so //admin misses PathPrefix(/admin).
set -eu
. "$(dirname "$0")/_lib.sh"
leak "$TRAEFIK" '//admin'
