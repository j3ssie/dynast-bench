#!/usr/bin/env bash
# TRAEFIK-INTERNAL-DOUBLESLASH (CWE-436): //internal misses PathPrefix(/internal).
set -eu
. "$(dirname "$0")/_lib.sh"
leak "$TRAEFIK" '//internal'
