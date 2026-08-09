#!/usr/bin/env bash
# TRAEFIK-ADMIN-ENCDOT (CWE-436): Traefik does not decode %2e, so /%2e/admin bypasses; origin resolves it.
set -eu
. "$(dirname "$0")/_lib.sh"
leak "$TRAEFIK" '/%2e/admin'
