#!/usr/bin/env bash
# TRAEFIK-HEADER-TRUST (CWE-807): Traefik forwards the client X-Internal-Auth header.
set -eu
. "$(dirname "$0")/_lib.sh"
leak "$TRAEFIK" '/' 'X-Internal-Auth: trusted'
