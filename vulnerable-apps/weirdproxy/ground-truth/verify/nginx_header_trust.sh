#!/usr/bin/env bash
# NGINX-HEADER-TRUST (CWE-807): nginx forwards the client X-Internal-Auth header the backend trusts.
set -eu
. "$(dirname "$0")/_lib.sh"
leak "$NGINX" '/' 'X-Internal-Auth: trusted'
