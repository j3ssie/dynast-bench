#!/usr/bin/env bash
# APACHE-HEADER-TRUST (CWE-807): Apache forwards the client X-Internal-Auth header.
set -eu
. "$(dirname "$0")/_lib.sh"
leak "$APACHE" '/' 'X-Internal-Auth: trusted'
