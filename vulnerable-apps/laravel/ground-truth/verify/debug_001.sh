#!/usr/bin/env bash
# DEBUG-001 (CWE-489/CWE-209): APP_DEBUG=true in production. An uncaught error on
# /diagnostics renders a full stack trace (exception class + framework paths).
set -eu
. "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/diagnostics" | grep -qE 'DivisionByZeroError|vendor/laravel/framework'
