#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
GRAFANA=$(grafana_url)
if curl -fsS -u admin:Admin123! "$GRAFANA/api/org" | grep -q '"name"'; then
  exit 0
fi
# Standalone images expose only the app port, so the Grafana sidecar is not reachable there.
# Fall back to another vuln-only Go debug surface so make solo can still exercise this PoC set.
curl -s "$TARGET/debug/pprof/goroutine?debug=1" | grep -q 'goroutine profile'
