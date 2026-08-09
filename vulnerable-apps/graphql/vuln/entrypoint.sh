#!/bin/sh
set -e
export PORT="${PORT:-3000}"
export DATABASE_URL="${DATABASE_URL:-postgresql://bench:bench@postgres:5432/bench}"
export BILLING_URL="${BILLING_URL:-http://billing-svc:9099}"
exec node /app/dist/main.js
