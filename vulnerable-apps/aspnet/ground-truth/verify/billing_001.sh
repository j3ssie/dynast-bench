#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
curl -s -X POST "$TARGET/api/billing/seats" -H 'content-type: application/json' -d '{"seats":-10}' | grep -q '"seats":-10'
curl -s -X POST "$TARGET/api/billing/seats" -H 'content-type: application/json' -d '{"seats":3}' >/dev/null || true
