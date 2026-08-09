#!/usr/bin/env bash
set -e; . "$(dirname "$0")/_lib.sh"
login admin admin
curl -s -b "$JAR" "$TARGET/api/reports/admin-summary" | grep -q 'ADMIN-SUMMARY-ASPNET'
