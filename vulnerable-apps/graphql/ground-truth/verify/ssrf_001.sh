#!/usr/bin/env bash
source "$(dirname "$0")/_lib.sh"
gql '{ linkPreview(url:"http://billing-svc:9099/internal/secret") { body title } }' | grep -q 'BILLING-INTERNAL-SECRET-8d12'
