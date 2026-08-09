#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -fsS --get "$TARGET/api/template" --data-urlencode 'view=<p th:text="${7*7}">x</p>' | grep -q '>49</p>'
