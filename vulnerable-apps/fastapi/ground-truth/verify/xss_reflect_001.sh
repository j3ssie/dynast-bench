#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/_lib.sh"
curl -s "$TARGET/search?q=%3Cscript%3EFASTAPI_REFLECT_42%3C/script%3E" | grep -q '<script>FASTAPI_REFLECT_42</script>'
