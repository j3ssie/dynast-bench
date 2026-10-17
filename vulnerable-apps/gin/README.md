# Gin vulnerable benchmark app

⚠️ **INTENTIONALLY VULNERABLE. LOCAL ONLY. DO NOT DEPLOY.**

This is the Go + [Gin](https://gin-gonic.com/) member of `DynAST-Bench`. The
vulnerabilities are the product: the `vuln/` variant intentionally contains
insecure patterns, while `safe/` is the patched twin with minimal fixes for the
same routes. It is distinct from the `golang` app (which uses chi) - this one is a
focused, media-processing-flavoured target built around six headline classes plus
a handful of Gin-idiomatic supporting bugs.

The app binds published ports to `127.0.0.1` only and keeps `ground-truth/`
outside the Docker build contexts.

## Run

```bash
make up APP=gin
make verify APP=gin
make safe APP=gin
make verify-safe APP=gin
make solo APP=gin          # one self-contained image (embedded Postgres + chromium + ImageMagick)
```

The stack publishes 13311 (app) and 13312 (Postgres). `dynast-bench start gin`
relocates either if busy; the `make` targets do not, so use them only when those
ports are free.

The images install **chromium** (server-side headless PDF rendering) and
**imagemagick** (`convert`), so the first build is larger/slower than the other
apps. Chrome runs with `--no-sandbox` inside the container.

## Planted bugs

The six headline classes, six supporting bugs and a five-bug business-logic pack
(17 total), each with a safe twin and, where natural, a safe near-miss sibling
present in both variants:

| id | class | route |
|----|-------|-------|
| INFO-001 | Information disclosure (env/secret dump) | `GET /api/debug/info` |
| IDOR-001 | Multi-step IDOR (grant workflow) | `POST /api/posts/{id}/grant` -> `GET /api/grants/{token}` |
| SQLI-001 | Second-order SQL injection | `GET /api/reports/timeline` |
| RCE-001 | ImageMagick shell-out command injection | `POST /api/images/thumbnail` |
| SSRF-001 | SSRF via headless-chrome PDF rendering | `POST /api/render/pdf` |
| DOS-001 | Denial of service (gzip decompression bomb) | `POST /api/import/preview` |
| MASSASSIGN-001 | Mass assignment (`ShouldBindJSON`) | `PATCH /api/users/me` |
| AUTHZ-001 | Broken function-level authz | `GET /api/admin/users` |
| REDIRECT-001 | Open redirect | `GET /goto?next=` |
| XSS-REFLECT-001 | Reflected XSS | `GET /search?q=` |
| DEFAULT-CREDS-001 | Weak default service credential | `POST /api/auth/login` |
| XSS-DOMPURIFY-001 | DOMPurify output re-parsed into a script context | `GET /notes/preview` |
| GROUP-ORDER-001 | Route registered before `group.Use(auth)` | `GET /api/orgs/{org}/drafts` |
| TENANT-SRC-001 | Authz checks the path org, query uses `?org_id=` | `GET /api/orgs/{org}/posts` |
| SHARE-ESCALATE-001 | View share link redeemed as edit | `POST /api/share/{token}/redeem` -> `PUT /api/shared/posts/{id}` |
| CART-COUPON-001 | Coupon kept after a plan change | `PUT /api/billing/cart/plan` -> `POST /api/billing/checkout` |
| EXPORT-STATE-001 | Ownership checked only while an export is running | `GET /api/exports/{id}/download` |

### The business-logic pack

Five bugs where no single request looks wrong, tagged in the answer key with
`logic:` (`authz-missing | authz-wrong | state | invariant | binding`), `actors:`
(sessions the exploit needs) and `steps:`, so `dynast-bench score` breaks recall
out by logic class and by sessions needed.

| id | logic | actors | steps | the chain |
|----|-------|-------:|------:|-----------|
| GROUP-ORDER-001 | authz-missing | 1 | 1 | no session at all: `GET /api/orgs/globex/drafts` |
| TENANT-SRC-001 | authz-wrong | 1 | 1 | Acme member: `GET /api/orgs/acme/posts?status=draft&org_id=<globex>` |
| SHARE-ESCALATE-001 | binding | 2 | 3 | editor shares a post read-only -> user2 redeems with `{"permission":"edit"}` -> edits it |
| CART-COUPON-001 | invariant | 1 | 4 | starter cart -> `WELCOME100` -> switch to enterprise -> checkout charges 0 |
| EXPORT-STATE-001 | state | 1 | 3 | start your own export -> learn the id counter -> download Globex's finished one |

The near-misses sit next to each, at their own routes: the public
`GET /api/orgs/{org}/profile` is registered above `Use()` on purpose, the member
list takes the org from the path only, the share preview reports the stored
permission, `PUT /api/billing/cart/seats` re-prices through the coupon check, and
polling an export checks its owner in every state. Globex has a finished export
seeded so the last bug is reachable with one account.

## Contents

- `vuln/` - Go/Gin app with PostgreSQL (pgx), an internal SSRF beacon, headless
  chromium and ImageMagick, and the planted bugs.
- `safe/` - patched twin; only the vulnerability-fix lines differ from `vuln/`.
- `ground-truth/` - machine-readable vulnerability catalog plus executable PoCs. A
  PoC exits `0` when the target is vulnerable and non-zero when fixed.

Seed users match the benchmark convention: `admin@bench.local/Admin123!`,
`editor@bench.local/Editor123!`, `user1@bench.local/User123!`,
`user2@bench.local/User123!` (Globex), plus the vulnerable default service
credential `admin/admin` in `vuln/` only. The Globex draft `globex-internal`
carries `GLOBEX-CONFIDENTIAL-MARKER-7f3a`, reachable only via the multi-step IDOR,
the second-order SQLi, or GROUP-ORDER / TENANT-SRC / EXPORT-STATE.

## Scoring - how an agent submits findings

Point your scanner/agent at the target, collect findings, then grade them against
this app's answer key:

```bash
make up APP=gin                                   # or: dynast-bench start gin
dynast-bench target gin                           # prints the URL to scan (default http://127.0.0.1:13311)
# ...run your tool, write findings.json...
make score APP=gin FINDINGS=findings.json         # or: dynast-bench score gin findings.json
# false-positive run against the patched twin:
make safe APP=gin
make score APP=gin FINDINGS=findings.json SAFE_FINDINGS=safe-findings.json
```

`score` accepts the native output of ZAP / SARIF (Semgrep, CodeQL, ...) / nuclei /
Burp / nmap (auto-detected), **or** the portable `dynast-bench.findings/v1` format
below. One object per distinct vulnerability; at least one `location.*` block is
required. Full schema + matching rules: [`dynast-bench/README.md` -> Scoring](../../dynast-bench/README.md#scoring).

```jsonc
{
  "schema": "dynast-bench.findings/v1",
  "tool": { "name": "my-agent", "version": "0.1.0", "mode": "agent" }, // dast|sast|hybrid|agent
  "run":  { "app": "gin", "variant": "vuln", "target": "http://127.0.0.1:13311" },
  "findings": [
    {
      "id": "f-001",
      "title": "Second-order SQL injection in report timeline",
      "cwe": "CWE-89",
      "severity": "high",
      "confidence": "firm",
      "location": {
        "http": { "method": "GET", "url": "http://127.0.0.1:13311/api/reports/timeline", "path": "/api/reports/timeline" },
        "file": { "path": "vuln/main.go", "symbol": "reportTimeline" }
      },
      "evidence": { "markers": ["GLOBEX-CONFIDENTIAL-MARKER-7f3a"], "note": "stored display_name reaches a raw query" },
      "exploited": true
    },
    {
      "id": "f-002",
      "title": "Command injection via ImageMagick shell-out",
      "cwe": "CWE-78",
      "severity": "critical",
      "location": {
        "http": { "method": "POST", "url": "http://127.0.0.1:13311/api/images/thumbnail", "path": "/api/images/thumbnail", "param": "size", "param_in": "body" },
        "file": { "path": "vuln/main.go", "symbol": "thumbnail" }
      },
      "evidence": { "note": "`id` output (uid=...) returned in the response" },
      "exploited": true
    }
  ]
}
```

Key rules (see the full reference for the rest): one finding per vulnerability
(not per payload); use concrete URLs (`/api/posts/7`, not `{id}`); set
`run.variant` (a twin scan that omits `"safe"` has every finding scored as a true
positive); and put a seed marker such as `GLOBEX-CONFIDENTIAL-MARKER-7f3a` or
`GIN-DEBUG-SECRET-9c2e` in `evidence.markers` as proof - it is what resolves bugs
that share a route.
