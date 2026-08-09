# FastAPI Version - Vulnerable App Plan

> ⚠️ **Intentionally vulnerable. Local only.** Binds `127.0.0.1`, ships a LOUD
> banner, carries no real data. Built to benchmark DAST/SAST/LLM security tools.

**Angle:** the **injection + deserialization** app. Python + Jinja2 + SQLAlchemy
give the richest catalog of server-side template injection, unsafe
deserialization (pickle/yaml), XXE, and raw-SQL bugs, plus MinIO makes SSRF and
presigned-URL abuse real. This is the recommended *first* app to build - the
source→sink→PoC loop is the fastest here.

## Services (4 containers) - independent `docker-compose.yml`

| Service  | Image                                | Host port  | Purpose                       |
|----------|--------------------------------------|------------|-------------------------------|
| app      | build ./app (python:3.12-slim)       | 3000       | FastAPI + Jinja2 SSR + API    |
| postgres | postgres:16.4                        | 5432       | Data                          |
| minio    | minio/minio:RELEASE.2024-08-17...    | 9000, 9001 | Avatars + attachments         |
| mailpit  | axllent/mailpit:v1.20                | 8025 (1025)| Verification + reset mail     |

## Stack choices (bugs live inside these idioms)

- **FastAPI + Jinja2** server-rendered pages + a JSON API under `/api/*`
- DB: **SQLAlchemy 2.0**; some queries via the ORM, some via `text()` /
  `cursor.execute()` string-building (the planted SQLi sites)
- Auth: signed session cookie (`SessionMiddleware`) **and** a JWT bearer path
  for the API (`python-jose`) - two auth surfaces, two bug classes
- Email: stdlib `smtplib` → `mailpit:1025`; reset link `…/reset?token=…`
- Files: **boto3** → MinIO; presigned GET URLs; an "import from URL" feature
  (the SSRF sink) and a "report export" feature (the shell-out sink)
- Reports: a Jinja2-rendered report + a `pickle`/`yaml`/XML import path

## Domain model

Standard shared domain (`Org → Team → Project → Post/Task → Comment/Attachment`,
`Users` with roles, `Invitations`, `Webhooks`, `Reports`). Cross-tenant `user2`
in org Globex exists so IDOR PoCs prove cross-org reads.

## Vulnerability catalog (~30 planted bugs)

| Service · Feature | Planted bug | CWE | OWASP | Sev | Diff | Taint |
|---|---|---|---|---|---|---|
| app · login | Password hashed with unsalted MD5 | 916/327 | A02 | H | E | in-file |
| app · login | No rate limit → brute force | 307 | A07 | M | E | in-file |
| app · login | User enumeration (distinct error + timing) | 204/203 | A07 | L | E-M | in-file |
| app · JWT | Hardcoded HS256 secret, `exp` never verified | 321/347 | A07 | H | M | in-file |
| app · JWT | `alg:none` accepted (verify disabled) | 347 | A07 | H | M | in-file |
| app · reset | Predictable token `md5(email+timestamp)` | 640/330 | A07 | M | M | cross-file |
| app · posts/tasks | IDOR/BOLA - no org/membership check | 639/863 | A01 | H | E-M | in-file |
| app · /admin/* | Missing function-level authz | 862 | A01 | M | M | in-file |
| app · PATCH /users/me | Mass assignment sets `role`/`is_admin` (`**payload`) | 915 | A01 | M | M | in-file |
| app · /posts/search | SQLi via f-string `cursor.execute` | 89 | A03 | H | E | in-file |
| app · report query | **Second-order** SQLi via stored project name | 89 | A03 | H | H | cross-file |
| app · reports render | **SSTI** - `Template(user_str).render()` (Jinja2) | 1336/94 | A03 | C | H | cross-file |
| app · report export | OS command injection (`subprocess shell=True`) | 78 | A03 | C | M | in-file |
| app · import (pickle) | **Insecure deserialization** `pickle.loads` | 502 | A08 | C | H | in-file |
| app · import (yaml) | `yaml.load` without `SafeLoader` | 502 | A08 | H | M | in-file |
| app · import (xml) | **XXE** - `lxml`/`etree` external entities on | 611 | A03 | H | M | in-file |
| app · webhook/import | **SSRF** → MinIO / `169.254.169.254` metadata | 918 | A10 | H | M-H | cross-service |
| app · login `?next=` | Open redirect | 601 | A01 | L | E | in-file |
| app · CORS | Reflects `Origin` + `Allow-Credentials: true` | 942 | A05 | M | M | in-file |
| app · attachments | Path traversal on download (`../`) | 22 | A01 | M | M | in-file |
| app · config | Hardcoded secrets in committed `settings.py` | 798 | A05 | M | E | in-file |
| app · errors | `debug=True` → stack traces leak | 209/489 | A05 | L | E | in-file |
| app · billing/seats | Negative/huge value manipulation | 840 | A04 | M | M | in-file |
| app · invites | **Race condition** exceeds seat limit | 362 | A04 | H | H | in-file |
| app · comments | Stored XSS (`| safe` in Jinja2 template) | 79 | A03 | M | E-M | cross-file |
| app · search page | Reflected XSS (autoescape off block) | 79 | A03 | M | E | in-file |
| app · forms | CSRF (cookie auth, no anti-CSRF token) | 352 | A01 | M | M | in-file |
| app · avatar upload | Unrestricted upload type + SVG stored XSS | 434/79 | A05 | M | M | in-file |
| app · MinIO | Presigned URL for other tenant's object (IDOR) | 639 | A01 | M | M | cross-service |
| seed data | Default `admin/admin` service creds | 798/1392 | A07 | M | E | in-file |

That's a wall of Easy for smoke-testing, a thick Medium core, and ~6 Hard bugs
(second-order SQLi, Jinja2 SSTI, pickle deser, the invite race, the SSRF→MinIO/
metadata chain) that set a real ceiling.

## Stack-specific highlights (only make sense in Python/FastAPI/Jinja2)

- **Jinja2 SSTI** - the report feature does `Template(user_supplied).render(...)`
  instead of rendering a fixed file. `{{7*7}}` → `49` proves it; the escalation
  to RCE via `{{ cycler.__init__.__globals__.os.popen('id').read() }}` is the
  classic. Put a *safe* report render (fixed template, data passed as context)
  in the adjacent function as the near-miss.
- **`pickle.loads` / `yaml.load`** - the "restore report state" import accepts a
  serialized blob. Both are RCE. The safe twin uses `pickle` → JSON and
  `yaml.safe_load`.
- **XXE via lxml** - the XML import path builds a parser with
  `resolve_entities=True` / `load_dtd=True`. Safe twin disables both.
- **`text()` string interpolation** - SQLAlchemy makes it easy to do the right
  thing (bound params) *and* the wrong thing (f-string into `text()`); plant one
  of each side by side.
- **CORS reflection** - `@app.middleware` echoes `Origin` back with
  `Access-Control-Allow-Credentials: true`, the FastAPI-idiomatic footgun.

## Near-misses (safe code beside the vulnerable code)

- `search_posts()` (SQLi) sits ~20 lines above `list_posts()` which uses bound
  params - same file, same shape.
- `render_report(tpl)` (SSTI) beside `render_dashboard()` which renders a fixed
  template file with a context dict.
- `download_attachment()` (path traversal) beside `download_avatar()` which
  resolves against a whitelist and `os.path.realpath`-checks containment.
- `import_pickle()` beside `import_json()`.

## Logic-only bugs (no pattern to grep)

- **Invite race (CWE-362):** seat check and insert aren't atomic; N concurrent
  `POST /invites` beat the seat limit. PoC fires 20 parallel requests and counts
  seats > limit.
- **Billing (CWE-840):** `POST /billing/seats` accepts negative/huge `quantity`,
  flipping the balance or overflowing.

## Ground truth & scoring

- `ground-truth/VULNERABILITIES.yaml` - one entry per row above, with
  `file`/`symbol`/`route`/`cwe`/`owasp`/`severity`/`difficulty`/`taint`/
  `near_miss`/`poc`.
- `ground-truth/verify/*.sh` - one PoC per bug (e.g. `ssti_report.sh` posts
  `{{7*7}}` and greps `49`; `sqli_search.sh` uses `' OR '1'='1`; `race_invite.sh`
  fires parallel curls). Each exits `0` on `main-vuln`, non-zero on `main-safe`.
- `ground-truth/scorer/` - normalize scanner output → match → P/R/F1.
- **`ground-truth/` is `.dockerignore`d** - never baked into the image.

## Patched twin

`main-safe` fixes every row: bcrypt+salt, rate limit, constant-time login,
verified JWT with a strong secret, random reset tokens, org/membership checks,
`@require_role`, bound SQL params, fixed-template rendering, `subprocess` with an
arg list + no shell, JSON import, `yaml.safe_load`, XXE-hardened parser, SSRF
allowlist + metadata-IP block, strict redirect allowlist, locked-down CORS,
containment-checked downloads, env-loaded secrets, `debug=False`, validated
billing quantities, atomic seat reservation, autoescaped templates, CSRF tokens,
MIME/size-checked uploads, per-tenant presign scoping. `git diff` = ground truth.

## Compose sketch (independent; 127.0.0.1 only)

```yaml
name: vuln-fastapi
services:
  app:
    build: ./app
    ports: ["127.0.0.1:${DYNAST_PORT:-13311}:3000"]
    environment:
      DATABASE_URL: postgresql+psycopg://bench:bench@postgres:5432/bench
      SMTP_HOST: mailpit
      S3_ENDPOINT: http://minio:9000
      S3_PUBLIC_ENDPOINT: http://localhost:9000
      JWT_SECRET: "hardcoded-weak-secret"     # planted CWE-798
      APP_DEBUG: "true"                        # planted CWE-489
    depends_on:
      postgres: { condition: service_healthy }
      minio:    { condition: service_healthy }
  postgres:
    image: postgres:16.4
    environment: { POSTGRES_USER: bench, POSTGRES_PASSWORD: bench, POSTGRES_DB: bench }
    healthcheck: { test: ["CMD-SHELL", "pg_isready -U bench"] }
  minio:
    image: minio/minio:RELEASE.2024-08-17T01-24-54Z
    command: server /data --console-address ":9001"
    environment: { MINIO_ROOT_USER: bench, MINIO_ROOT_PASSWORD: bench12345 }
    ports: ["127.0.0.1:${DYNAST_PORT_MINIO_9000:-13312}:9000", "127.0.0.1:${DYNAST_PORT_MINIO_9001:-13313}:9001"]
  mailpit:
    image: axllent/mailpit:v1.20
    ports: ["127.0.0.1:${DYNAST_PORT_MAILPIT_8025:-13314}:8025", "127.0.0.1:${DYNAST_PORT_MAILPIT_1025:-13315}:1025"]
```

## Build milestones

1. Compose + healthchecks + Makefile; schema + seed (incl. cross-tenant `user2`,
   default `admin/admin` service cred).
2. Auth surface: session login + JWT API, with the planted weak-hash / no-rate-
   limit / enumeration / JWT bugs and their safe twins.
3. Posts/tasks CRUD + IDOR + search SQLi (+ near-miss); comments stored XSS.
4. Reports: SSTI render, second-order SQLi, shell-out export, pickle/yaml/XML
   import, SSRF import - each with its safe twin.
5. Billing/invites logic bugs; CORS/redirect/traversal/upload misconfigs.
6. Write `VULNERABILITIES.yaml` + every `verify/` PoC; confirm all PASS on
   `main-vuln`; branch `main-safe`, fix all, confirm all PoCs FAIL; wire scorer.
