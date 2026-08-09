# NestJS Version - Vulnerable App Plan

> ⚠️ **Intentionally vulnerable. Local only.** Binds `127.0.0.1`, ships a LOUD
> banner, carries no real data. Built to benchmark DAST/SAST/LLM security tools.

**Angle:** the **proxy + DI-framework footgun** app. The app sits behind nginx,
so signature bugs are the ones that live at the framework and proxy seams:
**missing `ValidationPipe({whitelist})` → overposting/mass assignment**,
**Handlebars triple-stache (`{{{ }}}`) SSTI/XSS**, an **nginx `alias` path-
traversal** misconfig, and **`X-Forwarded-For` trusted for authorization**.
Redis-backed sessions make fixation and session bugs real.

## Services (4 containers) - independent `docker-compose.yml`

| Service  | Image             | Host port | Purpose                          |
|----------|-------------------|-----------|----------------------------------|
| nginx    | nginx:1.27.1      | 3000      | Entry point, proxies to app      |
| app      | build ./app       | (internal)| NestJS SSR (Handlebars) + API    |
| postgres | postgres:16.4     | 5432      | Data                             |
| redis    | redis:7.4.0       | 6379      | Session store                    |

## Stack choices (bugs live inside these idioms)

- **NestJS 10** + **hbs (Handlebars)** views; plain HTML forms + a JSON API
- DB: **Prisma**; typed mostly, `$queryRawUnsafe` on search/report (SQLi)
- Auth: **passport-local** + `express-session` + **connect-redis**; bcrypt;
  a JWT guard (`@nestjs/jwt`) with a hardcoded secret for API tokens
- Validation: DTOs exist but the global `ValidationPipe` is registered
  **without** `{ whitelist: true, forbidNonWhitelisted: true }` - extra body
  properties flow straight into `prisma.user.update({ data: body })`
- Uploads: avatar via **multer** to a shared volume, served by **nginx**
  directly at `/uploads/` (the `alias` traversal lives in the nginx config)
- Reverse proxy: `app.set('trust proxy', true)` + a `RolesGuard`/rate-limiter
  that reads client IP from `X-Forwarded-For` (spoofable behind the proxy)
- Features: a "webhook test" (SSRF), a report import that uses `node-serialize`
  / `eval` (deserialization / code injection)

## Domain model

Standard shared domain, cross-tenant `user2` (org Globex) for IDOR PoCs.

## Vulnerability catalog (~28 planted bugs)

| Service · Feature | Planted bug | CWE | OWASP | Sev | Diff | Taint |
|---|---|---|---|---|---|---|
| app · ValidationPipe | **Overposting** - no `whitelist`, `role` set from body | 915 | A01 | H | M | cross-file |
| app · views | **Handlebars SSTI/XSS** via `{{{ body }}}` triple-stache | 1336/79 | A03 | H | M-H | cross-file |
| nginx · /uploads | **`alias` path traversal** (`location /uploads` + `alias`) | 22 | A01 | H | M-H | cross-service |
| app · RolesGuard | **`X-Forwarded-For` trusted** for authz / rate limit | 290/348 | A07 | H | M | cross-file |
| app · login | No rate limit → brute force | 307 | A07 | M | E | in-file |
| app · login | User enumeration (distinct errors) | 204 | A07 | L | E-M | in-file |
| app · session | Session not regenerated on login → **fixation** | 384 | A07 | M | M | in-file |
| app · session | Hardcoded `SESSION_SECRET` | 798 | A02 | M | E | config |
| app · JWT | Hardcoded secret; `exp` unchecked | 321/347 | A07 | H | M | in-file |
| app · reset | Predictable reset token | 640/330 | A07 | M | M | cross-file |
| app · posts/tasks | IDOR/BOLA - no org check | 639/863 | A01 | H | E-M | in-file |
| app · /admin/* | Missing `RolesGuard` on an admin route | 862 | A01 | M | M | in-file |
| app · /posts/search | SQLi via `$queryRawUnsafe` | 89 | A03 | H | E | in-file |
| app · report query | **Second-order** SQLi via stored name | 89 | A03 | H | H | cross-file |
| app · webhook test | **SSRF** → Redis / `169.254.169.254` | 918 | A10 | H | M-H | cross-service |
| app · report import | Deserialization via `node-serialize`/`eval` | 502/94 | A08 | C | M-H | in-file |
| app · comments | Stored XSS (triple-stache render) | 79 | A03 | M | E-M | cross-file |
| app · search page | Reflected XSS | 79 | A03 | M | E | in-file |
| app · forms | CSRF (session cookie, no token) | 352 | A01 | M | M | in-file |
| app · login `?next=` | Open redirect | 601 | A01 | L | E | in-file |
| app · CORS | `enableCors({origin:true, credentials:true})` reflect | 942 | A05 | M | M | in-file |
| app · attachments | Path traversal in Nest download handler | 22 | A01 | M | M | in-file |
| app · config | Hardcoded secrets in committed source | 798 | A05 | M | E | in-file |
| app · errors | Exception filter leaks stack/query | 209 | A05 | L | E | in-file |
| app · billing/seats | Negative/huge value manipulation | 840 | A04 | M | M | in-file |
| app · invites | **Race condition** exceeds seat limit | 362 | A04 | H | H | in-file |
| app · upload | SVG stored XSS + unrestricted multer type | 434/79 | A05 | M | M | in-file |
| seed data | Default `admin/admin` service creds | 798 | A07 | M | E | in-file |

## Stack-specific highlights (only make sense in Nest/nginx)

- **`ValidationPipe` without `whitelist`** - the DTO declares `email`,
  `displayName`; the request also sends `role: "admin"`. Because whitelist is
  off, the extra prop survives into `prisma.user.update({ data: dto })`. This is
  *the* NestJS overposting foot-gun. Safe twin turns whitelist +
  `forbidNonWhitelisted` on.
- **Handlebars `{{{ }}}`** - comment/report bodies rendered with triple-stache
  bypass HTML escaping (stored XSS); building a template from a user string is
  SSTI. Near-miss uses `{{ }}` double-stache.
- **nginx `alias` traversal** - `location /uploads { alias /var/www/uploads/; }`
  (note trailing-slash mismatch) lets `/uploads../etc/passwd` escape the
  directory. Config-level bug, cross-service taint. Safe twin uses `root` +
  a normalized location.
- **`X-Forwarded-For` trust** - `trust proxy` + a guard that reads
  `req.ip`/XFF to allow internal admin or bypass rate limits; a spoofed
  `X-Forwarded-For: 127.0.0.1` unlocks it. Safe twin trusts only the known proxy
  hop and never uses client IP for authz.
- **`node-serialize` / `eval`** - the report-state import path; classic Node
  deserialization RCE (`_$$ND_FUNC$$_`). Safe twin uses `JSON.parse`.

## Near-misses (safe beside vulnerable)

- `updateMe` (no-whitelist DTO) beside `updateProfile` (whitelisted DTO).
- `{{{ comment.body }}}` beside `{{ post.title }}`.
- nginx `alias` block beside a correct `root` block for `/static/`.
- `importReport` (`node-serialize`) beside `importJson` (`JSON.parse`).

## Logic-only bugs

- **Invite race (CWE-362):** seat check + insert not atomic; parallel PoC beats
  the limit.
- **Billing (CWE-840):** negative/huge `seats` accepted.

## nginx config essentials (the planted misconfig)

```
# VULN: trailing-slash mismatch on alias → path traversal
location /uploads {
  alias /var/www/uploads/;      # request /uploads../secret escapes the dir
}
location / {
  proxy_pass http://app:3000;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;  # app trusts this for authz
  proxy_set_header Host $host;
}
client_max_body_size 10m;
```

## Ground truth & scoring

- `VULNERABILITIES.yaml` per row; `verify/` PoCs (`overpost.sh` posts a `role`
  field and re-reads it via `_verify`; `alias_traversal.sh` requests
  `/uploads../`; `xff_bypass.sh` spoofs the header; `node_deser.sh`;
  `race_invite.sh`). PASS on `main-vuln`, FAIL on `main-safe`.
- Scorer → P/R/F1 + per-CWE. `ground-truth/` `.dockerignore`d.

## Patched twin (`main-safe`)

`ValidationPipe({whitelist, forbidNonWhitelisted})`, double-stache rendering,
nginx `root` + normalized location, XFF ignored for authz, rate limit,
constant-time login, session regeneration on login, env secrets, verified JWT,
random reset tokens, org checks, `RolesGuard` on all admin routes,
`$queryRaw` tagged templates, SSRF allowlist + metadata block, `JSON.parse`
import, redirect allowlist, locked CORS, containment-checked downloads, generic
errors, validated billing, atomic seat reservation, CSRF tokens, MIME/size
upload checks.

## Compose sketch (independent; 127.0.0.1 only)

```yaml
name: vuln-nestjs
services:
  nginx:
    image: nginx:1.27.1
    ports: ["127.0.0.1:${DYNAST_PORT:-13311}:80"]
    volumes:
      - ./infra/nginx.conf:/etc/nginx/conf.d/default.conf:ro   # planted alias traversal
      - uploads:/var/www/uploads:ro
    depends_on: [app]
  app:
    build: ./app
    environment:
      DATABASE_URL: postgresql://bench:bench@postgres:5432/bench
      REDIS_URL: redis://redis:6379
      SESSION_SECRET: benchsecret        # planted CWE-798
      JWT_SECRET: hardcoded-weak-secret   # planted CWE-798
    volumes: [uploads:/app/uploads]
    depends_on:
      postgres: { condition: service_healthy }
      redis:    { condition: service_healthy }
  postgres:
    image: postgres:16.4
    healthcheck: { test: ["CMD-SHELL", "pg_isready -U bench"] }
  redis:
    image: redis:7.4.0
    healthcheck: { test: ["CMD", "redis-cli", "ping"] }
volumes: { uploads: {} }
```

## Build milestones

1. Compose (nginx entrypoint w/ planted config) + healthchecks + Makefile;
   Prisma schema + seed (cross-tenant + weak service cred).
2. Auth module (passport + Redis sessions) with fixation / XFF-trust / rate-
   limit bugs and safe twins; JWT guard.
3. Posts CRUD + IDOR + `$queryRawUnsafe` SQLi (+ near-miss); Handlebars
   triple-stache XSS/SSTI.
4. Webhook SSRF; report second-order SQLi + `node-serialize` import; overposting
   DTO - each with a safe twin.
5. Billing/invite logic bugs; redirect/CORS/upload misconfigs; nginx alias
   traversal.
6. `VULNERABILITIES.yaml` + `verify/` PoCs; all PASS on `main-vuln`; branch
   `main-safe`, fix all, all PoCs FAIL; wire scorer.
