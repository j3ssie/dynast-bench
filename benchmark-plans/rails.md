# Ruby on Rails Version - Vulnerable App Plan

> ⚠️ **Intentionally vulnerable. Local only.** Binds `127.0.0.1`, ships a LOUD
> banner, carries no real data. Built to benchmark DAST/SAST/LLM security tools.

**Angle:** the **Rails-idiom** app. Signature bugs are the ones that made Rails
CVEs famous: **mass assignment** (`permit!` / bypassed strong params),
**YAML/Marshal deserialization RCE**, **`render inline:` ERB SSTI**, the
**`^$` multiline-regex anchor bypass**, string-interpolated `where` SQLi, and a
**Pundit `authorize` skip**. ActiveStorage → MinIO makes upload + signed-id bugs
real; nginx is the entrypoint.

## Services (4 containers) - independent `docker-compose.yml`

| Service  | Image                              | Host port  | Purpose                     |
|----------|------------------------------------|------------|-----------------------------|
| nginx    | nginx:1.27.1                       | 3000       | Entry point → Puma          |
| app      | build ./app (ruby:3.3-slim)        | (internal) | Rails 7.2 + ERB             |
| postgres | postgres:16.4                      | 5432       | Data                        |
| minio    | minio/minio:RELEASE.2024-08-17...  | 9000, 9001 | ActiveStorage backend       |

## Stack choices (bugs live inside these idioms)

- **Rails 7.2**, ERB views, importmap; **Devise** auth (`:recoverable` on so the
  reset-token bug is reachable), **Pundit** policies (one route skips
  `authorize`)
- Data: ActiveRecord; most queries safe, but search/report use
  `where("name = '#{params[:q]}'")` string interpolation (SQLi)
- Validation: a `format:` validator uses `/^admin@/` (`^$` anchors) instead of
  `\A…\z` - the multiline bypass
- Serialization: a "restore/import" feature calls `YAML.load` / `Marshal.load`
  on user data (RCE); a "preview" feature `render inline: params[:tpl]` (ERB
  SSTI)
- Uploads: **ActiveStorage** → MinIO; a signed-id / direct-upload handling bug
- Features: an "import from URL" using `open-uri`/`Net::HTTP` (SSRF); a report
  export shelling out with backticks (command injection)

## Domain model

Standard shared domain, cross-tenant `user2` (org Globex) for IDOR PoCs.

## Vulnerability catalog (~29 planted bugs)

| Service · Feature | Planted bug | CWE | OWASP | Sev | Diff | Taint |
|---|---|---|---|---|---|---|
| app · users update | **Mass assignment** - `params.permit!` sets `role`/`admin` | 915 | A01 | H | M | in-file |
| app · import | **YAML/Marshal deserialization** RCE | 502 | A08 | C | H | in-file |
| app · preview | **ERB SSTI** via `render inline: params[:tpl]` | 1336/94 | A03 | C | H | cross-file |
| app · validation | **`^$` regex anchor bypass** (multiline) | 20/625 | A07 | M | M-H | in-file |
| app · policies | **Pundit `authorize` skipped** on a route | 862/285 | A01 | H | M | in-file |
| app · /posts/search | SQLi via `where("… #{params}")` interpolation | 89 | A03 | H | E | in-file |
| app · report query | **Second-order** SQLi via stored name | 89 | A03 | H | H | cross-file |
| app · import URL | **SSRF** via `open-uri`/`Net::HTTP` → metadata | 918 | A10 | H | M-H | cross-service |
| app · export | Command injection via backticks/`system` | 78 | A03 | C | M | in-file |
| app · reflection | `constantize`/`send` on user string | 470 | A08 | H | M-H | in-file |
| app · login | No rate limit → brute force | 307 | A07 | M | E | in-file |
| app · login | User enumeration (Devise distinct messages) | 204 | A07 | L | E-M | in-file |
| app · secret_key_base | Hardcoded → **session cookie forgery** | 798/321 | A02 | H | M | config |
| app · reset | Predictable/leaky reset token handling | 640 | A07 | M | M | cross-file |
| app · posts/tasks | IDOR/BOLA - no org scoping | 639/863 | A01 | H | E-M | in-file |
| app · comments | Stored XSS via `raw`/`html_safe` | 79 | A03 | M | E-M | cross-file |
| app · search page | Reflected XSS (unescaped `<%= raw %>`) | 79 | A03 | M | E | in-file |
| app · redirect | Open redirect `redirect_to params[:url]` | 601 | A01 | L | E | in-file |
| app · CORS | rack-cors reflects origin + credentials | 942 | A05 | M | M | in-file |
| app · attachments | Path traversal on `send_file` | 22 | A01 | M | M | in-file |
| app · ActiveStorage | Predictable/forgeable signed blob id | 639 | A01 | M | M-H | cross-service |
| app · CSRF | `skip_before_action :verify_authenticity_token` | 352 | A01 | M | M | in-file |
| app · config | Secrets committed (`config/secrets.yml`) | 798 | A05 | M | E | config |
| app · errors | `config.consider_all_requests_local = true` | 209 | A05 | L | E | config |
| app · billing/seats | Negative/huge value manipulation | 840 | A04 | M | M | in-file |
| app · invites | **Race condition** exceeds seat limit | 362 | A04 | H | H | in-file |
| app · upload | SVG stored XSS + unrestricted content type | 434/79 | A05 | M | M | in-file |
| app · deps | Outdated gem with a known CVE (locked) | 1035 | A06 | M | E | config |
| seed data | Default `admin/admin` service creds | 798 | A07 | M | E | config |

## Stack-specific highlights (only make sense in Rails/Ruby)

- **Mass assignment via `permit!`** - `params.require(:user).permit!` (or a
  blanket `permit(*params[:user].keys)`) lets `role`/`admin` flow into
  `update`. The archetypal Rails bug. Near-miss uses an explicit attribute list.
- **`YAML.load` / `Marshal.load`** - the import/restore path; both instantiate
  arbitrary Ruby objects (RCE). Safe twin uses `YAML.safe_load` /
  `JSON.parse`.
- **`render inline: params[:tpl]`** - ERB is evaluated server-side; `<%= 7*7 %>`
  → `49`, escalating to `system(...)`. Safe twin renders a fixed template with
  locals.
- **`^` / `$` regex anchors** - Ruby `^$` match line boundaries, not string
  boundaries, so `"evil@x.com\nadmin@bench.local"` passes a `/^admin@bench/`
  check. Uniquely Ruby. Safe twin uses `\A…\z`.
- **`constantize` / `send`** on a user-controlled string - unsafe reflection /
  gadget. Safe twin maps to an allowlist.
- **Hardcoded `secret_key_base`** - signed/encrypted cookies become forgeable;
  a known key means session forgery.

## Near-misses (safe beside vulnerable)

- `UsersController#update` (`permit!`) beside `ProfilesController#update`
  (`permit(:display_name, :bio)`).
- `import` (`YAML.load`) beside `import_json` (`JSON.parse`).
- `render inline:` beside `render :preview` (fixed template + locals).
- `/\A admin@ \z/x` safe validator beside the `/^admin@/` vulnerable one.

## Logic-only bugs

- **Invite race (CWE-362):** seat check + create not wrapped in a locking
  transaction; parallel PoC beats the limit.
- **Billing (CWE-840):** negative/huge `seats` accepted.

## Ground truth & scoring

- `VULNERABILITIES.yaml` per row; `verify/` PoCs (`mass_assign.sh` posts `role`;
  `yaml_deser.sh` uploads a crafted YAML; `erb_ssti.sh` posts `<%= 7*7 %>`;
  `regex_bypass.sh` sends a newline payload; `race_invite.sh`). PASS on
  `main-vuln`, FAIL on `main-safe`.
- Scorer → P/R/F1 + per-CWE. `ground-truth/` `.dockerignore`d.

## Patched twin (`main-safe`)

Explicit strong-param lists, `YAML.safe_load`/`JSON.parse`, fixed-template
render, `\A…\z` anchors, `authorize` on every action, bound query params, SSRF
allowlist + metadata block, arg-array shell-outs, reflection allowlist, rate
limit, generic auth errors, env `secret_key_base`, org scoping, escaped output,
redirect allowlist, scoped CORS, containment-checked `send_file`, per-user
signed-id verification, CSRF on, env secrets, `consider_all_requests_local =
false`, validated billing, locked seat reservation, MIME/size upload checks,
patched gem.

## Compose sketch (independent; 127.0.0.1 only)

```yaml
name: vuln-rails
services:
  nginx:
    image: nginx:1.27.1
    ports: ["127.0.0.1:${DYNAST_PORT:-13311}:80"]
    volumes: ["./infra/nginx.conf:/etc/nginx/conf.d/default.conf:ro"]
    depends_on: [app]
  app:
    build: ./app
    environment:
      DATABASE_URL: postgres://bench:bench@postgres:5432/bench
      RAILS_ENV: production
      SECRET_KEY_BASE: benchsecretbenchsecret   # planted CWE-798 (forgeable cookies)
      RAILS_LOG_LEVEL: debug
      S3_ENDPOINT: http://minio:9000
      S3_PUBLIC_ENDPOINT: http://localhost:9000
    depends_on:
      postgres: { condition: service_healthy }
      minio:    { condition: service_healthy }
  postgres:
    image: postgres:16.4
    healthcheck: { test: ["CMD-SHELL", "pg_isready -U bench"] }
  minio:
    image: minio/minio:RELEASE.2024-08-17T01-24-54Z
    command: server /data --console-address ":9001"
    ports: ["127.0.0.1:${DYNAST_PORT_MINIO_9000:-13312}:9000", "127.0.0.1:${DYNAST_PORT_MINIO_9001:-13313}:9001"]
```

## Build milestones

1. Compose + healthchecks + Makefile; `db:prepare` seeding (cross-tenant + weak
   service cred) green.
2. Devise + Pundit; plant the `permit!` mass-assignment, the skipped
   `authorize`, the `^$` validator, and their safe twins.
3. Posts CRUD + IDOR + interpolated-`where` SQLi (+ near-miss); `raw`/`html_safe`
   XSS.
4. Import (`YAML.load`), preview (`render inline:`), report second-order SQLi,
   `open-uri` SSRF, backtick export - each with a safe twin.
5. Billing/invite logic bugs; redirect/CORS/CSRF/traversal/error misconfigs;
   ActiveStorage signed-id bug.
6. `VULNERABILITIES.yaml` + `verify/` PoCs; all PASS on `main-vuln`; branch
   `main-safe`, fix all, all PoCs FAIL; wire scorer.
