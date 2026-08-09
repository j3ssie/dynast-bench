# Modern Laravel Version - Vulnerable App Plan

> ⚠️ **Intentionally vulnerable. Local only.** Binds `127.0.0.1`, ships a LOUD
> banner, carries no real data. Built to benchmark DAST/SAST/LLM security tools.

**Angle:** the **modern-framework-monolith** counterpart to the procedural `php`
app. Everything is idiomatic **Laravel 11** (PHP 8.3, Eloquent, Blade, route-model
binding, middleware, config), so the bugs are the ones that bite *because* of the
framework, not despite it. Signature bugs: **mass assignment via `$guarded = []`**,
**Blade `{!! !!}` unescaped output**, **`Blade::render()` SSTI**, **route-model-binding
IDOR with no policy**, **`unserialize()` object injection**, and **`APP_DEBUG=true`
in production**. A CSRF-enabled app (PoCs carry the token) with one planted
exemption keeps it realistic. phpMyAdmin is on the side as an extra surface.

## Services (4 containers) - independent `docker-compose.yml`

| Service    | Image                        | Host port  | Purpose                       |
|------------|------------------------------|------------|-------------------------------|
| app        | build . (php:8.3-apache)     | 13311      | Laravel 11 monolith (docroot `public/`) |
| mysql      | mysql:8.4                    | (internal) | Data                          |
| phpmyadmin | phpmyadmin:5.2.1             | 13312      | DB admin UI (weak `bench/bench`) |
| mailpit    | axllent/mailpit:v1.20        | 13313 (1025)| Verification email + internal SSRF target |

## Structure (idiomatic Laravel)

```
vuln/
  app/Http/Controllers/   Auth, Post, Comment, Profile, Admin, Tools, Billing, Report, Verify
  app/Http/Middleware/     AdminOnly.php
  app/Models/              User, Organization, Post, Comment, Subscription, Invitation
  app/Support/Backup.php   (deserialization gadget)
  bootstrap/app.php        middleware aliases + CSRF `except` (planted)
  config/cors.php          (planted reflective CORS)
  database/migrations/     users+orgs, posts/comments/subscriptions/invitations
  database/seeders/        DatabaseSeeder (shared Acme/Globex seed)
  resources/views/         Blade views (reflected + stored XSS sinks)
  routes/web.php           the route map (authz + throttle deltas live here)
  public/.env.backup       (planted secret leak)
  .env                     APP_DEBUG=true (planted)
```

- **php:8.3-apache**, `pdo_mysql` + `gd`; DocumentRoot is `public/`, `mod_rewrite`
  on. Runs in production mode (`APP_ENV=production`) so error handling is
  realistic - the verbose-error leak is deliberately `APP_DEBUG=true`, not a dev
  overlay.
- Session-based auth (`web` guard). CSRF is **on** for the whole app; the PoC
  harness scrapes `_token` from a Blade form and reuses it. `TrimStrings` and
  `ConvertEmptyStringsToNull` are active (they eat trailing-space SQL comments).

## Domain model

Standard shared domain, cross-tenant `user2` (org Globex) for IDOR PoCs; a Globex
DRAFT post carries `GLOBEX-CONFIDENTIAL-MARKER-7f3a`.

## Vulnerability catalog (25 planted bugs)

| Feature | Planted bug | CWE | OWASP | Sev | Diff | Taint |
|---|---|---|---|---|---|---|
| PostController@search | SQLi via raw `DB::select` concat | 89 | A03 | H | E | in-file |
| ReportController@titles | **Second-order** SQLi via stored title | 89 | A03 | H | H | cross-file |
| search.blade.php | Reflected XSS via `{!! $q !!}` | 79 | A03 | M | E | in-file |
| post_show.blade.php | Stored XSS via `{!! $c->body !!}` | 79 | A03 | M | E-M | cross-file |
| ToolsController@preview | **`Blade::render()` SSTI** | 1336 | A03 | C | M | in-file |
| ToolsController@export | Command injection via `shell_exec` | 78 | A03 | C | M | in-file |
| ProfileController@avatar | Arbitrary `.php` upload → RCE | 434 | A03 | C | M | in-file |
| PostController@show | **IDOR** via route-model binding | 639 | A01 | H | E | in-file |
| routes/web.php | Missing function-level authz (`/admin/users`) | 862 | A01 | H | M | in-file |
| User `$guarded = []` | **Mass assignment** priv-esc (is_admin/role) | 915 | A01 | H | M | cross-file |
| ToolsController@download | Path traversal via `file_get_contents` | 22 | A01 | H | E-M | in-file |
| ToolsController@go | Open redirect | 601 | A01 | L | E | in-file |
| bootstrap/app.php | CSRF exemption on a state-changing route | 352 | A01 | M | M | in-file |
| ToolsController@import | **`unserialize()` object injection** | 502 | A08 | C | H | cross-file |
| ToolsController@fetch | SSRF via `Http::get` | 918 | A10 | H | M-H | cross-service |
| .env | **`APP_DEBUG=true`** → stack/env leak | 489 | A05 | M | E | config |
| config/cors.php | Reflective CORS + credentials | 942 | A05 | M | M | config |
| public/.env.backup | Secret leak (env backup in web root) | 538 | A05 | H | E | in-file |
| phpmyadmin | Exposed with weak `bench/bench` | 798 | A05 | M | E | config |
| AuthController@sendReset | Predictable + leaked reset token | 640 | A07 | H | M | in-file |
| AuthController@login | User enumeration (distinct messages) | 204 | A07 | L | E-M | in-file |
| AuthController@login | No login rate limiting | 307 | A07 | M | E | in-file |
| DatabaseSeeder | Default creds `admin/admin` | 1392 | A07 | M | E | in-file |
| BillingController@invite | **Race condition** exceeds seat limit | 362 | A04 | H | H | in-file |
| BillingController@topup | Negative-amount billing manipulation | 840 | A04 | M | M | in-file |

## Stack-specific highlights (only make sense in Laravel)

- **Mass assignment** - the User model uses `$guarded = []`, so
  `$user->update($request->except('_token'))` lets a plain user set `is_admin`.
  Near-miss / fix: an explicit `$fillable` allowlist (name, email, avatar). The
  seeder/register set columns explicitly so they're independent of the allowlist.
- **Blade `{!! !!}`** - the reflected and stored XSS sinks are the raw-output
  directive; the escaping `{{ }}` sits right beside them (the post title).
- **`Blade::render($input)`** - a "template preview" compiles attacker input, so
  `{{ 7*7 }}` → 49 and `{{ system('id') }}` runs. Near-miss: `mode=greet` renders
  a *static* template with the input as bound, escaped data.
- **Route-model-binding IDOR** - `show(Post $post)` loads any id with no policy;
  the `audit()` sibling on the same object authorizes by org/owner.
- **`APP_DEBUG=true`** - an uncaught error renders the full Ignition/Symfony
  stack trace with framework paths; the fix is one line in `.env`.
- **CSRF** - one route is added to `validateCsrfTokens(except: [...])`; everything
  else stays protected, which is what makes it a discriminating finding.

## Near-misses (safe beside vulnerable, present in BOTH variants)

- `DB::select` concat (search) beside a bound `DB::select(?, [...])` (index).
- `{!! $c->body !!}` beside `{{ $post->title }}`.
- `show()` (no authz) beside `audit()` (org/owner check).
- `/admin/users` (no gate) beside `/admin/audit` (`admin` middleware).
- `unserialize()` beside a `json_decode()` import branch.
- `Blade::render($tpl)` beside `Blade::render('Hello {{ $name }}', [...])`.
- `redirect()->away($next)` beside an allowlist branch.

## Logic-only bugs

- **Invite race (CWE-362):** seat check-then-act with no lock; parallel PoC beats
  the limit. Safe twin reserves inside a transaction with `lockForUpdate()`.
- **Billing (CWE-840):** negative top-up accepted; safe twin rejects `amount <= 0`.

## Ground truth & scoring

- `VULNERABILITIES.yaml` per row; `ground-truth/verify/*.sh` PoCs read `$TARGET`,
  exit `0` on vuln and non-zero on safe. `_lib.sh` provides the CSRF-aware
  `login`, a `post` helper that carries the token, and `_verify` id resolvers.
- The rate-limit PoC hammers a **dedicated probe identity** so the safe twin's
  per-identity limiter never blocks other PoCs' logins.
- `ground-truth/` is `.dockerignore`d and never baked into an image.

## Patched twin (`safe/`)

Bound queries, escaped `{{ }}`, static-template render, org/owner check on `show`,
`admin` middleware on `/admin/users`, `$fillable` allowlist, `basename` +
containment on downloads, `escapeshellarg` + format allowlist, image-validated +
randomly-named uploads, allowlist-only redirect, empty CSRF `except`,
`json_decode` import, SSRF host allowlist + private-range block, `APP_DEBUG=false`,
pinned single-origin CORS without credentials, removed `.env.backup`, phpMyAdmin
dropped from compose, random + hashed + non-returned reset token with
`hash_equals`, generic auth error, per-identity failure limiter, strong service
password, seat reservation under a row lock, positive-amount billing.

## Compose sketch (independent; 127.0.0.1 only)

```yaml
name: vuln-laravel
services:
  app:
    build: .
    ports: ["127.0.0.1:${DYNAST_PORT:-13311}:80"]
    environment: { APP_ENV: production, APP_DEBUG: "true", DB_HOST: mysql, ... }
    depends_on: { mysql: { condition: service_healthy }, mailpit: ..., phpmyadmin: ... }
    healthcheck: { test: ["CMD","curl","-sf","http://localhost/api/_verify/health"] }
  mysql: { image: mysql:8.4, ... }
  phpmyadmin: { image: phpmyadmin:5.2.1, ports: ["127.0.0.1:${DYNAST_PORT_PHPMYADMIN_80:-13312}:80"] }
  mailpit: { image: axllent/mailpit:v1.20, ports: ["...:${DYNAST_PORT_MAILPIT_8025:-13313}:8025", "...:1025"] }
```

## Build milestones

1. `composer create-project laravel/laravel:^11` skeleton; shared domain
   migrations + seeder; verify API; compose + Dockerfile (Apache docroot `public/`);
   boot healthy.
2. Auth (login/register/reset) + enum/rate-limit/reset/default-creds bugs.
3. Tools controller (SSRF, traversal, cmd, SSTI, redirect, deser) + near-misses.
4. Posts CRUD + search SQLi + IDOR + second-order SQLi; comments/search XSS;
   profile mass-assign + upload RCE; admin authz; CSRF exemption.
5. Billing race + negative amount; CORS / debug / secret-leak / phpMyAdmin
   misconfigs.
6. `VULNERABILITIES.yaml` + `verify/` PoCs all PASS on vuln; `safe/` fixes all,
   all PoCs FAIL; `Dockerfile.standalone` + `entrypoint.standalone.sh` +
   `internal-sink.mjs`; `make validate` and `make solo` green.
```
