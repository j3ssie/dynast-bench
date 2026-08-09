# Traditional PHP Version - Vulnerable App Plan

> ⚠️ **Intentionally vulnerable. Local only.** Binds `127.0.0.1`, ships a LOUD
> banner, carries no real data. Built to benchmark DAST/SAST/LLM security tools.

**Angle:** the **classic-LAMP-monolith** app - the richest catalog of "PHP
special" bugs. Procedural PHP, one file per page. Signature bugs are the ones
that only bite in PHP: **LFI/RFI via `include`**, **type-juggling / magic-hash
auth bypass (`==`)**, **`unserialize()` object injection**, **arbitrary `.php`
upload → RCE**, and **`extract($_GET)` variable overwrite**. phpMyAdmin is on the
side as an extra surface.

## Services (4 containers) - independent `docker-compose.yml`

| Service    | Image                        | Host port  | Purpose                       |
|------------|------------------------------|------------|-------------------------------|
| app        | build ./app (php:8.3-apache) | 3000       | The monolith                  |
| mysql      | mysql:8.4                    | 3306       | Data                          |
| phpmyadmin | phpmyadmin:5.2.1             | 8081       | DB admin UI (weak creds)      |
| mailpit    | axllent/mailpit:v1.20        | 8025 (1025)| Verification emails           |

## Structure (deliberately old-school flat)

```
app/public/
  index.php  signup.php  login.php  logout.php  verify.php
  onboarding.php  profile.php  posts.php  post_edit.php  search.php
  admin_users.php  page.php  download.php  import.php  export.php  fetch.php
  captcha.php  uploads/                api/_verify/{health,user,post}.php
app/inc/
  db.php  auth.php  captcha.php  header.php  footer.php
  vendor/PHPMailer/                        (vendored, no composer)
```

- **php:8.3-apache**, `pdo_mysql` + `gd`; PDO available but the planted SQLi
  sites concatenate into `$pdo->query(...)` directly
- Auth: `password_hash`/`password_verify` in most places, but the "remember
  token" / admin check uses a loose `==` comparison (type juggling); native
  `$_SESSION`
- Email verification via vendored **PHPMailer** → `mailpit:1025`
- Forms POST back to the same file

## Domain model

Standard shared domain, cross-tenant `user2` (org Globex) for IDOR PoCs.

## Vulnerability catalog (~32 planted bugs)

| Service · Feature | Planted bug | CWE | OWASP | Sev | Diff | Taint |
|---|---|---|---|---|---|---|
| page.php · include | **LFI/RFI** - `include($_GET['page'])` | 98/22 | A03 | C | E-M | in-file |
| login.php · auth | **Type-juggling bypass** (`==` / magic hash) | 697/287 | A07 | H | M-H | in-file |
| import.php · restore | **`unserialize($_COOKIE/$_POST)`** object injection | 502 | A08 | C | H | in-file |
| profile.php · upload | **Arbitrary `.php` upload** → RCE (no type check) | 434 | A03 | C | M | in-file |
| *.php · params | **`extract($_GET)`** variable overwrite | 621/915 | A01 | H | M-H | in-file |
| search.php · query | SQLi via string concat into `$pdo->query` | 89 | A03 | H | E | in-file |
| report · query | **Second-order** SQLi via stored post title | 89 | A03 | H | H | cross-file |
| export.php · shell | Command injection (`system`/`shell_exec`/`exec`) | 78 | A03 | C | M | in-file |
| import.php · xml | **XXE** via `simplexml_load_string`/libxml | 611 | A03 | H | M | in-file |
| fetch.php · url | **SSRF** via `file_get_contents($_GET['url'])`/cURL | 918 | A10 | H | M-H | cross-service |
| eval endpoint | **Code injection** `eval($_GET['expr'])` (calc feature) | 94 | A03 | C | M | in-file |
| download.php · file | Path traversal / arbitrary read (`readfile($_GET)`) | 22 | A01 | H | E-M | in-file |
| posts.php · id | IDOR/BOLA - no owner/org check | 639/863 | A01 | H | E | in-file |
| admin_users.php | Missing function-level authz (no role check) | 862 | A01 | M | M | in-file |
| profile.php · role | Mass assignment / priv-esc via hidden `role` field | 915/269 | A01 | H | M | in-file |
| comments · output | Stored XSS (no `htmlspecialchars`) | 79 | A03 | M | E-M | cross-file |
| search.php · echo | Reflected XSS (echoed `$_GET`) | 79 | A03 | M | E | in-file |
| login.php · `?next` | Open redirect (`header("Location: $_GET[next]")`) | 601 | A01 | L | E | in-file |
| header.php · CORS | Reflects `Origin` + `Allow-Credentials: true` | 942 | A05 | M | M | in-file |
| auth.php · token | Predictable reset token `md5(time())` | 640/330 | A07 | M | M | cross-file |
| auth.php · session | Session fixation (no `session_regenerate_id`) | 384 | A07 | M | M | in-file |
| login.php · rate | No rate limit → brute force | 307 | A07 | M | E | in-file |
| login.php · enum | User enumeration (distinct messages) | 204 | A07 | L | E-M | in-file |
| db.php · creds | Hardcoded DB creds in source | 798 | A05 | M | E | in-file |
| php.ini · errors | `display_errors=On` → stack/path leak | 209/489 | A05 | L | E | config |
| info.php | `phpinfo()` page left in webroot | 200 | A05 | M | E | in-file |
| captcha.php · bypass | CAPTCHA answer in cookie / predictable seed | 804/330 | A07 | M | M | in-file |
| upload · mime | MIME spoof (checks extension only) | 434 | A03 | M | M | in-file |
| billing.php · seats | Negative/huge value manipulation | 840 | A04 | M | M | in-file |
| invite.php · seats | **Race condition** exceeds seat limit | 362 | A04 | H | H | in-file |
| crypto · weak | Weak crypto (ECB / static IV / `mcrypt`-era) | 327 | A02 | M | M | in-file |
| phpmyadmin | Reachable with weak `bench/bench` creds | 798 | A05 | M | E | config |

## Stack-specific highlights (only make sense in PHP)

- **LFI/RFI** - `include($_GET['page'] . '.php')`; `page=php://filter/...` reads
  source, `page=/etc/passwd%00` (or a log-poisoning chain) reaches RCE, and with
  `allow_url_include` a remote URL is straight RFI. Near-miss uses an allowlist
  `switch`.
- **Type juggling** - `if ($_POST['token'] == $stored)` where PHP coerces
  `"0e123..." == "0e456..."` (magic hashes) or `"admin" == 0`. Uniquely PHP's
  loose `==`. Near-miss uses `hash_equals()` / `===`.
- **`unserialize()` object injection** - a serialized cookie/POST field is
  `unserialize`d; a `__wakeup`/`__destruct` gadget triggers file write or RCE.
  Near-miss uses `json_decode`.
- **Arbitrary `.php` upload** - the avatar handler trusts the client extension
  and stores under the webroot, so `shell.php` becomes executable. Near-miss
  re-encodes the image + stores outside webroot with a random name.
- **`extract($_GET)`** - imports request keys into local scope, letting an
  attacker overwrite `$is_admin`/`$authenticated`. Near-miss reads explicit
  keys.
- **`eval($_GET['expr'])`** - a "formula" feature; direct code injection.

## Near-misses (safe beside vulnerable)

- `include($_GET['page'])` beside an allowlist-`switch` router.
- `==` token check beside a `hash_equals()` check.
- `unserialize()` import beside a `json_decode()` import.
- Raw echo beside `htmlspecialchars($x, ENT_QUOTES)`.

## Logic-only bugs

- **Invite race (CWE-362):** seat `SELECT` then `INSERT` without a lock;
  parallel PoC beats the limit.
- **Billing (CWE-840):** negative/huge seat value accepted.

## Ground truth & scoring

- `VULNERABILITIES.yaml` per row; `verify/` PoCs (`lfi.sh` reads
  `php://filter/.../page.php`; `typejuggle.sh` sends a magic-hash token;
  `phpupload.sh` uploads + executes a `.php`; `unserialize.sh`;
  `race_invite.sh`). PASS on `main-vuln`, FAIL on `main-safe`.
- Scorer → P/R/F1 + per-CWE. `ground-truth/` `.dockerignore`d.

## Patched twin (`main-safe`)

Allowlist include router, `hash_equals`/`===`, `json_decode` import, image
re-encode + out-of-webroot upload, explicit request keys (no `extract`), bound
PDO params, arg-safe shell-outs, XXE-hardened libxml (`LIBXML_NONET`, no DTD),
SSRF allowlist + metadata block, removed `eval`, containment-checked downloads,
owner/org checks, role checks, no self-escalation, `htmlspecialchars` output,
redirect allowlist, scoped CORS, random reset tokens, `session_regenerate_id`
on login, rate limit, generic auth errors, env DB creds, `display_errors=Off`,
`phpinfo` removed, CAPTCHA server-side + random seed, MIME sniff via
`finfo`, validated billing, locked seat reservation, AES-GCM crypto,
phpMyAdmin creds rotated / not exposed.

## Compose sketch (independent; 127.0.0.1 only)

```yaml
name: vuln-php
services:
  app:
    build: ./app
    ports: ["127.0.0.1:${DYNAST_PORT:-13311}:80"]
    environment:
      DB_HOST: mysql
      DB_USER: bench
      DB_PASS: bench            # planted CWE-798 (also hardcoded in db.php)
      SMTP_HOST: mailpit
      CAPTCHA_MODE: image
      CAPTCHA_SEED: "42"        # planted CWE-330 (predictable)
      PHP_DISPLAY_ERRORS: "On"  # planted CWE-209
      APP_URL: http://localhost:13311
    depends_on: { mysql: { condition: service_healthy } }
  mysql:
    image: mysql:8.4
    environment: { MYSQL_DATABASE: bench, MYSQL_USER: bench, MYSQL_PASSWORD: bench, MYSQL_ROOT_PASSWORD: root }
    volumes: ["./db/init:/docker-entrypoint-initdb.d:ro"]
    healthcheck: { test: ["CMD", "mysqladmin", "ping", "-h", "localhost"] }
  phpmyadmin:
    image: phpmyadmin:5.2.1
    environment: { PMA_HOST: mysql }
    ports: ["127.0.0.1:${DYNAST_PORT_PHPMYADMIN_80:-13312}:80"]
  mailpit:
    image: axllent/mailpit:v1.20
    ports: ["127.0.0.1:${DYNAST_PORT_MAILPIT_8025:-13313}:8025", "127.0.0.1:${DYNAST_PORT_MAILPIT_1025:-13314}:1025"]
```

## Build milestones

1. Compose + init SQL (schema + seed: cross-tenant + weak creds) + Makefile.
2. Auth pages + sessions + PHPMailer verification; plant type-juggling bypass,
   fixation, weak reset token + safe twins.
3. `page.php` LFI, `download.php` traversal, `import.php` unserialize/XXE,
   `fetch.php` SSRF, `export.php` cmd injection, eval feature - each + safe twin.
4. Posts CRUD + IDOR + search SQLi (+ near-miss); comments/search XSS; profile
   upload RCE + priv-esc.
5. `extract` overwrite; billing/invite logic bugs; CORS/redirect/CAPTCHA/info
   misconfigs; phpMyAdmin surface.
6. `api/_verify/*` + `VULNERABILITIES.yaml` + `verify/` PoCs; all PASS on
   `main-vuln`; branch `main-safe`, fix all, all PoCs FAIL; wire scorer.
