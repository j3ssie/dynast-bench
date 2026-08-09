# WordPress Version - Vulnerable App Plan

> ⚠️ **Intentionally vulnerable. Local only.** Binds `127.0.0.1`, ships a LOUD
> banner, carries no real data. Built to benchmark DAST/SAST/LLM security tools.

**Angle:** the **vulnerable-plugin** app. WordPress core stays stock; the
planted bugs live in a **custom plugin (`bench-tasks`)** written the way most
real-world WP vulns are written - **`$wpdb->query` without `prepare` (SQLi)**,
**missing nonce (CSRF)**, **missing `current_user_can` (broken authz)**,
**`wp_ajax_nopriv_` unauthenticated actions**, **arbitrary file upload**, and
**`unserialize()` object injection**. Plus the config-level WordPress classics:
REST/author **user enumeration** and **XML-RPC** abuse.

## Services (4 containers) - independent `docker-compose.yml`

| Service   | Image                       | Host port  | Purpose                     |
|-----------|-----------------------------|------------|-----------------------------|
| nginx     | nginx:1.27.1                | 3000       | Entry point → WordPress fpm |
| wordpress | wordpress:6.6-php8.3-fpm    | (internal) | Core + `bench-tasks` plugin |
| mysql     | mysql:8.4                   | 3306       | Data                        |
| mailpit   | axllent/mailpit:v1.20       | 8025 (1025)| New-user + reset emails     |

## Provisioning (WP-CLI, reproducible)

`make reset` reprovisions exactly: `wp core install` (admin per seed), roles
mapped to the shared matrix (`administrator`=admin, `editor`=editor,
`author`≈user), 6 seeded posts across two "orgs" (categories used as tenants),
Mailpit SMTP via mu-plugin, then the **`bench-tasks`** plugin activated (all
planted bugs) and a `bench-verify` mu-plugin exposing the `/api/_verify/*`
ground-truth endpoints.

## The `bench-tasks` plugin (where the bugs live)

A small task/board plugin adding shortcodes, admin pages, AJAX endpoints, a REST
namespace, and an "import/export" tool - every function a realistic home for a
planted bug.

## Domain model

Standard shared domain expressed in WP terms: custom post type `task`, taxonomy
`org` for tenancy, `wp_users` + roles, plugin options for webhooks/reports.
A second-tenant author exists so IDOR PoCs cross the `org` boundary.

## Vulnerability catalog (~30 planted bugs)

| Service · Feature | Planted bug | CWE | OWASP | Sev | Diff | Taint |
|---|---|---|---|---|---|---|
| plugin · task query | **SQLi** - `$wpdb->query("… $_GET[id]")` no `prepare` | 89 | A03 | H | E | in-file |
| plugin · report | **Second-order** SQLi via stored task title | 89 | A03 | H | H | cross-file |
| plugin · AJAX save | **Missing nonce** → CSRF on state change | 352 | A01 | M | M | in-file |
| plugin · admin action | **Missing `current_user_can`** → broken authz | 862/285 | A01 | H | M | in-file |
| plugin · AJAX | **`wp_ajax_nopriv_`** exposes privileged action | 306/862 | A01 | H | M | in-file |
| plugin · import | **`unserialize()`** on user data → object injection | 502 | A08 | C | H | in-file |
| plugin · upload | **Arbitrary file upload** (no type check) → webshell | 434 | A03 | C | M-H | in-file |
| plugin · include | **LFI** via `include($_GET['view'])` | 98/22 | A03 | H | M | in-file |
| plugin · fetch | **SSRF** via `wp_remote_get($_GET['url'])` | 918 | A10 | H | M-H | cross-service |
| plugin · shortcode | Stored XSS (no `esc_html`/`wp_kses`) | 79 | A03 | M | E-M | cross-file |
| plugin · search | Reflected XSS (echoed `$_GET` unescaped) | 79 | A03 | M | E | in-file |
| plugin · task read | IDOR - task by id ignores `org`/author | 639/863 | A01 | H | E-M | in-file |
| plugin · profile | Privilege escalation via `role`/meta update | 915/269 | A01 | H | M | in-file |
| plugin · export | Command injection (`shell_exec` to zip/convert) | 78 | A03 | C | M | in-file |
| plugin · redirect | Open redirect (`wp_redirect($_GET['to'])` unvalidated) | 601 | A01 | L | E | in-file |
| plugin · options | Secrets stored/echoed in plugin settings page | 200/798 | A02 | M | E-M | in-file |
| plugin · reset | Predictable custom reset token | 640/330 | A07 | M | M | cross-file |
| core · REST | **User enumeration** via `/wp-json/wp/v2/users` | 200/204 | A07 | M | E | config |
| core · author | **User enumeration** via `?author=1` redirect | 200/204 | A07 | L | E | config |
| core · xmlrpc | **XML-RPC** `system.multicall` brute force / pingback SSRF | 307/918 | A07 | M | M | config |
| core · login | No rate limit → brute force | 307 | A07 | M | E | config |
| core · config | Weak/duplicated `wp-config.php` salts & keys | 798/321 | A02 | M | E-M | config |
| core · debug | `WP_DEBUG`/`WP_DEBUG_DISPLAY` on → info leak | 209/489 | A05 | L | E | config |
| core · files | `wp-config.php.bak` / `debug.log` web-reachable | 538/532 | A05 | M | E-M | config |
| plugin · billing/seats | Negative/huge value manipulation | 840 | A04 | M | M | in-file |
| plugin · invites | **Race condition** exceeds seat limit | 362 | A04 | H | H | in-file |
| plugin · CORS | Custom endpoint reflects origin + credentials | 942 | A05 | M | M | in-file |
| plugin · deps | Bundled vulnerable JS/PHP lib (pinned) | 1035 | A06 | M | E | config |
| seed data | Default `admin/admin` extra account | 798 | A07 | M | E | config |

## Stack-specific highlights (only make sense in WordPress)

- **`$wpdb->query` without `prepare`** - the plugin concatenates `$_GET`/`$_POST`
  straight into SQL. The near-miss: an adjacent query uses
  `$wpdb->prepare("… %d", $id)`.
- **Missing nonce (CSRF)** - a state-changing AJAX/admin-post handler with no
  `wp_verify_nonce()` / `check_admin_referer()`. Near-miss handler verifies a
  nonce.
- **Missing capability check** - a privileged action reachable by any logged-in
  user because there's no `current_user_can('manage_options')`. Near-miss gates
  it.
- **`wp_ajax_nopriv_`** - a privileged AJAX action registered for *unauthenticated*
  users too. Uniquely WP.
- **`unserialize()` object injection** - PHP object injection via WP's meta/
  options path or an import blob; gadget chains reach RCE. Safe twin uses
  `maybe_unserialize` only on trusted data / JSON.
- **REST + author enumeration & XML-RPC** - config-level WP classics a
  WP-aware scanner should always flag.

## Near-misses (safe beside vulnerable)

- Unprepared `$wpdb->query` beside a `$wpdb->prepare` sibling.
- No-nonce handler beside a `check_admin_referer` handler.
- Uncapped action beside a `current_user_can`-gated one.
- `include($_GET['view'])` beside an allowlist-`switch` include.

## Logic-only bugs

- **Invite/seat race (CWE-362):** option read-modify-write without a lock;
  parallel PoC beats the limit.
- **Billing (CWE-840):** negative/huge seat value accepted.

## Ground truth & scoring

- `VULNERABILITIES.yaml` per row; `verify/` PoCs (`wpdb_sqli.sh`;
  `nopriv_ajax.sh` hits `admin-ajax.php?action=…` unauthenticated;
  `rest_userenum.sh` GETs `/wp-json/wp/v2/users`; `unserialize.sh`;
  `race_invite.sh`). PASS on `main-vuln`, FAIL on `main-safe`.
- Scorer → P/R/F1 + per-CWE. `ground-truth/` `.dockerignore`d.

## Patched twin (`main-safe`)

`$wpdb->prepare` everywhere, nonces on every state change, `current_user_can`
on privileged actions, remove `nopriv` registration, JSON import (no
`unserialize`), MIME/extension upload allowlist, allowlist includes (no LFI),
SSRF allowlist + metadata block, `esc_html`/`wp_kses` output, org/author-scoped
reads, no role self-escalation, arg-array shell-outs, redirect allowlist,
secrets out of options UI, random reset tokens, REST user endpoint restricted,
`?author` redirect disabled, XML-RPC disabled, login rate limit, unique salts,
`WP_DEBUG` off, backup/log files blocked, scoped CORS, validated billing, locked
seat reservation, patched bundled lib.

## Compose sketch (independent; 127.0.0.1 only)

```yaml
name: vuln-wordpress
services:
  nginx:
    image: nginx:1.27.1
    ports: ["127.0.0.1:${DYNAST_PORT:-13311}:80"]
    volumes:
      - ./infra/nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - wp_data:/var/www/html:ro
    depends_on: [wordpress]
  wordpress:
    image: wordpress:6.6-php8.3-fpm
    environment:
      WORDPRESS_DB_HOST: mysql
      WORDPRESS_DEBUG: "1"                     # planted CWE-489
      WORDPRESS_CONFIG_EXTRA: |
        define('DISALLOW_FILE_EDIT', false);   # planted: plugin/theme editor on
    volumes:
      - wp_data:/var/www/html
      - ./mu-plugins:/var/www/html/wp-content/mu-plugins:ro
      - ./plugins/bench-tasks:/var/www/html/wp-content/plugins/bench-tasks:ro
    depends_on: { mysql: { condition: service_healthy } }
  provision:
    image: wordpress:cli-php8.3
    volumes: [wp_data:/var/www/html, ./provision.sh:/provision.sh:ro]
    entrypoint: ["bash", "/provision.sh"]
    depends_on: [wordpress]
  mysql:
    image: mysql:8.4
    healthcheck: { test: ["CMD", "mysqladmin", "ping", "-h", "localhost"] }
  mailpit:
    image: axllent/mailpit:v1.20
    ports: ["127.0.0.1:${DYNAST_PORT_MAILPIT_8025:-13312}:8025", "127.0.0.1:${DYNAST_PORT_MAILPIT_1025:-13313}:1025"]
volumes: { wp_data: {} }
```

## Build milestones

1. Compose (fpm + nginx + mysql) boots installed WP via provision script;
   Makefile.
2. `bench-tasks` plugin skeleton: shortcodes, admin pages, AJAX, REST,
   import/export - each function a home for a planted bug + its safe twin.
3. Plant SQLi/nonce/cap/nopriv/unserialize/upload/LFI/SSRF/XSS + IDOR + priv-esc.
4. Config-level classics: REST/author enumeration, XML-RPC, weak salts, debug
   on, backup files reachable.
5. Billing/invite logic bugs; CORS; bundled vulnerable lib.
6. `bench-verify` mu-plugin + rewrites; `VULNERABILITIES.yaml` + `verify/` PoCs;
   all PASS on `main-vuln`; branch `main-safe`, fix all, all PoCs FAIL; scorer.
