# laravel - intentionally vulnerable app

> ⚠️ **DELIBERATELY INSECURE. Local only.** Binds `127.0.0.1`, holds no real
> data. Built to benchmark DAST/SAST/LLM security tools. Never deploy publicly.

**BenchBoard** is a modern **Laravel 11** (PHP 8.3 · Apache · MySQL) SaaS app
built from [`../../benchmark-plans/laravel.md`](../../benchmark-plans/laravel.md).
It keeps the shared Acme/Globex seed and plants Laravel/PHP-signature bugs - Blade
`{!! !!}` XSS, `Blade::render` SSTI, mass assignment via `$guarded = []`,
route-model-binding IDOR, `unserialize` object injection, `APP_DEBUG` leakage,
an `libxml` **XXE**, a **DOM XSS** and a **postMessage** sink, and a four-step
signup flow - right next to safe-shaped near-misses (bound queries, escaped
`{{ }}`, policy-checked siblings, `json_decode`, allowlisted redirects, CSPRNG
tokens, rate-limited resend).

**Built to reward a smart agent over a dumb scanner.** The home page is not a
sitemap: the nav is rendered client-side from a session-scoped `/nav` manifest,
every app URL is assembled at runtime from a JS route registry, the signup wizard
is four independent fetch calls, and the XXE endpoint is referenced only from a
panel the dashboard fetches after an **Advanced** click. Of the **33** bugs, each
carries a `discovery:` tier and **only 7 are `static-html`** (a request-only tool
like ffuf/nuclei finds these: `/login`, `/.env.backup`, phpMyAdmin, the health
path). The other 26 need more:

- **12 `js-runtime`** - the URL only exists once the page's JS assembles it
  (`/search`, `/tools/*`, `/reports/titles`, `/admin/users`, `/posts/{id}`, and
  the click-gated `import-mapping` XXE).
- **10 `interaction`** - the sink only fires on a click / submit / browser event
  (stored XSS, upload, CSRF, deser, billing, invite race, **DOM XSS** via
  `location.hash`, **postMessage**, and signup step 1).
- **4 `flow`** - only reachable from a specific state of the multi-step signup
  (clock-derived verification code, `role`/`org_slug` mass assignment, complete
  without verifying, and draft IDOR that leaks another signup's email + code).

So an agent that logs in, drives the DOM, and completes the signup flow uncovers
~4x what a path fuzzer can. The browser-driven PoCs (`domxss_001`, `postmsg_001`)
reuse a curl login and hand the session cookie to the shared
`dynast-bench/tools/browser/` image via `--cookie`.

## Layout

```text
laravel/
├── vuln/          # vulnerable variant (the default target)
├── safe/          # patched twin - same app, documented bugs fixed
├── ground-truth/  # VULNERABILITIES.yaml + verify/ PoCs (never baked into images)
└── Makefile       # up · reset · safe · verify · validate · diff · solo
```

## Run

```bash
make up          # build + start vuln/ on http://127.0.0.1:13311
make verify      # run PoCs; expect ALL exploitable
make safe        # switch to the patched twin
make verify-safe # run PoCs; expect ALL fixed
make validate    # vuln→all pass, safe→all fixed
make diff        # ground-truth diff (vuln vs safe)
make reset       # fresh seeded state
make solo        # single self-contained image (embeds MySQL + internal sink)
```

The verification API lives at `/api/_verify/*`; lookup routes require
`X-Verify-Token: benchsecret`. The health endpoint is `/api/_verify/health`
(no token).

## Notes for scanners / PoC authors

- **CSRF is enabled app-wide.** The PoCs scrape the `_token` from a Blade form
  and reuse it (the token rotates once at login). One route -
  `POST /account/name` - is the planted CSRF exemption.
- **`TrimStrings` is active**, so trailing-whitespace SQL comments (`-- `) get
  eaten; the SQLi PoCs use MySQL's `#` comment instead.
- Sidecars: **MySQL 8.4**, **Mailpit** (also the internal SSRF target at
  `mailpit:8025`), **phpMyAdmin** (weak `bench/bench`). In `solo` mode a tiny
  `internal-sink.mjs` stands in for Mailpit and phpMyAdmin.

## Planted vulnerabilities

25 planted bugs + 7 near-misses spanning OWASP A01/A03/A04/A05/A07/A08/A10.
Full metadata (CWE, OWASP, severity, difficulty, taint, reachability, PoC) is in
[`ground-truth/VULNERABILITIES.yaml`](ground-truth/VULNERABILITIES.yaml).
