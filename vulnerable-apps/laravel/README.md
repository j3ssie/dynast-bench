# laravel - intentionally vulnerable app

> ⚠️ **DELIBERATELY INSECURE. Local only.** Binds `127.0.0.1`, holds no real
> data. Built to benchmark DAST/SAST/LLM security tools. Never deploy publicly.

**BenchBoard** is a modern **Laravel 11** (PHP 8.3 · Apache · MySQL) SaaS app
built from [`../../benchmark-plans/laravel.md`](../../benchmark-plans/laravel.md).
It keeps the shared Acme/Globex seed and plants Laravel/PHP-signature bugs - Blade
`{!! !!}` XSS, `Blade::render` SSTI, mass assignment via `$guarded = []`,
route-model-binding IDOR, `unserialize` object injection, `APP_DEBUG` leakage -
right next to safe-shaped near-misses (bound queries, escaped `{{ }}`,
policy-checked siblings, `json_decode`, allowlisted redirects).

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
