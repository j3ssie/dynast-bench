# php - intentionally vulnerable app

> ⚠️ **DELIBERATELY INSECURE. Local only.** Binds `127.0.0.1`, holds no real
> data. Built to benchmark DAST/SAST/LLM security tools. Never deploy publicly.

**Classic PHP Bench** is a procedural PHP 8.3 + Apache + MySQL application built
from [`../../benchmark-plans/php.md`](../../benchmark-plans/php.md). It keeps the
shared Acme/Globex seed and plants PHP/LAMP-specific bugs next to safe-shaped
near-misses.

**Agent-only surface (deep hardening).** On top of the LAMP catalog it plants an
8-bug surface a request fuzzer cannot reach - only an agent that behaves like a
user: a **four-step signup wizard** at `/signup.php` (client-driven fetch to
`/api/signup/*.php`) with four `flow`-tier bugs (clock-derived verification code,
`role`/`org_slug` mass-assignment, complete-without-verify, draft-IDOR leaking
another signup's email + code), two browser-only bugs on the wizard page (**DOM
XSS** via `location.hash`, a **postMessage** sink), and a hidden `eval()` report
builder (`CODEINJ`, CWE-94) referenced only from the panel the wizard fetches
after an **Advanced** click. Those 8 are tiered `flow`/`interaction`/`js-runtime`;
the pre-existing catalog stays `static-html`, so `recall by discovery tier` shows
how far past the fuzzable surface a tool gets. The browser PoCs drive the shared
`dynast-bench/tools/browser/` image.

## Layout

```text
php/
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
make solo        # single self-contained image
```

The verification API lives at `/api/_verify/*`; lookup routes require
`X-Verify-Token: benchsecret`.

## Planted vulnerability clusters

This representative subset covers 21 PHP-plan bugs: LFI, loose comparison,
default credentials, `unserialize`, arbitrary PHP upload, SQLi, command
injection, XXE, SSRF, traversal, IDOR, missing authz, mass assignment, reflected
and stored XSS, open redirect, reflective CORS, predictable reset token, session
fixation, and phpMyAdmin side surface. Full metadata is in
[`ground-truth/VULNERABILITIES.yaml`](ground-truth/VULNERABILITIES.yaml).
