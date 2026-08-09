# php - intentionally vulnerable app

> ⚠️ **DELIBERATELY INSECURE. Local only.** Binds `127.0.0.1`, holds no real
> data. Built to benchmark DAST/SAST/LLM security tools. Never deploy publicly.

**Classic PHP Bench** is a procedural PHP 8.3 + Apache + MySQL application built
from [`../../benchmark-plans/php.md`](../../benchmark-plans/php.md). It keeps the
shared Acme/Globex seed and plants PHP/LAMP-specific bugs next to safe-shaped
near-misses.

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
