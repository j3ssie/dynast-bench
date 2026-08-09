# nestjs - intentionally vulnerable app

> ⚠️ **DELIBERATELY INSECURE. Local only.** Binds `127.0.0.1`, holds no real
> data. Built to benchmark DAST/SAST/LLM security tools. Never deploy publicly.

**TaskFlow NestJS** is a small multi-tenant task/blog app (NestJS + Handlebars +
Postgres + Redis sessions behind nginx) built from
[`../../benchmark-plans/nestjs.md`](../../benchmark-plans/nestjs.md). It keeps
the shared Acme/Globex seed and plants Nest/proxy-specific footguns next to
safe-shaped near-misses.

## Layout

```text
nestjs/
├── vuln/          # vulnerable variant (the default target)
├── safe/          # patched twin - same app, documented bugs fixed
├── ground-truth/  # VULNERABILITIES.yaml + verify/ PoCs (never baked into images)
└── Makefile       # up · reset · safe · verify · validate · diff · solo
```

## Run

```bash
make up          # build + start vuln/ on http://127.0.0.1:13311 through nginx
make verify      # run PoCs; expect ALL exploitable
make safe        # switch to the patched twin
make verify-safe # run PoCs; expect ALL fixed
make validate    # vuln→all pass, safe→all fixed
make diff        # ground-truth diff (vuln vs safe)
make reset       # fresh seeded state
make solo        # single self-contained image
```

The verification API lives at `/api/_verify/*`; lookup routes require
`X-Verify-Token: benchsecret` except health.

## Planted vulnerability clusters

This representative subset includes 23 planted bugs and 5 near-misses: missing
Nest `ValidationPipe` whitelist/mass assignment, Handlebars template/triple-stache
XSS shape, nginx alias traversal, trusted `X-Forwarded-For`, auth enumeration,
default credentials, session fixation, JWT/reset flaws, IDOR/BFLA, raw SQLi,
SSRF, unsafe deserialization/eval, reflected CORS, CSRF, open redirect,
filesystem traversal, unrestricted upload/SVG XSS, billing manipulation, and an
invite race. Full metadata is in
[`ground-truth/VULNERABILITIES.yaml`](ground-truth/VULNERABILITIES.yaml).
