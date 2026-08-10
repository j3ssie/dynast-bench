# nestjs - intentionally vulnerable app

> ⚠️ **DELIBERATELY INSECURE. Local only.** Binds `127.0.0.1`, holds no real
> data. Built to benchmark DAST/SAST/LLM security tools. Never deploy publicly.

**TaskFlow NestJS** is a small multi-tenant task/blog app (NestJS + Handlebars +
Postgres + Redis sessions behind nginx) built from
[`../../benchmark-plans/nestjs.md`](../../benchmark-plans/nestjs.md). It keeps
the shared Acme/Globex seed and plants Nest/proxy-specific footguns next to
safe-shaped near-misses.

**Two research-grade classes.** `SSPP-001` (CWE-1321->78): *server-side prototype pollution* to RCE - a recursive merge walks `constructor.prototype` onto `Object.prototype`, and a fresh `{}` in `/api/reports/generate` inherits a polluted `cmdSuffix` that lands in a shell command. `QSCONFUSION-001` (CWE-843): Express/`qs` *parameter type confusion* - `?url[]=` makes the value an array, skipping an `if (typeof url === 'string')` SSRF guard and reaching the internal sink a string URL can't.

**Agent-only surface (deep hardening).** On top of the API catalog it plants an
8-bug surface a request fuzzer cannot reach - only an agent that behaves like a
user: a **four-step signup wizard** at `/signup` (client-driven fetch to
`/api/signup/*`) with four `flow`-tier bugs (clock-derived verification code,
`role`/`org_slug` mass-assignment, complete-without-verify, draft-IDOR leaking
another signup's email + code), two browser-only bugs on the wizard page (**DOM
XSS** via `location.hash`, a **postMessage** sink), and a hidden `new Function`
report builder (`CODEINJ`, CWE-94) referenced only from the panel the wizard
fetches after an **Advanced** click. Those 8 are tiered
`flow`/`interaction`/`js-runtime`; the pre-existing REST catalog stays
`static-html`, so `recall by discovery tier` shows how far past the fuzzable API a
tool gets. The browser PoCs drive the shared `dynast-bench/tools/browser/` image.

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
