# fastapi - intentionally vulnerable app

> ⚠️ **DELIBERATELY INSECURE. Local only.** Binds `127.0.0.1`, holds no real
> data. Built to benchmark DAST/SAST/LLM security tools. Never deploy publicly.

**TaskFlow FastAPI** is a small multi-tenant task/blog app (FastAPI + Jinja2 +
SQLAlchemy/Postgres + MinIO + Mailpit) built from
[`../../benchmark-plans/fastapi.md`](../../benchmark-plans/fastapi.md). It keeps
the shared Acme/Globex seed and plants Python/FastAPI-specific bugs next to
safe-shaped near-misses.

**Two research-grade classes.** `CLASSPOLL-001` (CWE-1321): Python *class pollution* - a recursive `setattr` merge walks `__class__` to mutate class-level defaults process-wide (POST `/api/flags/merge` then GET `/api/flags/state`). `JWTCONF-001` (CWE-347): RS256->HS256 *algorithm confusion* - the RS256 verifier also accepts HS256 tokens HMAC'd with the (published) RSA public key, so an attacker forges an admin token for `/api/reports/exec-summary`.

**Agent-only surface (deep hardening).** On top of the API catalog it plants an
8-bug surface a request fuzzer cannot reach - only an agent that behaves like a
user: a **four-step signup wizard** at `/signup` (client-driven fetch to
`/api/signup/*`) with four `flow`-tier bugs (clock-derived verification code,
`role`/`org_slug` mass-assignment, complete-without-verify, draft-IDOR leaking
another signup's email + code), two browser-only bugs on the wizard page (**DOM
XSS** via `location.hash`, a **postMessage** sink), and a hidden `eval()` report
builder (`CODEINJ`, CWE-94 - reaches `os.environ`) referenced only from the panel
the wizard fetches after an **Advanced** click. Those 8 are tiered
`flow`/`interaction`/`js-runtime`; the pre-existing REST catalog stays
`static-html`, so `recall by discovery tier` shows how far past the fuzzable API a
tool gets. The browser PoCs drive the shared `dynast-bench/tools/browser/` image.

## Layout

```text
fastapi/
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

**Status: validated - 25/25 exploitable on `vuln/`, 25/25 fixed on `safe/`, and
25/25 exploitable in standalone `vuln` mode.**

## Planted vulnerability clusters

The implementation follows the FastAPI catalog with 25 planted bugs and 4
near-misses: weak auth/JWT/reset tokens, IDOR/BFLA/mass assignment, SQLi and
second-order SQLi, Jinja2 SSTI, command injection, pickle/YAML/XML unsafe import,
SSRF, traversal, CORS/redirect/debug leaks, stored/reflected XSS, unrestricted
upload, presign-style attachment IDOR, billing logic flaws, invite race, and
default credentials. Full metadata is in
[`ground-truth/VULNERABILITIES.yaml`](ground-truth/VULNERABILITIES.yaml).
