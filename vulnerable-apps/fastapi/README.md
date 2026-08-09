# fastapi - intentionally vulnerable app

> ⚠️ **DELIBERATELY INSECURE. Local only.** Binds `127.0.0.1`, holds no real
> data. Built to benchmark DAST/SAST/LLM security tools. Never deploy publicly.

**TaskFlow FastAPI** is a small multi-tenant task/blog app (FastAPI + Jinja2 +
SQLAlchemy/Postgres + MinIO + Mailpit) built from
[`../../benchmark-plans/fastapi.md`](../../benchmark-plans/fastapi.md). It keeps
the shared Acme/Globex seed and plants Python/FastAPI-specific bugs next to
safe-shaped near-misses.

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
