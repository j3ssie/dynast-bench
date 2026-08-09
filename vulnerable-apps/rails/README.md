# rails - intentionally vulnerable app

> ⚠️ **DELIBERATELY INSECURE. Local only.** Binds `127.0.0.1`, holds no real
> data. Built to benchmark DAST/SAST/LLM security tools. Never deploy publicly.

**TaskFlow Rails** is a compact multi-tenant Rails 7.2 + ERB + ActiveRecord/Postgres
application with a machine-checkable ground truth. It implements a practical
representative subset of the Rails catalog in `../../benchmark-plans/rails.md`:
strong-params overposting, unsafe YAML import, `render inline:` ERB SSTI, Ruby
regex anchor bypass, skipped authorization, raw SQLi, second-order SQLi, SSRF,
command injection, unsafe reflection, default credentials/hardcoded secrets,
IDOR, XSS, CSRF/open-redirect/CORS/traversal, upload, billing, and invite-race
logic bugs.

## Layout

```
rails/
├── vuln/          # vulnerable Rails variant (Docker build context)
├── safe/          # patched twin; only YAML-named bug lines differ
├── ground-truth/  # VULNERABILITIES.yaml + executable PoCs (never in images)
└── Makefile       # up · reset · safe · verify · validate · solo · diff
```

## Run

```bash
make up          # build + start vuln/ on http://127.0.0.1:13311
make verify      # run all PoCs; expect ALL exploitable
make safe        # switch to patched twin (shared host port)
make verify-safe # run all PoCs; expect ALL fixed
make validate    # full vulnerable/safe loop
make solo        # all-in-one image with embedded Postgres + internal SSRF sink
make diff        # intended vulnerable-vs-safe patch lines
```

All host bindings are `127.0.0.1` only. The compose topology uses nginx as the
entry point and keeps Postgres/internal sink on the private compose network. The
standalone image aliases compose service names to localhost so PoCs use the same
URLs in both modes.

## Seed data

The shared benchmark domain is preserved: Acme and Globex tenants, users
`admin@bench.local/Admin123!`, `editor@bench.local/Editor123!`,
`user1@bench.local/User123!`, `user2@bench.local/User123!`, plus weak service
credentials `admin/admin`. The Globex draft post contains
`GLOBEX-CONFIDENTIAL-MARKER-7f3a` and should only appear through planted access
control or injection bugs.

## Status

Static/syntax checks were run locally by the implementing agent. Docker compose
and default-port validation were intentionally not run per task instruction.
