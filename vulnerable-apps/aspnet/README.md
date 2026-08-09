# vulnerable-apps/aspnet

⚠️ **Intentionally vulnerable benchmark app. Local only. Do not deploy.**

ASP.NET Core 8 monolith-style benchmark app for DAST/SAST/LLM security tooling.
The `vuln/` variant intentionally contains .NET-flavored vulnerabilities; the
`safe/` twin applies minimal fixes on the YAML-named files. The app binds host
ports to `127.0.0.1` only, and `ground-truth/` is outside both Docker build
contexts.

## Run

```bash
make up APP=aspnet
make verify APP=aspnet
make safe APP=aspnet
make verify-safe APP=aspnet
```

Standalone single-image mode is provided for the benchmark harness:

```bash
make solo APP=aspnet VARIANT=vuln
```

## Seed data

Shared benchmark domain: Acme + Globex tenants, `user2@bench.local` in Globex,
weak `admin/admin` service credentials in the vulnerable variant, and a Globex
DRAFT post containing `GLOBEX-CONFIDENTIAL-MARKER-7f3a`.
