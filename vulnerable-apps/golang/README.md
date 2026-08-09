# Go vulnerable benchmark app

⚠️ **INTENTIONALLY VULNERABLE. LOCAL ONLY. DO NOT DEPLOY.**

This is the Go/Golang member of `DynAST-Bench`. The vulnerabilities are the product: the `vuln/` variant intentionally contains insecure Go web-application patterns, while `safe/` is the patched twin with minimal fixes for the same routes.

The app binds published ports to `127.0.0.1` only and keeps `ground-truth/` outside Docker build contexts.

## Run

```bash
make up APP=golang
make verify APP=golang
make safe APP=golang
make verify-safe APP=golang
```

The stack publishes 13311 (app), 13312 (Postgres), 13313 (Prometheus) and 13314
(Grafana). `dynast-bench start golang` relocates any of those that are busy;
the `make` targets do not, so use them only when those ports are free.

## Contents

- `vuln/` - Go chi app with PostgreSQL, Prometheus/Grafana side services, pprof, SSRF target support, and planted bugs.
- `safe/` - patched twin; only vulnerability-fix/config lines differ from `vuln/`.
- `ground-truth/` - machine-readable vulnerability catalog plus executable PoCs. A PoC exits `0` when the target is vulnerable and non-zero when fixed.

Seed users match the benchmark convention: `admin@bench.local/Admin123!`, `editor@bench.local/Editor123!`, `user1@bench.local/User123!`, `user2@bench.local/User123!` (Globex), plus the vulnerable default service credential `admin/admin` in `vuln/` only.
