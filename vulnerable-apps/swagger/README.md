# Swagger / OpenAPI vulnerable benchmark app

⚠️ **DELIBERATELY INSECURE. LOCAL ONLY.** This app plants Swagger/OpenAPI and API-inventory vulnerabilities for scanner benchmarking. Do not expose it publicly.

This implementation focuses on a practical representative subset of `benchmark-plans/swagger.md`:

- public Swagger UI/ReDoc/schema and vulnerable `?url=` spec loading
- leaked OpenAPI examples/extensions/internal hostnames
- shadow debug APIs, zombie `/api/v0/`, and spec/code drift
- default/forgotten authorization, BOLA/BFLA, overposting, sensitive serializer output
- ordering SQL injection, debug/secret leaks, Host/CORS/JWT mistakes
- SSRF to an internal partner API and unsafe YAML consumption
- upload path traversal, seat/quantity logic abuse, and bearer-token log leakage

Run with the standard per-app interface:

```bash
make up
make verify
make safe
make verify-safe
make solo
```

The app binds host ports only to `127.0.0.1`. Ground truth lives outside Docker build contexts in `ground-truth/`.
