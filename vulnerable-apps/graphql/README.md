# GraphQL vulnerable benchmark app

This app is intentionally vulnerable and must be run only on localhost. It is a pure GraphQL API benchmark target: most behavior is behind `POST /graphql`, with a REST verification API only for the benchmark harness.

## Local endpoints

- App: `http://127.0.0.1:13311`
- GraphQL: `POST /graphql`, `GET /graphql`, and WebSocket `/graphql/ws`
- Safe near-miss endpoint: `/graphql/public`
- Verification: `/api/_verify/health`, `/api/_verify/user`, `/api/_verify/post`

## Commands

```bash
make up          # vulnerable variant
make verify      # PoCs should all exploit vuln/
make safe        # patched twin
make verify-safe # PoCs should all fail against safe/
make solo        # one self-contained image
```

The app binds host ports to `127.0.0.1` only. `ground-truth/` is outside both Docker build contexts and is not copied into images.

## Seed

The seed follows the shared benchmark domain: Acme and Globex tenants; `admin@bench.local/Admin123!`, `editor@bench.local/Editor123!`, `user1@bench.local/User123!`, `user2@bench.local/User123!`, and weak `admin/admin` service credentials in the vulnerable variant. The Globex draft post contains `GLOBEX-CONFIDENTIAL-MARKER-7f3a`.
