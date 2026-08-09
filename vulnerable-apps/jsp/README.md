# JSP/Tomcat intentionally vulnerable benchmark app

WARNING: This app intentionally contains exploitable vulnerabilities for local DAST/SAST/LLM security-tool benchmarking. Do not deploy it to any public network. Compose and solo modes bind host ports to `127.0.0.1` only.

This app is a classic Java monolith: Tomcat 10.1, Jakarta Servlets/JSP, hand-written JDBC, JSP scriptlets, an auth filter, file upload/download, XML/object import, and business workflows.

## Run

```bash
cd vulnerable-apps/jsp
make up          # vulnerable twin on http://127.0.0.1:13311
make verify      # PoCs should all be exploitable
make safe        # patched twin on the same port
make verify-safe # PoCs should all be fixed
```

The `ground-truth/` directory is outside both Docker build contexts.

Seed accounts:

- `admin@bench.local` / `Admin123!` (Acme admin)
- `editor@bench.local` / `Editor123!` (Acme editor)
- `user1@bench.local` / `User123!` (Acme user)
- `user2@bench.local` / `User123!` (Globex user)
- weak manager-style/service credential: `admin` / `admin`
