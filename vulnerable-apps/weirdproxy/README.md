# weirdproxy - intentionally vulnerable app

> ⚠️ **DELIBERATELY INSECURE. Local only.** Binds `127.0.0.1`, holds no real
> data. Built to benchmark DAST/SAST/LLM security tools. Never deploy publicly.

**weirdproxy** puts ONE tiny internal origin behind **three reverse proxies at
once** - **nginx**, **Apache**, and **Traefik** - each on its own host port, each
with its own ACL for the protected paths. The bugs are **proxy-vs-origin
normalization discrepancies** (inspired by
[GrrrDog/weird_proxies](https://github.com/GrrrDog/weird_proxies)): a request the
proxy forwards but the origin normalizes back to a protected path, plus a client
header a proxy fails to strip. The vuln↔safe delta is **config only** - the three
proxy config files. The origin is byte-identical in both variants.

```
             ┌── nginx   :13311  (app under test)
client ──────┼── apache  :13312
             └── traefik :13313
                     │
                     └── origin :9000  (internal only - never published)
                         serves GLOBEX-CONFIDENTIAL-MARKER-7f3a behind
                         /admin, /internal/*, /metrics
```

## Layout

```text
weirdproxy/
├── vuln/          # origin + nginx/apache/traefik configs (the vulnerable ACLs)
├── safe/          # patched twin - same origin, hardened proxy configs
├── ground-truth/  # VULNERABILITIES.yaml + verify/ PoCs (never baked into images)
└── Makefile       # up · reset · safe · verify · validate · diff · solo
```

## Run

```bash
make up          # build + start vuln/: nginx 13311, apache 13312, traefik 13313
make verify      # run PoCs; expect ALL 16 bypasses exploitable
make safe        # switch to the hardened twin
make verify-safe # run PoCs; expect ALL blocked
make validate    # vuln→all bypass, safe→all blocked
make diff        # ground-truth diff (only the 3 proxy configs differ)
make solo        # one image running all three proxies + origin
```

The health endpoint is `/api/_verify/health` (forwarded through each proxy to the
origin). PoCs use `curl --path-as-is` so the crafted path reaches the proxy
unmodified; they derive the Apache/Traefik base URLs from `$TARGET` (`:13312`,
`:13313`) or from `WEIRDPROXY_APACHE` / `WEIRDPROXY_TRAEFIK`.

## What's planted (16 bypasses + 4 near-misses)

Each proxy blocks `/admin`, `/internal/*`, `/metrics` - but:

- **nginx** - exact-match `location = /admin` (→ `/admin/`, `/admin%2f`,
  `/metrics/`), case-sensitive prefix (`/INTERNAL`), and a forwarded
  `X-Internal-Auth` header.
- **Apache** - anchored `LocationMatch "^/admin$"` (→ `/admin/`, `/metrics/`),
  case-sensitive `<Location>` (`/ADMIN`, `/INTERNAL`), forwarded header.
- **Traefik** - no path normalization, so `//admin`, `/./admin`, `/%2e/admin`,
  `//internal` and `/ADMIN` all miss `PathPrefix`, plus a forwarded header.

The **near-misses** are the tricks each proxy *does* handle correctly (nginx
collapses `//` and `/./`; Apache too; Traefik's `PathPrefix` catches the
trailing-slash that beats nginx/Apache) - flagging those is a false positive.
Full metadata is in
[`ground-truth/VULNERABILITIES.yaml`](ground-truth/VULNERABILITIES.yaml).
