# Weird-Proxies Version - Vulnerable App Plan

> ⚠️ **Intentionally vulnerable. Local only.** Binds `127.0.0.1`, ships a LOUD
> banner, carries no real data. Built to benchmark DAST/SAST/LLM security tools.

**Angle:** the **reverse-proxy ACL-bypass** app - a different shape from the rest
of the suite. Instead of one framework with in-code bugs, it stands up ONE tiny
internal origin behind **three reverse proxies at once** (nginx, Apache, Traefik),
each with its own access-control list for the protected paths. Every planted bug
is a **proxy-vs-origin normalization discrepancy** (from
[GrrrDog/weird_proxies](https://github.com/GrrrDog/weird_proxies)): a request the
proxy forwards but the origin resolves back to a protected path - or a client
header the proxy fails to strip. Like `network`, the vuln↔safe delta is
**config only**; no application source changes.

## Services (4 containers) - independent `docker-compose.yml`

| Service | Image            | Host port | Purpose                                  |
|---------|------------------|-----------|------------------------------------------|
| nginx   | build ./nginx    | 13311     | Front proxy #1 (the app under test)      |
| apache  | build ./apache   | 13312     | Front proxy #2 (httpd + mod_proxy)       |
| traefik | build ./traefik  | 13313     | Front proxy #3 (v3, file provider)       |
| origin  | build ./origin   | (internal)| Node backend - never published           |

## Structure

```
vuln/
  origin/server.mjs     permissive-normalizing Node backend + the marker
  origin/Dockerfile
  nginx/default.conf     exact-match + case-sensitive + header-passthrough ACL
  nginx/Dockerfile
  apache/proxy-bench.conf anchored LocationMatch + case-sensitive + header ACL
  apache/Dockerfile
  traefik/traefik.yml     static config (entrypoint :80, file provider)
  traefik/dynamic.yml     PathPrefix block router + deny middleware
  traefik/Dockerfile
  docker-compose.yml
  Dockerfile.standalone   all three proxies + origin in one image (solo)
  entrypoint.standalone.sh
```

## The origin (the "backend that normalizes more than the proxy")

`origin/server.mjs` is intentionally permissive: it percent-decodes (up to twice),
swaps `\`→`/`, strips `;params`, resolves `.`/`..`, collapses `//`, case-folds,
and drops a trailing slash before routing. So `/admin/`, `/admin%2f`, `/ADMIN`,
`//admin`, `/./admin`, `/%2e/admin` all resolve to `/admin` at the origin. It has
**no ACL of its own** - the proxies are the security boundary - and it holds
`GLOBEX-CONFIDENTIAL-MARKER-7f3a` behind `/admin`, `/internal/*`, `/metrics`. It
also trusts an `X-Internal-Auth: trusted` header a correct proxy must strip.

The origin is **identical in vuln and safe**. Only the proxy configs change.

## Vulnerability catalog (16 planted bypasses + 4 near-misses)

| Proxy | Planted bypass | Trick | CWE | Sev |
|-------|----------------|-------|-----|-----|
| nginx | `/admin/` | exact-match `location = /admin` | 436 | H |
| nginx | `/admin%2f` | %2f kept encoded, missed by exact match | 436 | H |
| nginx | `/metrics/` | exact-match `location = /metrics` | 436 | M |
| nginx | `/INTERNAL` | case-sensitive prefix | 436 | H |
| nginx | header | forwards client `X-Internal-Auth` | 807 | H |
| apache | `/admin/` | anchored `LocationMatch "^/admin$"` | 436 | H |
| apache | `/ADMIN` | case-sensitive `LocationMatch` | 436 | H |
| apache | `/INTERNAL` | case-sensitive `<Location>` | 436 | H |
| apache | `/metrics/` | anchored `^/metrics$` | 436 | M |
| apache | header | forwards client `X-Internal-Auth` | 807 | H |
| traefik | `//admin` | Traefik doesn't collapse `//` | 436 | H |
| traefik | `/./admin` | Traefik doesn't resolve `/./` | 436 | H |
| traefik | `/%2e/admin` | Traefik doesn't decode `%2e` | 436 | H |
| traefik | `//internal` | `//` vs `PathPrefix(/internal)` | 436 | H |
| traefik | `/ADMIN` | case-sensitive `PathPrefix` | 436 | H |
| traefik | header | forwards client `X-Internal-Auth` | 807 | H |

All are **pre-auth**, taint **cross-service** (the flaw spans proxy + origin), and
map to **A01 Broken Access Control** (the normalization ones) / **CWE-807 reliance
on untrusted input** (the header ones).

## Near-misses (correctly blocked in BOTH variants - flagging them is an FP)

- **nginx** collapses `//` and resolves `/./`, so `//admin` and `/./admin` are
  blocked on nginx even though they beat Traefik.
- **Apache** likewise normalizes `//` and `/./`.
- **Traefik**'s `PathPrefix` is a prefix match, so `/admin/` is blocked on Traefik
  even though the trailing-slash trick beats nginx and Apache.

The discriminator across the three proxies is the point: the *same* payload is a
bypass on one and a correctly-handled request on another.

## Patched twin (`safe/`) - config only

- **nginx**: case-insensitive regex `location ~* ^/(admin|internal|metrics)(...)`
  covering trailing-slash / `%2f` / case, plus `proxy_set_header X-Internal-Auth ""`.
- **Apache**: `(?i)`-prefixed `LocationMatch` for each protected name, plus
  `RequestHeader unset X-Internal-Auth`.
- **Traefik**: `PathRegexp("(?i)(admin|internal|metrics)")` (Traefik doesn't
  normalize, so the rule must) + a `strip-internal` headers middleware.

`diff -ru vuln safe` touches exactly `nginx/default.conf`,
`apache/proxy-bench.conf`, `traefik/dynamic.yml` and nothing else.

## Ground truth & scoring

- `VULNERABILITIES.yaml` per row; `ground-truth/verify/*.sh` PoCs use
  `curl --path-as-is` and derive the Apache/Traefik ports from `$TARGET`
  (`:13312`, `:13313`) or `WEIRDPROXY_APACHE` / `WEIRDPROXY_TRAEFIK`. Exit `0`
  when the marker leaks (bypass) - PASS on vuln, FAIL on safe.
- `ground-truth/` is never baked into an image.

## Standalone single-image (`make solo`)

One image (Debian + nginx + apache2 + the Traefik binary + Node) runs all four
processes on internal ports 8080/8081/8082/9000; the entrypoint aliases `origin`
→ `127.0.0.1` and patches only the listen ports (the buggy ACL directives are
untouched). `make solo` publishes nginx→13311, apache→13312, traefik→13313, so the
PoCs run unchanged.

## Build milestones

1. Origin backend (permissive normalization + marker + health) - internal only.
2. Three proxy configs, each blocking the protected paths with a native-but-flawed
   ACL; compose with nginx as the app-under-test.
3. Empirically probe a battery of encodings against each proxy; record which leak
   (bugs) and which are correctly blocked (near-misses).
4. PoCs from the observed bypasses; `VULNERABILITIES.yaml`.
5. Harden the three configs in `safe/`; `make validate` (vuln→all bypass,
   safe→all blocked) green.
6. `Dockerfile.standalone` + `entrypoint.standalone.sh`; `make solo` green.
