# Go Version - Vulnerable App Plan

> ⚠️ **Intentionally vulnerable. Local only.** Binds `127.0.0.1`, ships a LOUD
> banner, carries no real data. Built to benchmark DAST/SAST/LLM security tools.

**Angle:** the **SSRF + command-injection + exposed-debug-surface** app, with a
strong seam of Go-specific footguns (`text/template` SSTI, `math/rand` tokens,
public `/debug/pprof`, an unsynchronized goroutine race). Prometheus/Grafana are
in the compose so metrics/label leakage and default-cred exposure are in scope.

## Services (4 containers) - independent `docker-compose.yml`

| Service    | Image                     | Host port | Purpose                         |
|------------|---------------------------|-----------|---------------------------------|
| app        | build ./app (multi-stage) | 3000      | Go web app (SSR) + JSON API     |
| postgres   | postgres:16.4             | 5432      | Data                            |
| prometheus | prom/prometheus:v2.54.1   | 9090      | Scrapes app `/metrics`          |
| grafana    | grafana/grafana:11.2.0    | 3001      | Dashboard (default-cred bug)    |

## Stack choices (bugs live inside these idioms)

- Router **chi**; templates: a mix of `html/template` (safe) and, on the report
  page, `text/template` (the SSTI/XSS sink - auto-escaping is OFF in `text/`)
- DB: **pgx**; parameterized in most places, `fmt.Sprintf` into the query in the
  planted SQLi sites
- Auth: bcrypt + **gorilla/sessions** with a **hardcoded** cookie store key;
  a JWT path (`golang-jwt`) with `alg:none` accepted
- Tokens: password-reset + invite tokens minted from `math/rand` (not
  `crypto/rand`) - predictable
- Uploads: avatar to a local volume served at `/uploads/*` via
  `http.ServeFile(filepath.Join(dir, r.URL.Query().Get("name")))` (traversal)
- Metrics: **promhttp** at `/metrics`; a label carries the raw username (info
  leak); `/debug/pprof/*` mounted on the public app port
- Features: "fetch preview" (SSRF), "export report" (`exec.Command("sh","-c")`)

## Domain model

Standard shared domain with cross-tenant `user2` (org Globex) for IDOR PoCs.

## Vulnerability catalog (~28 planted bugs)

| Service · Feature | Planted bug | CWE | OWASP | Sev | Diff | Taint |
|---|---|---|---|---|---|---|
| app · login | No rate limit → brute force | 307 | A07 | M | E | in-file |
| app · login | User enumeration (distinct errors) | 204 | A07 | L | E-M | in-file |
| app · session | Hardcoded `gorilla/sessions` key | 798/321 | A02 | H | M | in-file |
| app · JWT | `alg:none` accepted; `exp` unchecked | 347 | A07 | H | M | in-file |
| app · reset/invite | `math/rand` tokens (predictable) | 338/330 | A02 | M | M | cross-file |
| app · posts/tasks | IDOR/BOLA - no org check | 639/863 | A01 | H | E-M | in-file |
| app · /admin/* | Missing function-level authz | 862 | A01 | M | M | in-file |
| app · PATCH /users/me | Mass assignment sets `role` (struct decode) | 915 | A01 | M | M | in-file |
| app · /posts/search | SQLi via `fmt.Sprintf` into query | 89 | A03 | H | E | in-file |
| app · report query | **Second-order** SQLi via stored name | 89 | A03 | H | H | cross-file |
| app · report render | **SSTI/XSS** via `text/template` on user input | 1336/79 | A03 | H | M-H | cross-file |
| app · report export | Command injection `exec.Command("sh","-c",…)` | 78 | A03 | C | M | in-file |
| app · fetch preview | **SSRF** → internal svc / `169.254.169.254` | 918 | A10 | H | M-H | cross-service |
| app · attachments | Path traversal (`filepath.Join` no clean) | 22 | A01 | M | M | in-file |
| app · archive import | **Zip slip** on extract | 22 | A08 | H | M-H | in-file |
| app · login `?next=` | Open redirect | 601 | A01 | L | E | in-file |
| app · CORS | Reflects `Origin` + credentials | 942 | A05 | M | M | in-file |
| app · config | Hardcoded DB/JWT secrets in source | 798 | A05 | M | E | in-file |
| app · errors | Stack traces / `err.Error()` echoed to client | 209 | A05 | L | E | in-file |
| app · comments | Stored XSS via `template.HTML(userInput)` | 79 | A03 | M | E-M | in-file |
| app · search page | Reflected XSS (unescaped `text/template`) | 79 | A03 | M | E | in-file |
| app · forms | CSRF (cookie auth, no token) | 352 | A01 | M | M | in-file |
| app · billing/seats | Integer overflow / negative seats | 190/840 | A04 | M | M | in-file |
| app · invites | **Race condition** exceeds seat limit (no mutex) | 362 | A04 | H | H | in-file |
| app · `/debug/pprof` | Debug endpoints exposed unauthenticated | 489/200 | A05 | M | E | in-file |
| app · `/metrics` | Sensitive label (username/email) leak | 200/532 | A09 | L | M | in-file |
| grafana | Default `admin/Admin123!`, anon view on | 1392/798 | A05 | M | E | config |
| seed data | Default `admin/admin` service creds | 798 | A07 | M | E | in-file |

## Stack-specific highlights (only make sense in Go)

- **`text/template` vs `html/template`** - the report page uses `text/template`,
  so `{{.}}` and any user data render **unescaped** (XSS), and constructing a
  template from a user string is full SSTI. The near-miss: the post page uses
  `html/template` correctly.
- **`math/rand` for secrets** - reset/invite tokens use `math/rand` seeded from a
  fixed value (deterministic → predictable). Safe twin uses `crypto/rand`.
- **`exec.Command("sh","-c", "wkhtmltopdf "+userArg)`** - the export shell-out;
  safe twin passes an arg slice with no shell.
- **Public `/debug/pprof`** - `net/http/pprof`'s `init()` registers handlers on
  `http.DefaultServeMux`; wiring that mux to the public port leaks heap/goroutine
  dumps and enables profiling DoS. Classic Go misconfig.
- **Goroutine race on the seat counter** - `count++` across goroutines with no
  mutex/transaction; `go run -race` and a parallel PoC both expose it.
- **Zip slip** - `filepath.Join(dest, f.Name)` on a crafted archive with
  `../../` entries writes outside `dest`.

## Near-misses (safe beside vulnerable)

- `searchPosts` (`fmt.Sprintf` SQLi) beside `listPosts` (`$1` placeholders).
- `renderReport` (`text/template`) beside `renderPost` (`html/template`).
- `serveAttachment` (raw `filepath.Join`) beside `serveAvatar`
  (`filepath.Clean` + `strings.HasPrefix` containment check).
- `newResetToken` (`math/rand`) beside `newSessionID` (`crypto/rand`).

## Logic-only bugs

- **Invite race (CWE-362):** unsynchronized read-modify-write on seats; PoC
  fires N goroutines/curls and asserts final seats > limit. `-race` build flags
  it at the source level too.
- **Seat overflow (CWE-190):** `int32` seat math wraps on a huge `quantity`.

## Ground truth & scoring

- `VULNERABILITIES.yaml` per row; `verify/` PoCs (`ssrf_fetch.sh` targets
  `http://169.254.169.254/…` and the internal metrics port; `pprof_open.sh`
  GETs `/debug/pprof/goroutine`; `race_invite.sh` parallel curls; `zipslip.sh`
  uploads a crafted zip). PASS on `main-vuln`, FAIL on `main-safe`.
- Scorer emits P/R/F1 + per-CWE. `ground-truth/` is `.dockerignore`d.

## Patched twin (`main-safe`)

Rate limit + constant-time login, env-loaded random session key, verified JWT,
`crypto/rand` tokens, org checks, `@requireRole`, `$N` params, fixed-template
render with `html/template`, `exec.Command` arg slice, SSRF allowlist +
metadata-IP block, `filepath.Clean` containment, zip-slip guard, redirect
allowlist, locked CORS, env secrets, generic error pages, escaped output, CSRF
tokens, validated seat math, mutex/`SELECT … FOR UPDATE` seat reservation,
`/debug/pprof` gated behind auth + bound to localhost, metrics labels scrubbed,
Grafana creds rotated + anon off.

## Compose sketch (independent; 127.0.0.1 only)

```yaml
name: vuln-golang
services:
  app:
    build: ./app
    ports: ["127.0.0.1:${DYNAST_PORT:-13311}:3000"]
    environment:
      DATABASE_URL: postgres://bench:bench@postgres:5432/bench
      SESSION_KEY: "hardcoded-32-byte-key-do-not-use"   # planted CWE-798
      EXPOSE_PPROF: "true"                                # planted CWE-489
    depends_on: { postgres: { condition: service_healthy } }
  postgres:
    image: postgres:16.4
    environment: { POSTGRES_USER: bench, POSTGRES_PASSWORD: bench, POSTGRES_DB: bench }
    healthcheck: { test: ["CMD-SHELL", "pg_isready -U bench"] }
  prometheus:
    image: prom/prometheus:v2.54.1
    volumes: ["./infra/prometheus.yml:/etc/prometheus/prometheus.yml:ro"]
    ports: ["127.0.0.1:${DYNAST_PORT_PROMETHEUS_9090:-13312}:9090"]
  grafana:
    image: grafana/grafana:11.2.0
    environment:
      GF_SECURITY_ADMIN_USER: admin
      GF_SECURITY_ADMIN_PASSWORD: Admin123!          # planted weak cred
      GF_AUTH_ANONYMOUS_ENABLED: "true"               # planted misconfig
    ports: ["127.0.0.1:${DYNAST_PORT_GRAFANA_3000:-13313}:3000"]
```

## Build milestones

1. Compose + healthchecks + Makefile; migrations + seed (cross-tenant + weak
   service cred) green.
2. Auth (session + JWT) with planted weak-key / alg:none / rate-limit /
   enumeration bugs + safe twins.
3. Posts CRUD + IDOR + `fmt.Sprintf` SQLi (+ near-miss); comments/search XSS.
4. Reports: `text/template` SSTI, second-order SQLi, `sh -c` export, SSRF fetch,
   zip-slip import - each with a safe twin.
5. Billing/invite logic bugs; traversal/redirect/CORS/pprof/metrics misconfigs;
   Grafana defaults.
6. `VULNERABILITIES.yaml` + `verify/` PoCs; all PASS on `main-vuln`; branch
   `main-safe`, fix all, all PoCs FAIL; wire scorer.
