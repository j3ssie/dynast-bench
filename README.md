# DynAST-Bench

_A DAST benchmark of intentionally-vulnerable apps with ground-truth answer keys for scoring scanners._

> ⚠️ **This repository contains DELIBERATELY INSECURE applications.** They exist
> only to benchmark security tooling - DAST scanners, SAST engines, and LLM
> security agents. Every app binds to `127.0.0.1`, ships a LOUD banner, and holds
> no real data. **Never deploy any of this on a public network.**

A suite of **19 intentionally-vulnerable apps**, one per stack, each with a
documented, machine-checkable **ground truth**. The point is to measure how well
a scanner or agent (a) finds the planted bugs, (b) ignores the safe near-miss
code sitting right next to them, and (c) doesn't hallucinate findings on the
patched twin.

## The apps at a glance

**19 apps · 480 planted vulnerabilities · 119 near-misses · 478 runnable PoCs.**
Every app boots on `127.0.0.1:13311`, ships a `vuln/`+`safe/` twin pair and a
single-image `--solo` build. `dynast-bench list` prints this table live.

| App | Stack | Datastore | Vulns | Near-miss | Docs |
|-----|-------|-----------|------:|----------:|------|
| [aspnet](vulnerable-apps/aspnet) | C# / ASP.NET Core Razor Pages | SQL Server | 28 | 12 | [plan](benchmark-plans/aspnet.md) |
| [fastapi](vulnerable-apps/fastapi) | Python / FastAPI + Jinja2 | Postgres | 26 | 5 | [plan](benchmark-plans/fastapi.md) |
| [gin](vulnerable-apps/gin) | Go / Gin | Postgres | 11 | 6 | [readme](vulnerable-apps/gin/README.md) |
| [golang](vulnerable-apps/golang) | Go / chi | Postgres | 26 | 4 | [plan](benchmark-plans/golang.md) |
| [graphql](vulnerable-apps/graphql) | Node / GraphQL 16 API-only | Postgres | 31 | 6 | [plan](benchmark-plans/graphql.md) |
| [jsp](vulnerable-apps/jsp) | Java / JSP + Servlets (Tomcat) | Postgres | 28 | 6 | [plan](benchmark-plans/jsp.md) |
| [laravel](vulnerable-apps/laravel) | PHP 8.3 / Laravel 11 + Blade | MySQL | 25 | 7 | [plan](benchmark-plans/laravel.md) |
| [llmagent](vulnerable-apps/llmagent) | Node / Fastify + AI SDK + MCP | Postgres | 29 | 8 | [plan](benchmark-plans/llmagent.md) |
| [llmchat](vulnerable-apps/llmchat) | Python / FastAPI + LangChain RAG | Postgres+pgvector | 30 | 9 | [plan](benchmark-plans/llmchat.md) |
| [nestjs](vulnerable-apps/nestjs) | Node / NestJS + Handlebars | Postgres | 23 | 6 | [plan](benchmark-plans/nestjs.md) |
| [network](vulnerable-apps/network) | Simulated multi-host network range | mixed fleet | 32 | 5 | [plan](benchmark-plans/network.md) |
| [nextjs](vulnerable-apps/nextjs) | Node / Next.js 15 **(reference impl)** | Postgres | 23 | 9 | [plan](benchmark-plans/nextjs.md) |
| [php](vulnerable-apps/php) | PHP / procedural LAMP | MySQL | 21 | 5 | [plan](benchmark-plans/php.md) |
| [rails](vulnerable-apps/rails) | Ruby / Rails 7.2 | Postgres | 26 | 6 | [plan](benchmark-plans/rails.md) |
| [springboot](vulnerable-apps/springboot) | Java / Spring Boot + Thymeleaf | Postgres | 30 | 4 | [plan](benchmark-plans/springboot.md) |
| [swagger](vulnerable-apps/swagger) | OpenAPI / Swagger UI + spec loading | Postgres | 19 | 5 | [plan](benchmark-plans/swagger.md) |
| [websocket](vulnerable-apps/websocket) | Node 22 / `ws` + Socket.IO realtime | Postgres | 28 | 6 | [plan](benchmark-plans/websocket.md) |
| [weirdproxy](vulnerable-apps/weirdproxy) | nginx + Apache + Traefik over one origin | none | 16 | 4 | [plan](benchmark-plans/weirdproxy.md) |
| [wordpress](vulnerable-apps/wordpress) | PHP / WordPress + custom plugin | MySQL | 28 | 6 | [plan](benchmark-plans/wordpress.md) |

Extra sidecars per stack (Mailpit, MinIO, Redis, Jenkins, Prometheus, Ollama, …)
are listed in [The apps](#the-apps) below.

The per-stack **design docs live in [`benchmark-plans/`](benchmark-plans/)** -
start there for the full vulnerability catalog of each app. This README is the
operational guide: how the repo is laid out and how to run and score an app.

## Repository structure

```
dynast-bench/
├── README.md             # you are here - overview, safety, run/score guide
├── Makefile              # top-level runner: list / run / verify / validate / solo any app
├── benchmark-plans/      # per-stack design docs (the vulnerability catalogs)
├── dynast-bench/           # the `dynast-bench` CLI + scorer (Bun/TS)
└── vulnerable-apps/      # the 19 apps - each a separated, self-contained folder
    ├── _template/        # skeleton; copy it to start a new app
    ├── fastapi/  golang/  nextjs/  nestjs/  springboot/
    └── rails/  wordpress/  php/  jsp/  aspnet/  ...
```

## Running apps (`dynast-bench` CLI)

The CLI is the easiest way to drive the suite - it health-gates boots, arbitrates
the shared ports, and speaks `--json` so a scanner harness can consume it.
Needs [Bun](https://bun.sh) 1.2+ and Docker.

```bash
make install                             # compile the CLI + link it into ~/.bun/bin
                                         # (BIN_DIR=/somewhere/else to pick the dir)

dynast-bench list                        # every app: vulns, PoCs, near-misses, what's up
dynast-bench start nextjs                # build + boot, wait for health, print the URL
dynast-bench verify nextjs               # run the ground-truth PoCs (expect all exploitable)
dynast-bench validate nextjs             # twin loop: vuln all-exploitable → safe all-fixed
dynast-bench status                      # variant, mode, target, health
dynast-bench stop --all                  # stop everything
dynast-bench clean --all --images --yes  # reclaim containers, volumes, networks, images

dynast-bench start nextjs --variant safe # the patched twin (false-positive run)
dynast-bench start --all --solo          # whole fleet in parallel, one port each
dynast-bench run nextjs -- my-scanner --url '$TARGET'   # start → scan → stop
```

Full reference: [`dynast-bench/README.md`](dynast-bench/README.md).

### Ports

Everything lives in a quiet slice of the ephemeral range, so the suite doesn't
fight the usual 3000/8000/8080/5432 crowd:

| range | what |
|-------|------|
| `13311` | the app under test - **the URL you point a scanner at** |
| `13312`–`13319` | that stack's sidecars (mailpit, phpMyAdmin, Jenkins, Prometheus, …) |
| `13320`–`13399` | auto-assigned solo ports (`start --all --solo`) |
| `13400`–`13499` | relocation pool |

If anything is already listening on a port it wants, `dynast-bench start` leaves
it alone and publishes that service from the relocation pool instead, then
prints (and `--json`-reports) the real URL. Nothing ever binds beyond
`127.0.0.1`. `dynast-bench doctor` shows the current picture; `make` targets
don't relocate but honour `DYNAST_PORT=<n>`, and `--port N` pins it explicitly.

## Running apps (top-level Makefile)

The Makefiles remain the low-level contract and work standalone:

```bash
make list                  # show all apps (a [solo] tag = has a single-image build)
make run APP=nextjs        # start via compose (app + datastores)
make verify APP=nextjs     # run its ground-truth PoCs (expect all exploitable)
make validate APP=nextjs   # full twin loop: vuln all-pass -> safe all-fixed
make down APP=nextjs        # stop it
make solo APP=nextjs       # run as ONE self-contained image - no compose needed
make solo-down APP=nextjs  # stop the standalone image
# shorthands: make run-nextjs   make validate-nextjs
```

Two ways to run every app:
- **Compose** (`make run`) - the canonical multi-service topology the ground
  truth targets (app + Postgres/Redis/etc. as separate containers).
- **Standalone** (`make solo`) - one self-contained image per app
  (`vuln/Dockerfile.standalone`) with the datastores + an internal SSRF sink
  embedded, so `docker build` + `docker run` works with no compose. Behaviour
  and PoCs are identical (compose service names are aliased to `127.0.0.1`).

The root stays deliberately small: this README, the design guide, the shared
tooling, and the apps. Everything operational for a given app is inside that
app's own folder.

## Per-app anatomy

Every app under `vulnerable-apps/` has the identical shape:

```
vulnerable-apps/<stack>/
├── README.md            # LOUD banner + run notes
├── Makefile             # up · reset · safe · verify · score · diff  (uniform interface)
├── vuln/                # the vulnerable variant - this is what you scan by default
│   ├── docker-compose.yml   # independent; binds 127.0.0.1 only
│   ├── app/                 # application source; the planted bugs live here
│   └── db/seed.sql          # seed incl. a cross-tenant user + a weak default cred
├── safe/                # the patched twin - same app, every planted bug fixed
│   ├── docker-compose.yml
│   ├── app/
│   └── db/seed.sql
└── ground-truth/        # the answer key - see "Ground truth" below
    ├── VULNERABILITIES.yaml
    ├── verify/          # one runnable PoC per bug
    └── expected/        # optional golden normalized findings
```

## The vuln/safe twin

Each app ships **two separated variant folders** rather than git branches or
patch files:

- **`vuln/`** - the app with every planted bug. The default target; what a
  scanner points at.
- **`safe/`** - the *same* app with every planted bug fixed and nothing else
  changed (parameterized queries, escaped output, added authz, safe
  deserializers, …).

**`diff -ru vulnerable-apps/<stack>/vuln vulnerable-apps/<stack>/safe` is the ground truth.** It must
touch exactly the lines named in `ground-truth/VULNERABILITIES.yaml` and nothing
else. Scanning the `safe/` variant measures a tool's **false-positive rate**:
every finding there is a false alarm, because the twin is clean by construction.

Because each variant's Docker **build context is its own folder** (`vuln/` or
`safe/`), the app's `ground-truth/` sits *outside* every build context and
**cannot be baked into an image** - the answer key can't leak into the running
app, by construction.

## Ground truth (`ground-truth/`)

`VULNERABILITIES.yaml` records one entry per planted bug:

```yaml
- id: SQLI-001
  variant_paths:                 # same relative path in both variants
    vuln: vuln/app/routes/search.py
    safe: safe/app/routes/search.py
  symbol: search_posts
  route: "GET /posts/search?q="
  cwe: CWE-89
  owasp: "A03:2021-Injection"
  severity: high                 # info | low | medium | high | critical
  difficulty: E                  # E | E-M | M | M-H | H  (detection difficulty)
  taint: in-file                 # in-file | cross-file | cross-service
  reachability: pre-auth         # pre-auth | user | admin
  near_miss: SAFE-SQLI-001       # id of the safe twin planted nearby
  match:                         # machine anchors for the scorer (generated)
    http: { method: GET, path: "/posts/search", params: [q] }
    file: { path: vuln/app/routes/search.py, symbol: search_posts, lines: [18, 24] }
    markers: [GLOBEX-CONFIDENTIAL-MARKER-7f3a]
  poc: ground-truth/verify/sqli_001.sh
```

`verify/` holds one runnable PoC per bug - it exits **0 against `vuln/`** and
**non-zero against `safe/`**. That's the executable definition of "the bug is
real (and actually fixed in the twin)."

## Shared tooling (`dynast-bench/`, Bun/TypeScript)

One toolchain, used by every app, so cross-stack results are comparable:

- **`dynast-bench.ts`** - the CLI: start/stop/reset/clean, health gating, port
  arbitration, PoC verification, scoring, `--json` for harnesses.
- **`src/schema/`** - types + validators for the finding format and
  `VULNERABILITIES.yaml`, the CWE-family table used for partial credit, and the
  path/route/file normalizers both sides of a comparison go through.
- **`src/normalize/`** - adapters converting raw scanner output (OWASP ZAP, SARIF
  from Semgrep/CodeQL/Snyk, nuclei, Burp XML, nmap XML) into that format. The
  format is auto-detected, so `score` takes native output directly.
- **`src/scorer/`** - matches findings against the answer key and emits
  **precision / recall / F1**, recall per difficulty / severity / reachability /
  taint / CWE, a **discrimination** score over the near-misses, and a duplicate
  (noise) ratio.

```
dynast-bench verify <app>                # run the app's ground-truth PoCs
dynast-bench score  <app> findings.json  # findings → P/R/F1 + per-dimension recall
dynast-bench diff   <app>                # the vuln↔safe delta vs the answer key
dynast-bench check  --all                # CI gate: schema · anchors · diff scope · binds
```

Full reference - the finding schema, the matching tiers, every metric:
[`dynast-bench/README.md`](dynast-bench/README.md#scoring).

## Uniform Makefile interface (identical in every app)

```
make up       # docker compose up the vuln/ variant (127.0.0.1 only), wait for health
make reset    # down -v && up → fresh, byte-identical state
make safe     # bring up the safe/ variant instead (for false-positive runs)
make verify   # run every ground-truth PoC; expect all PASS against vuln/
make score FINDINGS=f.json    # grade a scanner's findings → P/R/F1
make diff     # the vuln↔safe delta, cross-checked against the answer key
make check    # CI gate: schema · anchors · diff scope · PoCs · 127.0.0.1 binds
```

## The apps

| App        | Stack                          | DB         | Extra services       | Design doc |
|------------|--------------------------------|------------|----------------------|------------|
| fastapi    | Python / FastAPI + Jinja2      | Postgres   | MinIO, Mailpit       | [fastapi.md](benchmark-plans/fastapi.md) |
| golang     | Go / chi                       | Postgres   | Prometheus, Grafana  | [golang.md](benchmark-plans/golang.md) |
| gin        | Go / Gin                       | Postgres   | chromium, ImageMagick (in-image) | [README](vulnerable-apps/gin/README.md) |
| nextjs     | Node / Next.js 15              | Postgres   | Redis, Mailpit       | [nextjs.md](benchmark-plans/nextjs.md) |
| nestjs     | Node / NestJS + Handlebars     | Postgres   | Redis, nginx         | [nestjs.md](benchmark-plans/nestjs.md) |
| springboot | Java / Spring Boot + Thymeleaf | Postgres   | Jenkins, Prometheus  | [springboot.md](benchmark-plans/springboot.md) |
| rails      | Ruby / Rails 7.2               | Postgres   | MinIO, nginx         | [rails.md](benchmark-plans/rails.md) |
| wordpress  | PHP / WordPress + plugin       | MySQL      | nginx, Mailpit       | [wordpress.md](benchmark-plans/wordpress.md) |
| php        | PHP / procedural LAMP          | MySQL      | phpMyAdmin, Mailpit  | [php.md](benchmark-plans/php.md) |
| jsp        | Java / JSP + Servlets (Tomcat) | Postgres   | Mailpit              | [jsp.md](benchmark-plans/jsp.md) |
| aspnet     | C# / ASP.NET Core Razor Pages  | SQL Server | Mailpit              | [aspnet.md](benchmark-plans/aspnet.md) |

Plus three **API-only** apps (GraphQL, WebSocket, Swagger/OpenAPI), a
**network-range** fleet for host/port scanners, and two **LLM** apps:

| App        | Stack                                       | DB                | Extra services                       | Design doc |
|------------|---------------------------------------------|-------------------|--------------------------------------|------------|
| llmchat    | Python / FastAPI + LangChain (RAG chatbot)  | Postgres+pgvector | Redis, Ollama, internal svc          | [llmchat.md](benchmark-plans/llmchat.md) |
| llmagent   | Node / Fastify + Vercel AI SDK + MCP (agent)| Postgres          | Redis, Ollama, partner-MCP, internal svc | [llmagent.md](benchmark-plans/llmagent.md) |

Both LLM apps run a **local model** via an internal-only Ollama container
(`gemma3:1b` for chat, `qwen2.5:1.5b` for tool calling) - no API key, no egress,
no per-run cost - and ship a scripted `LLM_BACKEND=stub` backend so the
ground-truth PoCs stay deterministic against a stochastic model.

See [`benchmark-plans/README.md`](benchmark-plans/README.md) for the shared
domain model, the OWASP-Top-10 coverage matrix, and the benchmark-design
principles (near-misses, taint distance, logic-only bugs).

## Getting started

```bash
make install                           # once: puts `dynast-bench` on your PATH
dynast-bench doctor                    # docker reachable? which ports are taken?

dynast-bench start fastapi             # boots the vuln/ variant, waits for health
dynast-bench verify fastapi            # sanity-check: every planted bug's PoC PASSes

# ...point your scanner/agent at $(dynast-bench target fastapi), collect findings.json...

dynast-bench start fastapi --variant safe   # patched twin → measures false positives
dynast-bench reset fastapi                  # restore fresh, re-seeded state
dynast-bench clean --all --yes              # give the disk back
```

Or drive one app directly with its Makefile:

```bash
cd vulnerable-apps/fastapi
make up      # vuln/ variant on 127.0.0.1
make verify  # every planted bug's PoC PASSes
make safe    # the patched twin
make reset   # fresh state
```

## Status

- **19 apps carry a complete answer key**: 480 planted vulnerabilities, 119
  near-misses, 478 PoCs, and a `Dockerfile.standalone` each (`--solo`).
  `dynast-bench list` prints the live table.
- **`nextjs` is the reference implementation** - built and validated end to end
  (23 vulns + 9 near-misses). `make validate APP=nextjs` proves every PoC
  exploitable on `vuln/` and fixed on `safe/`; `make solo APP=nextjs` runs it from
  one image. Copy its patterns.
- **`dynast-bench` CLI - built**: runs, verifies, scores and cleans any app, in
  compose or single-image mode, with `--json` for harnesses.
- **The scorer - built** (`dynast-bench/src/`): scanner output → normalized findings
  → precision/recall/F1, per-difficulty recall, a discrimination score over the
  near-misses, and separate discovery (network) and injection-channel (LLM) tracks.
  191 tests, including per-app invariants over all 19 answer keys: `make test`.
- **Known gap** (`dynast-bench check --all` reports it): `nextjs` patches a
  predictable-session-id bug (`SESSION-001`, `src/lib/session.ts`) in the safe twin
  without recording it in `VULNERABILITIES.yaml`, so a tool that finds it is scored
  as a false positive. Either add the entry or revert the fix.

## Scoring a tool

```bash
dynast-bench start nextjs --json | jq -r .target        # boot, get the URL
zap-baseline.py -t http://127.0.0.1:13311 -J zap.json   # scan
dynast-bench score nextjs zap.json --full               # grade it

# measure false positives properly: scan the patched twin too
dynast-bench start nextjs --variant safe
my-scanner --url http://127.0.0.1:13311 --out safe.json
dynast-bench score nextjs zap.json --safe safe.json
```

`score` reads a `findings/v1` file or native ZAP / SARIF / nuclei / Burp / nmap
output - the format is sniffed. See
[`dynast-bench/README.md`](dynast-bench/README.md#scoring) for the schema, the
matching tiers and every metric.
