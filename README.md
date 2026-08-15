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

**19 apps · 549 planted vulnerabilities · 146 near-misses · 546 runnable PoCs ·
594 cataloged endpoints.** Every app boots on `127.0.0.1:13311`, ships a
`vuln/`+`safe/` twin pair and a single-image `--solo` build. `dynast-bench list`
prints this table live; `dynast-bench surface <app>` prints its endpoint catalog.

| App | Stack | Datastore | Vulns | Near-miss | Docs |
|-----|-------|-----------|------:|----------:|------|
| [aspnet](vulnerable-apps/aspnet) | C# / ASP.NET Core Razor Pages | SQL Server | 28 | 12 | [plan](benchmark-plans/aspnet.md) |
| [fastapi](vulnerable-apps/fastapi) | Python / FastAPI + Jinja2 | Postgres | 26 | 5 | [plan](benchmark-plans/fastapi.md) |
| [gin](vulnerable-apps/gin) | Go / Gin | Postgres | 12 | 7 | [readme](vulnerable-apps/gin/README.md) |
| [golang](vulnerable-apps/golang) | Go / chi | Postgres | 26 | 4 | [plan](benchmark-plans/golang.md) |
| [graphql](vulnerable-apps/graphql) | Node / GraphQL 16 API-only | Postgres | 31 | 6 | [plan](benchmark-plans/graphql.md) |
| [jsp](vulnerable-apps/jsp) | Java / JSP + Servlets (Tomcat) | Postgres | 28 | 6 | [plan](benchmark-plans/jsp.md) |
| [laravel](vulnerable-apps/laravel) | PHP 8.3 / Laravel 11 + Blade | MySQL | 25 | 7 | [plan](benchmark-plans/laravel.md) |
| [llmagent](vulnerable-apps/llmagent) | Node / Fastify + AI SDK + MCP | Postgres | 29 | 8 | [plan](benchmark-plans/llmagent.md) |
| [llmchat](vulnerable-apps/llmchat) | Python / FastAPI + LangChain RAG | Postgres+pgvector | 30 | 9 | [plan](benchmark-plans/llmchat.md) |
| [nestjs](vulnerable-apps/nestjs) | Node / NestJS + Handlebars | Postgres | 23 | 6 | [plan](benchmark-plans/nestjs.md) |
| [network](vulnerable-apps/network) | Simulated multi-host network range | mixed fleet | 32 | 5 | [plan](benchmark-plans/network.md) |
| [nextjs](vulnerable-apps/nextjs) | Node / Next.js 15 **(reference impl)** | Postgres | 35 | 15 | [plan](benchmark-plans/nextjs.md) |
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

## Vulnerability classes covered

Every planted bug carries a CWE and an OWASP category. Rolled up by class - each
bug counted once, under its primary CWE - the planted bugs break down roughly
as (rollup last regenerated at 480 bugs; per-app counts above are current):

| Class | CWEs | Bugs | Apps |
|-------|------|-----:|-----:|
| Sensitive data exposure (errors, logs, debug endpoints, backups, source) | 200, 209, 489, 524, 532, 538, 540, 548 | 39 | 16 |
| Default / hardcoded / leaked credentials | 321, 522, 798, 1104, 1392 | 38 | 18 |
| Missing or broken authorization (BFLA, vertical + horizontal) | 269, 284, 285, 668, 862, 863 | 37 | 18 |
| Cross-site scripting (reflected · stored · DOM) | 79 | 28 | 16 |
| Authentication bypass · weak session · JWT verification | 287, 288, 290, 306, 347, 384, 613, 614, 1385 | 28 | 13 |
| SQL injection (incl. second-order, ORDER BY, NoSQL) | 89, 943 | 27 | 17 |
| Proxy / parser interpretation conflicts (path confusion, header trust) | 345, 348, 349, 436, 441, 693, 697, 706, 807 | 27 | 10 |
| SSRF (incl. blind, redirect chains, internal-only sinks) | 918 | 20 | 17 |
| IDOR / BOLA (user-controlled object key) | 639 | 19 | 17 |
| Path traversal · LFI/RFI · zip slip | 22, 98 | 19 | 16 |
| Mass assignment / over-posting · prototype pollution | 915, 1321 | 18 | 16 |
| Brute force · missing rate limiting · resource exhaustion | 307, 400, 406, 674, 770 | 17 | 11 |
| Business-logic, pricing and quota abuse | 625, 840 | 15 | 14 |
| OS command / argument injection | 78 | 14 | 12 |
| Insecure deserialization (pickle · PHP · Java · YAML) | 470, 502 | 14 | 11 |
| CORS misconfiguration | 942 | 14 | 14 |
| Race conditions / TOCTOU | 362 | 14 | 14 |
| Open redirect | 601 | 14 | 14 |
| User & resource enumeration (observable response discrepancy) | 204, 598 | 13 | 12 |
| Code injection · SSTI · expression language | 94, 917, 1059, 1336 | 11 | 10 |
| Weak crypto & randomness · cleartext transport | 295, 319, 327, 330, 338 | 11 | 6 |
| Password reset + account recovery flaws | 184, 640 | 9 | 9 |
| Unrestricted / unsafe file upload | 434 | 9 | 9 |
| CSRF (incl. cross-site WebSocket hijacking) | 352 | 8 | 8 |
| Prompt injection & LLM tool abuse (direct · indirect · RAG) | 1427 | 7 | 2 |
| XXE / XML external entity | 611 | 5 | 5 |
| Supply chain & integrity (unsigned updates, vulnerable deps) | 494, 1035 | 2 | 2 |
| Insecure network exposure (binding, service misconfiguration) | 1327 | 2 | 1 |
| Insufficient logging / log injection | 117 | 1 | 1 |

By OWASP category (2021 Top 10 for the web apps, API Top 10 2023 where the app is
API-only):

| OWASP | Bugs | | OWASP API | Bugs |
|-------|-----:|-|-----------|-----:|
| A01 Broken Access Control | 118 | | API8 Security Misconfiguration | 21 |
| A03 Injection | 89 | | API5 Broken Function Level Authorization | 6 |
| A05 Security Misconfiguration | 72 | | API1 Broken Object Level/Property Authorization | 4 |
| A07 Identification & Authentication Failures | 65 | | API2 Broken Authentication | 4 |
| A04 Insecure Design | 34 | | API7 Server Side Request Forgery | 4 |
| A08 Software & Data Integrity Failures | 17 | | API9 Improper Inventory Management | 3 |
| A10 SSRF | 15 | | API3 Broken Object Property Level Authorization | 2 |
| A02 Cryptographic Failures | 15 | | API4 Unrestricted Resource Consumption | 2 |
| A09 Logging & Monitoring Failures | 4 | | API6 Unrestricted Access to Sensitive Business Flows | 1 |
| A06 Vulnerable & Outdated Components | 3 | | API10 Unsafe Consumption of APIs | 1 |

Two non-web tracks sit alongside these: the **network** app plants 32 host/port
and service-level findings for network scanners, and the two **LLM** apps
(`llmchat`, `llmagent`) plant prompt-injection, tool-abuse and RAG-poisoning bugs
scored on a separate injection-channel track.

Each bug is also tagged with a **detection difficulty** (118 `E`, 68 `E-M`, 202
`M`, 61 `M-H`, 100 `H`), a **taint distance** (351 `in-file`, 83 `cross-file`, 87
`cross-service`, 28 `config`) and a **reachability** (368 `pre-auth`, 181
`user`), so recall can be broken down along each of those axes instead of
reported as one number. The per-app catalogs live in
[`benchmark-plans/`](benchmark-plans/).

## Repository structure

```
dynast-bench/
├── README.md             # you are here - overview, safety, run/score guide
├── examples/             # ready-to-score findings/v1 + endpoints/v1 files
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
dynast-bench vulns nextjs                # the planted bugs as a checklist, one title each
                                         # (--full · --near · --ids for a coverage diff)
dynast-bench start nextjs                # build + boot, wait for health, print the URL
dynast-bench verify nextjs               # run the ground-truth PoCs (expect all exploitable)
dynast-bench validate nextjs             # twin loop: vuln all-exploitable → safe all-fixed
dynast-bench status                      # variant, mode, target, health
dynast-bench stop --all                  # stop everything
dynast-bench clean --all --images --yes  # reclaim containers, volumes, networks, images

dynast-bench start nextjs --variant safe # the patched twin (false-positive run)
dynast-bench start --count 5 --parallel  # 5 apps at once, one port each + a summary table
dynast-bench start --all --solo --parallel   # whole fleet, one image + port each
dynast-bench run nextjs -- my-scanner --url '$TARGET'   # start → scan → stop
```

Full reference: [`dynast-bench/README.md`](dynast-bench/README.md).

### Ports

Everything lives in a quiet slice of the ephemeral range, so the suite doesn't
fight the usual 3000/8000/8080/5432 crowd - and **every app owns a fixed port**,
so a URL always means the same app, alone or in a batch of five:

| range | what |
|-------|------|
| `13311`–`13339` | the app under test - **the URL you point a scanner at**, one port per app in `list` order (aspnet `13311`, fastapi `13312`, … nextjs `13322`) |
| `13340`–`13484` | that app's sidecars (mailpit, phpMyAdmin, Jenkins, Prometheus, …), 5 apiece |
| `13500`–`13599` | relocation pool |

`dynast-bench list` is the map. If anything is already listening on a port an app
owns, `dynast-bench start` leaves it alone and publishes that one service from
the relocation pool instead, then prints (and `--json`-reports) the real URL.
Nothing ever binds beyond `127.0.0.1`. `dynast-bench doctor` shows which app
ports are free; `make` targets don't relocate and publish the compose defaults
(`13311`+) one app at a time, honouring `DYNAST_PORT=<n>`; `--port N` pins it.

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
    ├── VULNERABILITIES.yaml  # every planted bug
    ├── SURFACE.yaml          # every endpoint the app exposes
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

Two answer keys, because there are two questions. `VULNERABILITIES.yaml` says
what is **wrong** in the app; `SURFACE.yaml` says what is **there** at all.

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

`SURFACE.yaml` records one entry per **operation the app exposes**, vulnerable
and benign alike - it is the denominator for [endpoint
coverage](#endpoint-coverage):

```yaml
operations:
  - id: posts.search
    kind: http                 # http | graphql | ws | llm | net
    method: GET
    path: /api/posts/search
    params: [q]
    discovery: js-runtime      # same crawl tiers as the answer key
    reachability: user
    vulns: [SQLI-001]          # omit when the operation is benign

  - id: graphql.mutation.update-post
    kind: graphql              # the op BEHIND POST /graphql, which is its own entry
    op: updatePost
    graphql_kind: mutation
    via: graphql.transport
    discovery: static-html
```

Benign operations are in there on purpose: a catalog of only the vulnerable
routes would measure coverage of the answer key rather than of the app.

`verify/` holds one runnable PoC per bug - it exits **0 against `vuln/`** and
**non-zero against `safe/`**. That's the executable definition of "the bug is
real (and actually fixed in the twin)."

The shared runner (`dynast-bench/tools/poc-runner.sh`) adds a third outcome the
exit code cannot carry on its own: **the harness could not run**. Point the suite
at a port nothing is listening on and a good half of any app's PoCs exit `1` -
indistinguishable from a genuine fix. So the runner health-probes the target
before it believes a rejection, applies a per-PoC deadline, and fails both legs
on a timeout, a missing tool or a target that stopped answering. "The suite could
not run" is never recorded as "the vulnerability is fixed".

## Shared tooling (`dynast-bench/`, Bun/TypeScript)

One toolchain, used by every app, so cross-stack results are comparable:

- **`dynast-bench.ts`** - the CLI: start/stop/reset/clean, health gating, port
  arbitration, PoC verification, scoring, `--json` for harnesses.
- **`src/schema/`** - types + validators for the two report formats
  (`findings/v1`, `endpoints/v1`) and the two answer keys
  (`VULNERABILITIES.yaml`, `SURFACE.yaml`), the CWE-family table used for
  partial credit, and the path/route/operation normalizers both sides of a
  comparison go through.
- **`src/normalize/`** - adapters converting raw scanner output (OWASP ZAP, SARIF
  from Semgrep/CodeQL/Snyk, nuclei, Burp XML, nmap XML) into that format. The
  format is auto-detected, so `score` takes native output directly.
- **`src/scorer/`** - matches findings against the answer key and emits
  **precision / recall / F1**, recall per difficulty / severity / reachability /
  taint / CWE, a **discrimination** score over the near-misses, and a duplicate
  (noise) ratio. Alongside it, an [endpoint-coverage](#endpoint-coverage) track
  grades how much of the app a run actually reached and splits every miss into
  "never found the endpoint" vs "found it, missed the bug".

```
dynast-bench verify   <app>                 # run the app's ground-truth PoCs
dynast-bench score    <app> findings.json   # findings → P/R/F1 + per-dimension recall
dynast-bench coverage <app> endpoints.json  # endpoint discovery → how much was reached
dynast-bench surface  <app>                 # the operation checklist a crawl is graded on
dynast-bench diff     <app>                 # the vuln↔safe delta vs the answer key
dynast-bench check    --all                 # CI gate: schema · anchors · diff scope · binds
```

[`examples/`](examples/) holds files you can score immediately - a findings run, a
false-positive run, three endpoint traces and two blank templates, each documented
with the numbers it produces:

```bash
dynast-bench score    nextjs examples/findings.json --safe examples/findings-safe.json
dynast-bench coverage nextjs examples/endpoints.json --findings examples/findings.json
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

- **19 apps carry a complete answer key**: 549 planted vulnerabilities, 146
  near-misses, 546 PoCs, and a `Dockerfile.standalone` each (`--solo`).
  `dynast-bench list` prints the live table.
- **`nextjs` is the reference implementation** - built and validated end to end
  (35 vulns + 15 near-misses). `make validate APP=nextjs` proves every PoC
  exploitable on `vuln/` and fixed on `safe/`; `make solo APP=nextjs` runs it from
  one image. Copy its patterns.
- **`dynast-bench` CLI - built**: runs, verifies, scores and cleans any app, in
  compose or single-image mode, with `--json` for harnesses.
- **The scorer - built** (`dynast-bench/src/`): scanner output → normalized findings
  → precision/recall/F1, per-difficulty recall, a discrimination score over the
  near-misses, and separate discovery (network) and injection-channel (LLM) tracks.
- **Endpoint coverage - built**: a `SURFACE.yaml` per app (~600 operations across
  the fleet) grading how much of the app a run actually reached, and splitting
  every miss into "never found the endpoint" vs "found it, missed the bug".
- Per-app invariants over all 19 answer keys and surface catalogs run in
  `make test`; `dynast-bench check --all` is the CI gate.

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
output - the format is sniffed. Start from [`examples/`](examples/) if you are
wiring up a tool: `examples/template-findings.json` is a blank skeleton with every
field, and `examples/findings.json` is a working file you can score right now.

Endpoint discovery is graded separately, against each app's `SURFACE.yaml`:

```bash
dynast-bench coverage nextjs endpoints.json --findings findings.json
```

That is what separates a **discovery miss** (never reached the endpoint - fix the
crawler) from an **analysis miss** (reached it, did not report - fix the scanner).
See [`dynast-bench/README.md`](dynast-bench/README.md#scoring) for the schema, the
matching tiers and every metric.

### Reading the report (`Leg │ Precision │ Recall │ F1`)

A **leg** is one scan run against one target state:

| Leg | What it is |
|---|---|
| `blackbox` | no credentials - the unauthenticated attacker view |
| `credentialed` | same target with the seeded logins injected, so authenticated surface (IDOR, privilege escalation) is reachable |
| `safe-twin` | the patched twin (`--safe`), a false-positive baseline - ideally finds nothing |

All three run `0.0`–`1.0`, and for all three **higher is better** (`1.0` is perfect):

| Metric | Formula | Better | Reads as |
|---|---|---|---|
| **Precision** | `TP / (TP + FP)` | ↑ higher | of everything reported, how much was real. `0.38` = ~38% of findings were genuine, the rest noise. High = few false alarms. |
| **Recall** | `TP / (TP + FN)` | ↑ higher | of the bugs actually planted, how many were found. `0.73` = 8 of 11. High = few misses. |
| **F1** | `2 × P × R / (P + R)` | ↑ higher | harmonic mean of the two - the headline "overall quality" number. Only high when both are, so it penalises being noisy *and* missing bugs. |

The one inversion: on the **`safe-twin` leg there is nothing real to find**, so
every finding there is a false alarm - fewer is better, and an empty report is
the perfect score.

## Endpoint coverage

Recall tells you how many bugs a tool found. It cannot tell you **why** it missed
the rest - and the two reasons need opposite fixes:

| Miss | Meaning | What to fix |
|---|---|---|
| **discovery miss** | never reached the endpoint carrying the bug | the crawler |
| **analysis miss** | reached the endpoint, did not report the bug | the analysis |

Telling them apart needs a second input: the endpoints your tool says it found.
That is `endpoints/v1`, scored against each app's `SURFACE.yaml`.

```bash
dynast-bench surface  nextjs                       # the checklist a crawl is graded on
dynast-bench coverage nextjs endpoints.json        # how much did it reach?
dynast-bench coverage nextjs endpoints.json --findings findings.json   # ...and why not the rest
dynast-bench score    nextjs findings.json --endpoints endpoints.json  # both in one report
```

A crawler that reads HTML and runs JS but never completes a multi-step flow:

```
operations   62.5%   25 of 40
detection    25.0%   of the bugs on operations it reached
misses:      11 never reached the operation · 18 reached it and did not report

  static-html    6/6   100.0%
  js-static      5/5   100.0%
  js-runtime    11/19   57.9%
  interaction    3/5    60.0%
  flow           0/5     0.0%
```

The tier breakdown is the useful part: 100% on `static-html` and 0% on `flow` is
a discovery problem, not a scanner problem, and those read identically in a
single recall number.

Two rules keep the number honest:

- **Transport is not operation.** One `POST /graphql` does not exercise the 25
  GraphQL operations behind it; one WebSocket handshake does not exercise its
  events; one `POST /api/runs` does not exercise an agent's tools. Reaching a URL
  and exercising what lives there are separately scored.
- **Missing telemetry produces no track at all**, never `0%`. "We did not measure
  this" and "it reached nothing" are opposite claims about a tool.

Reported endpoints that match nothing cost precision but never reduce coverage,
so spraying a wordlist is not a way to score higher. Full model:
[`dynast-bench/README.md#endpoint-coverage`](dynast-bench/README.md#endpoint-coverage).

## License

`dynast-bench` is made with ♥ by [@j3ssie](https://github.com/j3ssie) to benchmark
**Vigolium** and **Gimora** (an autonomous offensive-security agent), and it is
released under the [MIT license](LICENSE).
