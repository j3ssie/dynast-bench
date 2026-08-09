# Vulnerable-App Benchmark - DAST Ground-Truth Suite

> ⚠️ **These are DELIBERATELY INSECURE applications.** They exist only to
> benchmark security tooling (DAST scanners, SAST engines, and LLM security
> agents). **Never deploy on a public network.** Every app binds to
> `127.0.0.1`, ships a LOUD banner, and carries no real data.

Self-contained **intentionally-vulnerable** benchmark apps, one per stack: ten
browser-facing web apps, three **API-only** apps (GraphQL, WebSocket,
Swagger/OpenAPI), and two **LLM apps** (a RAG chatbot and a tool-calling agent).
Each is a small SaaS-flavoured app (users, roles, posts/tasks,
uploads, admin) with a **planted, documented catalog of vulnerabilities** and a
machine-checkable ground truth. The point is discrimination: a good scanner
finds the planted bugs, ignores the near-miss safe code sitting right next to
them, and doesn't hallucinate on the patched twin.

Every app is **fully independent**: its own directory, its own
`docker-compose.yml`, its own `Makefile`, its own `ground-truth/`, its own two
git branches. You can build, run, and score any one app without touching the
others. The stacks are spread deliberately so the suite as a whole exercises a
wide vulnerability catalog *and* the idioms unique to each ecosystem.

## The ten apps

| App        | Language / framework        | DB        | Extra services            | Signature vuln class (stack-specific)         |
|------------|-----------------------------|-----------|---------------------------|-----------------------------------------------|
| nextjs     | Node / Next.js 15 (App Router) | Postgres | Redis, Mailpit          | Middleware auth bypass, prototype pollution   |
| golang     | Go / chi                    | Postgres  | Prometheus, Grafana       | `/debug/pprof` exposure, `text/template` SSTI |
| fastapi    | Python / FastAPI + Jinja2   | Postgres  | MinIO, Mailpit            | Jinja2 SSTI, `pickle`/`yaml` deserialization  |
| nestjs     | Node / NestJS + Handlebars  | Postgres  | Redis, nginx              | Missing `ValidationPipe` overposting, nginx `alias` traversal |
| springboot | Java / Spring Boot + Thymeleaf | Postgres | Jenkins, Prometheus     | SpEL injection, exposed Actuator, Java deser  |
| rails      | Ruby / Rails 7.2            | Postgres  | MinIO, nginx              | Mass assignment, YAML/Marshal deser, `^$` regex bypass |
| wordpress  | PHP / WordPress + custom plugin | MySQL | nginx, Mailpit            | Vulnerable plugin: nonce/cap checks, `unserialize` |
| php        | PHP / procedural LAMP       | MySQL     | phpMyAdmin, Mailpit       | LFI/RFI, type-juggling auth bypass, `.php` upload RCE |
| jsp        | Java / JSP + Servlets (Tomcat) | Postgres | Mailpit                 | JSP webshell upload, Java deser, AuthFilter bypass |
| aspnet     | C# / ASP.NET Core Razor Pages | SQL Server | Mailpit                 | Overposting, `BinaryFormatter`/`TypeNameHandling` deser |

## The three API-only apps

No HTML UI, nothing to crawl. These measure whether a tool can reach a sink that
isn't behind an anchor tag: one endpoint and a type graph, a message protocol, or
a machine-readable spec that lies about the implementation.

| App        | Language / framework                | DB       | Extra services              | Signature vuln class (protocol-specific)             |
|------------|-------------------------------------|----------|-----------------------------|-------------------------------------------------------|
| graphql    | Node / Apollo Server 4 + Prisma     | Postgres | Redis, internal billing svc | Field-level authz gap, nested-path bypass, alias/batch amplification, APQ cache poisoning |
| websocket  | Node / bare `ws` + Socket.IO 4      | Postgres | Redis, internal svc         | CSWSH (no `Origin` check), auth bypass by transport downgrade, message-type BFLA, channel BOLA |
| swagger    | Python / Django 5.1 + DRF + drf-spectacular | Postgres | Redis, Mailpit, internal partner API | Shadow/zombie APIs, spec-implementation drift, Swagger UI `?url=` spec load |

They are catalogued so that **no single discovery strategy wins**: the GraphQL
app rewards schema introspection and graph traversal over route enumeration; the
WebSocket app puts ~27 of ~31 bugs behind frames a crawler never sends (three are
deliberately reachable with plain `curl`, as a floor); the Swagger app rewards
consuming `/api/schema/` *and* punishes trusting it, because the shadow route,
the zombie `v0` route, and the writable-field drift are all invisible to a
spec-driven scan. The Swagger app's catalog is mapped to the **OWASP API
Security Top 10 (2023)** rather than the web list.

## The network-range app (host/port scanning)

One more app is a different shape again: instead of a single service, `network`
stands up a **fleet** - ~18 containers across four simulated network segments
(edge / app / data / mgmt) exposing ~30 ports of real third-party services (SSH,
FTP, SMTP, Redis, Mongo, Elasticsearch, Postgres, MySQL, Memcached, RabbitMQ,
Jenkins, Grafana, phpMyAdmin, MinIO, SNMP). It targets **network scanners**
(nmap, masscan, Nessus/OpenVAS, TLS/default-cred auditors), grading host+port
discovery, service/version→CVE fingerprinting, no-auth/default-cred/anonymous
access, weak-TLS detection, and - the headline - **network segmentation** breaks
where a data-tier service is reachable from the edge. Every broken service has a
**hardened twin on an adjacent port** (authed Redis, modern-TLS vhost, key-only
SSH) so precision is measured too.

| App     | Orchestration                    | Segments        | Signature class                                   |
|---------|----------------------------------|-----------------|---------------------------------------------------|
| network | Compose fleet on a private bridge | edge/app/data/mgmt | Exposed datastores, default creds, weak/broken TLS, **segmentation break (edge→data)**, rogue port |

> ⚠️ **The "network" is a private, non-routed Docker bridge.** Host-facing ports
> still bind `127.0.0.1`; the range is scanned only from a `scanner` container
> placed *inside* the bridge. Never attach it to a physical NIC. Its ground truth
> adds an `expected-ports.yaml` port map beside `VULNERABILITIES.yaml`, and the
> vuln↔safe delta is **config only** (service `*.conf`, `pg_hba`, compose
> `networks:`), never service source. See [`network.md`](network.md).

## The two LLM apps

The newest shape in the suite: apps where **the model is part of the dataflow**.
Attacker input arrives as a retrieved document, a browsed page, or a third-party
tool description rather than a parameter, and the model's *output* is what
reaches `innerHTML`, `cursor.execute`, `exec`, or a tool call. They target
LLM/AI security tooling (prompt-injection scanners, agent guardrail products,
LLM red-team harnesses) as well as conventional DAST/SAST.

| App      | Language / framework                        | DB              | Extra services                  | Signature vuln class (LLM-specific)                          |
|----------|---------------------------------------------|-----------------|---------------------------------|--------------------------------------------------------------|
| llmchat  | Python / FastAPI + LangChain 0.3            | Postgres+pgvector | Redis, **Ollama**, internal svc | Indirect prompt injection via RAG, cross-tenant vector retrieval, improper output handling, system-prompt leakage |
| llmagent | Node / TypeScript + Fastify + Vercel AI SDK + MCP | Postgres  | Redis, **Ollama**, partner-MCP, internal svc | Excessive agency, HITL bypass, MCP tool-description poisoning / rug-pull / shadowing, confused deputy, memory poisoning |

Both run a **local model** - `gemma3:1b` for chat, `qwen2.5:1.5b` for the agent
(Gemma 3 has no tool-calling template in Ollama) - baked into a build-time-pulled
`ollama` image with **no host port**. That means zero API keys, zero egress, zero
cost per run, *and* it makes the model host itself an internal-only SSRF target.

> **Determinism.** A model is stochastic; the PoC contract (`exit 0` =
> exploitable) is not. Both plans resolve this the same way: every graded bug is
> a missing control in **application plumbing** (no sanitizer, no `org_id`
> predicate, no approval binding, no step budget), not a model behaviour; a
> scripted `LLM_BACKEND=stub` backend present in *both* variants makes
> `make verify` hermetic; and the handful of genuinely model-compliance-dependent
> bugs carry `probabilistic: true` + `attempts` / `pass_threshold` and are graded
> N-of-M under `make verify LLM=real`. Both modes must be green.

These two are graded against the **OWASP Top 10 for LLM Applications (2025)**,
carried in an additive `llm_owasp:` key so the standard `owasp:` field keeps its
web/API Top-10 value and cross-app scoring stays comparable. They also add
`injection_channel:` (`user | document | browsed-page | tool-result |
mcp-description | memory | cache`) so detection rate can be reported by *how the
payload entered the prompt* - the axis that actually distinguishes LLM security
tools. See [`llmchat.md`](llmchat.md) and [`llmagent.md`](llmagent.md).

| OWASP LLM Top 10 (2025)                  | llmchat | llmagent |
|------------------------------------------|:-------:|:--------:|
| LLM01 Prompt Injection                   |    ●    |    ●     |
| LLM02 Sensitive Information Disclosure   |    ●    |    ●     |
| LLM03 Supply Chain                       |    ○    |    ●     |
| LLM04 Data & Model Poisoning             |    ○    |    ●     |
| LLM05 Improper Output Handling           |    ●    |    ●     |
| LLM06 Excessive Agency                   |    -    |    ●     |
| LLM07 System Prompt Leakage              |    ●    |    ○     |
| LLM08 Vector & Embedding Weaknesses      |    ●    |    -     |
| LLM09 Misinformation                     |    ○    |    -     |
| LLM10 Unbounded Consumption              |    ●    |    ●     |

Each app plants **~25–35 vulnerabilities**. Some are the same well-worn classes
seen everywhere (SQLi, XSS, IDOR, CSRF) so cross-stack detection is comparable;
some are the ecosystem's signature foot-guns (SpEL in Spring, prototype
pollution in Node, type-juggling in PHP, `YAML.load` in Rails) so the suite as a
whole covers a broad catalog no single stack could.

## Shared domain (identical concept in every app)

Keeping the domain constant across stacks is what makes cross-stack scanner
results comparable - only the language and the *shape* of each bug changes.

**Domain model.** `Organization → Teams → Projects → Posts/Tasks →
Comments/Attachments`, with `Users` (roles `guest / user / editor / admin /
service`), `Invitations`, `Webhooks/Integrations`, and `Reports`. The
multi-tenant structure is what makes access-control (IDOR/BOLA, function-level
authz) bugs actually bite.

**Routes** (each app maps these onto its idiom):
```
/signup  /login  /logout  /onboarding  /profile
/posts   /posts/new  /posts/{id}   /posts/search
/comments            /attachments/{id}/download
/admin/users         /admin/*
/api/webhooks  /api/import  /api/reports
```

**Seed data** (loaded on first boot; `make reset` restores byte-identical
state):
```
admin@bench.local   / Admin123!    role: admin,  verified   (org: Acme)
editor@bench.local  / Editor123!   role: editor, verified   (org: Acme)
user1@bench.local   / User123!     role: user,   verified   (org: Acme)
user2@bench.local   / User123!     role: user,   verified   (org: Globex)  ← different tenant
+ default admin/admin service account (planted weak cred)
+ 6 seeded posts across both orgs in mixed draft/published states
```

The cross-tenant `user2` (org Globex) exists specifically so access-control
PoCs can prove one tenant reads/writes another tenant's data.

## Vulnerability catalog conventions (identical in every app)

Every planted bug is recorded, once, in the app's ground truth. This is what
turns "a vulnerable app" into "a benchmark."

**`ground-truth/VULNERABILITIES.yaml`** - one entry per planted bug:
```yaml
- id: SQLI-001
  service: gateway
  file: app/routes/search.py
  symbol: search_posts          # function / route / method
  route: "GET /posts/search?q="
  cwe: CWE-89
  owasp: "A03:2021-Injection"
  severity: high                # info | low | medium | high | critical
  difficulty: E                 # E | E-M | M | M-H | H  (detection difficulty)
  taint: in-file                # in-file | cross-file | cross-service
  source: "request query param q"
  sink: "cursor.execute(f\"...{q}...\")"
  near_miss: SAFE-SQLI-001      # id of the safe twin planted nearby
  poc: ground-truth/verify/sqli_001.sh
  notes: "String-concat query; a correctly parameterized query sits 20 lines below."
```

**`ground-truth/verify/`** - one runnable PoC per bug (a `curl`/`http` script or
a tiny Python/Node file). Each exits `0` on the **vuln** branch and non-zero on
the **safe** branch. This is the executable definition of "the bug is real."

**`ground-truth/scorer/`** - takes a scanner's findings (a normalized JSON of
`{file, line, cwe, route}` records), matches them against
`VULNERABILITIES.yaml`, and emits **precision / recall / F1** plus a
per-severity and per-CWE breakdown. Matching tolerates ±N lines and accepts
CWE-family matches (e.g. CWE-89 ↔ CWE-943 both count as "injection" partial).

**`ground-truth/` is NEVER copied into any image.** `.dockerignore` excludes it;
the running app must not leak its own answer key. The scorer and PoCs run from
the host against the exposed ports.

## The patched twin (false-positive measurement)

Every app ships two git branches:

- **`main-vuln`** - the app with all planted bugs (the default; what you scan).
- **`main-safe`** - the *same* app with every planted bug fixed and nothing else
  changed (parameterized queries, escaped output, added authz checks, safe
  deserializers, etc.).

`git diff main-safe main-vuln` **is** the ground truth - it should touch exactly
the lines named in `VULNERABILITIES.yaml` and nothing else. Running a scanner
against `main-safe` measures its **false-positive rate**: every finding there is
a false alarm, because the twin is clean by construction.

## Benchmark-design principles (build these into every app)

- **Plant near-misses.** Put a correctly-parameterized query, an escaped
  template output, or a properly-authorized route *right next to* the vulnerable
  one. Discrimination - not flagging the safe twin - is what separates a real
  scanner from grep-with-an-LLM. Every `near_miss` in the YAML points at its
  safe sibling.
- **Vary taint distance.** Keep some source→sink flows inside one function
  (easy). Route the hard ones across files and across services (the
  second-order SQLi, the SSRF→internal-service chains). Cross-service dataflow
  is where scanners fail; label each bug's `taint` so the scorer can report
  detection rate by distance.
- **Keep logic-only bugs.** Race conditions (seat/invite limits), negative-value
  and integer-overflow money bugs, and auth-state machine flaws can't be
  pattern-matched - they're the best signal for genuine reasoning over
  pattern-scanning.
- **Mix authenticated and unauthenticated reachability.** Tag each bug with
  whether it's reachable pre-auth, as `user`, or only as `admin`. A DAST scanner
  with no creds should still find the pre-auth wall; the authenticated core is
  where crawling + session handling get tested.

## Coverage matrix (OWASP Top 10 2021 × app)

Read down a column to see one app's spread; read across a row to see which
apps exercise a category. ● = a signature/multi-instance area for that app,
○ = present.

| OWASP 2021                          | next | go | fapi | nest | boot | rails | wp | php | jsp | aspnet |
|-------------------------------------|:----:|:--:|:----:|:----:|:----:|:-----:|:--:|:---:|:---:|:------:|
| A01 Broken Access Control           |  ●   | ●  |  ○   |  ●   |  ○   |   ●   | ●  |  ○  |  ●  |   ●    |
| A02 Cryptographic Failures          |  ○   | ●  |  ●   |  ○   |  ○   |   ○   | ○  |  ●  |  ●  |   ●    |
| A03 Injection (SQLi/XSS/cmd/SSTI)   |  ●   | ●  |  ●   |  ●   |  ●   |   ●   | ●  |  ●  |  ●  |   ●    |
| A04 Insecure Design (logic/race)    |  ○   | ●  |  ○   |  ○   |  ○   |   ○   | ○  |  ○  |  ○  |   ○    |
| A05 Security Misconfiguration       |  ●   | ●  |  ●   |  ●   |  ●   |   ○   | ●  |  ●  |  ●  |   ●    |
| A06 Vulnerable/Outdated Components  |  ○   | ○  |  ○   |  ○   |  ●   |   ●   | ●  |  ○  |  ●  |   ○    |
| A07 Auth & Session Failures         |  ●   | ●  |  ●   |  ●   |  ●   |   ●   | ●  |  ●  |  ●  |   ●    |
| A08 Software/Data Integrity (deser) |  ●   | ○  |  ●   |  ●   |  ●   |   ●   | ●  |  ●  |  ●  |   ●    |
| A09 Logging & Monitoring Failures   |  ○   | ○  |  ○   |  ○   |  ○   |   ○   | ○  |  ○  |  ○  |   ○    |
| A10 SSRF                            |  ●   | ●  |  ●   |  ●   |  ●   |   ●   | ●  |  ●  |  ●  |   ●    |

The three API-only apps are scored against the **OWASP API Security Top 10
(2023)** instead - the two lists overlap but the API list is what actually
describes these bugs:

| OWASP API 2023                          | graphql | websocket | swagger |
|-----------------------------------------|:-------:|:---------:|:-------:|
| API1 Broken Object Level Authz (BOLA)   |    ●    |     ●     |    ●    |
| API2 Broken Authentication              |    ○    |     ●     |    ●    |
| API3 Broken Object Property Level Authz |    ●    |     ○     |    ●    |
| API4 Unrestricted Resource Consumption  |    ●    |     ●     |    ○    |
| API5 Broken Function Level Authz (BFLA) |    ○    |     ●     |    ●    |
| API6 Unrestricted Sensitive Flows       |    ○    |     ○     |    ○    |
| API7 SSRF                               |    ○    |     ○     |    ○    |
| API8 Security Misconfiguration          |    ●    |     ●     |    ●    |
| API9 Improper Inventory Management      |    ○    |     ○     |    ●    |
| API10 Unsafe Consumption of APIs        |    -    |     ○     |    ●    |

## Standard host ports (per-app; only one app runs at a time by default)

```
3000 app (or nginx)   5432 postgres   3306 mysql    1433 sqlserver   6379 redis
8025 mailpit UI (1025 smtp)           9000/9001 minio api/console
9090 prometheus       3001 grafana    8080 jenkins  8081 phpmyadmin
```

If you want to run several apps at once, override the host-port prefix per app
(`APP_PORT`, `DB_PORT`, … are env-driven in every compose file) - the internal
service names never collide because each app has its own compose project.

## Makefile targets (identical interface in every app)

```
make up       # docker compose up -d --wait   (bind to 127.0.0.1 only)
make reset    # docker compose down -v && make up   → fresh, byte-identical state
make verify   # run every ground-truth/verify PoC; expect all PASS on main-vuln
make safe     # git switch main-safe && make reset   → the patched twin
make score    # feed a scanner's findings.json to the scorer → P/R/F1
```

## Per-app repo layout

```
<app>/
├── docker-compose.yml         # independent; binds 127.0.0.1 only
├── .env.example · README.md    # LOUD "intentionally vulnerable / local only" banner
├── Makefile
├── app/ (or services/...)      # the application source (bugs live here)
├── db/seed.sql                 # seed users/posts incl. cross-tenant + weak creds
├── ground-truth/               # NEVER copied into any image (.dockerignore'd)
│   ├── VULNERABILITIES.yaml     # id, file, symbol, cwe, owasp, severity, taint, near_miss, poc
│   ├── verify/                  # one runnable PoC per bug (0 on vuln, non-0 on safe)
│   └── scorer/                  # match findings → GT, emit P/R/F1 + per-CWE breakdown
└── PLAN.md                     # the per-stack plan in this folder
```

## Build order recommendation

Start with **fastapi** or **php** (fastest source→sink→PoC loop, and the
richest injection/deserialization catalog), validate the full
`up → verify → score → safe` loop on that one app end to end, then reuse the
compose / Makefile / ground-truth patterns across the other nine. Each per-stack
plan (`fastapi.md`, `golang.md`, …) is self-contained and lists that app's full
vulnerability catalog, its stack-specific bugs, its near-misses, and its compose
sketch.

Build the API-only apps **after** at least one web app is validated end to end -
they reuse the same compose/Makefile/ground-truth patterns but need extra PoC
tooling (`graphql.md` adds a `gqlws.mjs` subscription helper, `websocket.md` a
`ws.mjs` frame helper, both on Node 22's built-in `WebSocket`). Of the three,
`swagger.md` has the shortest source→sink→PoC loop; `websocket.md` has the
longest, because most of its PoCs are stateful frame sequences.

Build the two **LLM apps** after the API-only ones. They reuse the same
compose/Makefile/ground-truth patterns but add two things nothing else in the
suite has: a build-time model pull (the `ollama` image is ~1 GB and the `solo`
image ~2.5 GB - budget the disk and the first build) and the `LLM_BACKEND=stub`
determinism harness, which must be working end to end *before* any bug is
planted. Of the two, `llmchat.md` is much the shorter loop; `llmagent.md` is the
hardest app in the suite - most of its PoCs are stateful multi-step runs with a
mandatory cleanup `trap`, and three of its bugs live in an internal-only MCP
server that has no host port at all.

Build `network.md` **last**: it reuses no application code (it wires pinned
upstream images by config) but is the heaviest to run - ~18 containers, four
Docker subnets, UDP probes, and a `scanner` container that carries the probe
toolbox (`nmap`, `openssl`, `redis-cli`, `mongosh`, `snmpwalk`) so its PoCs don't
depend on host tooling. Its ground truth is a two-file pair - a
`expected-ports.yaml` port map graded for discovery + version accuracy, and the
usual `VULNERABILITIES.yaml` for the exposure findings.

> **Note on conventions.** The ten web-app plans above predate the current repo
> layout and still describe the twin as two git branches (`main-vuln` /
> `main-safe`). The live convention - see `CLAUDE.md` and the built
> `vulnerable-apps/nextjs/` reference - is sibling `vuln/` and `safe/` directories under
> `vulnerable-apps/<app>/`, driven by `make run | verify | validate | solo`. The three
> API-app plans are written against the current convention.
