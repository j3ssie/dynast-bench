# Agent guide - DynAST-Bench

> This file is the canonical agent guide. `AGENTS.md` is a symlink to it.

You are working in **DynAST-Bench**: a suite of **intentionally-vulnerable web
apps** used to benchmark security tooling (DAST scanners, SAST engines, LLM
security agents). Each app is small, self-contained, and ships a documented,
machine-checkable ground truth.

## ⚠️ Read this first - the #1 rule

**The vulnerabilities are the product. Do NOT "fix" them.** In `vulnerable-apps/<app>/vuln/`
the insecure code is intentional and must stay insecure. Never add sanitization,
auth checks, or parameterized queries to `vuln/`. Fixes live ONLY in the
`safe/` twin. If a security-minded instinct says "this is a bug, patch it" -
that's the point; leave it and record it in the ground truth instead.

Also: every app binds host ports to `127.0.0.1` only. Never expose these apps to
a public network.

## What "done" means for an app (the acceptance bar)

An app is complete when all of these hold:

```bash
make run APP=<app>       # boots healthy via compose
make verify APP=<app>    # every ground-truth PoC is EXPLOITABLE on vuln/
make validate APP=<app>  # vuln/: all exploitable  ->  safe/: all fixed
make solo APP=<app>      # runs as ONE self-contained image, PoCs still exploitable
make check APP=<app>     # answer key is scoreable: schema, anchors, diff scope, binds
```

Equivalent via the CLI (same docker commands, plus health gating and `--json`):

```bash
dynast-bench start <app>            # = make run
dynast-bench verify <app>           # = make verify
dynast-bench validate <app>         # = make validate
dynast-bench start <app> --solo     # = make solo
```

Plus: `diff -ru vuln safe` touches **only** the lines named in
`ground-truth/VULNERABILITIES.yaml`, and `ground-truth/` is never baked into an
image.

## Reference implementation

**`vulnerable-apps/nextjs/` is fully built and validated (35 vulns + 15 near-misses,
tiered by `discovery:` and using the browser PoC harness).**
Copy its patterns. `vulnerable-apps/_template/` is the empty skeleton to clone. Each app's
vulnerability catalog and design notes live in
**`benchmark-plans/<stack>.md`** - build to that catalog (or document any
deferrals at the bottom of `VULNERABILITIES.yaml`).

## Repo layout

```
dynast-bench/
├── Makefile              # top-level runner (make list / run / verify / validate / solo)
├── README.md             # human overview
├── CLAUDE.md / AGENTS.md # this guide
├── benchmark-plans/      # per-stack design docs = the vulnerability catalogs
├── examples/             # ready-to-score findings/v1 + endpoints/v1 files, and
│                         # blank templates; every number in its README is asserted
│                         # by dynast-bench/test/examples.test.ts
├── dynast-bench/           # `dynast-bench` CLI + scorer (Bun/TS, both built)
└── vulnerable-apps/
    ├── _template/        # skeleton to copy
    ├── nextjs/           # ✅ reference implementation (built + validated)
    └── <17 more>         # aspnet fastapi golang graphql jsp laravel llmagent llmchat
                          # nestjs network php rails springboot swagger websocket
                          # weirdproxy wordpress   (all carry a complete answer key)
```

Per-app anatomy (identical everywhere):

```
vulnerable-apps/<app>/
├── Makefile              # copy from _template (uniform interface, auto-detects APP)
├── README.md             # LOUD banner + run notes
├── vuln/                 # vulnerable variant  (Docker build context = this folder)
│   ├── docker-compose.yml            # binds 127.0.0.1 only
│   ├── Dockerfile                    # app-only image (compose provides datastores)
│   ├── Dockerfile.standalone         # all-in-one image (embeds datastores) - for `make solo`
│   ├── entrypoint.sh                 # compose entrypoint (migrate + seed + start)
│   ├── entrypoint.standalone.sh      # standalone entrypoint (starts DBs + app in one container)
│   ├── internal-sink.mjs             # tiny internal-only HTTP svc = SSRF target in solo mode
│   └── <app source + seed>
├── safe/                 # patched twin - byte-identical to vuln/ except fixed bug lines
└── ground-truth/         # NEVER copied into any image (outside both build contexts)
    ├── VULNERABILITIES.yaml
    ├── SURFACE.yaml      # every operation the app exposes = the coverage denominator
    ├── verify/           # one PoC per bug + _lib.sh helper
    ├── run.sh            # thin wrapper over dynast-bench/tools/poc-runner.sh:
    │                     #   expect-vuln (all exploitable) | expect-safe (all fixed)
    └── expected/         # optional golden findings files for the scorer (see nextjs)
```

## Every planted bug needs FIVE things

1. **Insecure code in `vuln/`** - the real sink, written idiomatically for the stack.
2. **A fix in `safe/`** - same file/lines, minimal change, nothing else touched.
3. **A `VULNERABILITIES.yaml` entry** (schema below).
4. **A runnable PoC** in `ground-truth/verify/<id>.sh` - exits `0` against `vuln/`,
   non-zero against `safe/`.
5. **A near-miss where sensible** - safe code of the same shape sitting next to the
   vulnerable one, present in BOTH variants, recorded under `near_misses:`. Flagging
   it is a false positive; this is what separates real scanners from grep.

### `VULNERABILITIES.yaml` schema

```yaml
app: <app>
entry: http://127.0.0.1:13311
seed_notes: >
  Orgs Acme + Globex; user2 in Globex (cross-tenant IDOR); a Globex DRAFT carries
  GLOBEX-CONFIDENTIAL-MARKER-7f3a (only reachable via SQLi/IDOR); weak admin/admin.
vulnerabilities:
  - id: SQLI-001                       # CLASS-NNN, unique
    variant_paths: { vuln: vuln/..., safe: safe/... }
    symbol: <function/route/method>
    route: "GET /api/posts/search?q="  # or "" for source-only
    cwe: CWE-89
    owasp: "A03:2021-Injection"
    severity: high                     # info|low|medium|high|critical
    difficulty: E                      # E|E-M|M|M-H|H  (detection difficulty)
    discovery: static-html             # static-html|js-static|js-runtime|interaction|flow
    taint: in-file                     # in-file|cross-file|cross-service
    reachability: pre-auth             # pre-auth|user|admin
    near_miss: NM-SQL-001              # or null
    match:                             # machine anchors - GENERATED, see below
      http: { method: GET, path: "/api/posts/search", params: [q] }
      http_alt: ["/api/docs/"]         # other paths reaching the same sink, when
                                       # `route:` names more than one. Reporting
                                       # ANY of them is the correct answer.
      file: { path: vuln/..., symbol: <symbol>, lines: [19, 33] }
      markers: [GLOBEX-CONFIDENTIAL-MARKER-7f3a]
    poc: ground-truth/verify/sqli_001.sh
    notes: >
      one-line description of the sink and how to reach it
near_misses:
  - id: NM-SQL-001
    path: vuln/...
    symbol: <safe sibling>
    of: SQLI-001
    match: { file: { path: vuln/..., symbol: <safe sibling>, lines: [19, 25] } }
    notes: "why this is safe"
```

### `discovery:` - how far a tool has to crawl to find it

`difficulty` says how hard a bug is to recognise once you are looking at it.
`discovery` is the other axis: what it takes to reach the endpoint at all.

| tier | means |
|---|---|
| `static-html` | URL is in the served HTML of a public page |
| `js-static` | URL is a literal string in a bundle - greppable, no execution |
| `js-runtime` | URL only exists once JS evaluates (fragments, manifest, lazy chunk) |
| `interaction` | request only fires on a click/submit/scroll |
| `flow` | only reachable from one state of a multi-step flow |

Two rules keep this honest:

- **Discovery only.** Every bug stays exploitable over plain HTTP once its URL is
  known. Gate how a tool *finds* the route, never how it exploits it - PoCs are
  still curl unless the bug genuinely needs a DOM (see "Browser PoCs").
- **All-or-nothing per app.** `check` errors if a key tiers some entries and not
  others, because a partial breakdown reports recall over the labelled subset
  while looking like it covers the app.

Aim for a spread rather than a cliff: leaving a handful of bugs at `static-html`
is what lets a request-fuzzer score above zero, which is the number that makes
the tiers above it mean something.

**Every app in the fleet is tiered.** How much gradient an app has depends on its
shape, and that is itself the signal:

- **Behaviorally hardened, rich gradient** - `nextjs` (5 tiers) and `laravel`
  (static/js-runtime/interaction) kill the served route manifest and assemble URLs
  from a client route registry, so most of the surface is only reachable by running
  the page. Copy these when an app has a real browser UI.
- **Naturally structured** - `swagger` maps documented→`static-html`,
  shadow→`js-runtime`; `graphql` is `static-html` while introspection is on, with
  the WS subscription `interaction` and the persisted query `js-runtime`.
- **Honest single tier** - a pure-API app (`rails`, `fastapi`, `aspnet`, …) is
  uniformly `static-html`: every endpoint is a conventional, request-fuzzable path
  with no client route assembly, so a browser buys nothing. `network` is
  `static-html` (a port scan is request-only); `websocket` and the two LLM apps are
  `interaction` (you must drive the protocol/agent). Do NOT fake a gradient on an
  API app by inventing a JS front-end - the flat tier is the truthful finding.

### The `match:` block is generated - do not hand-write it

`match:` is what lets the scorer tell two bugs on the same endpoint apart. Never
type it by hand; regenerate after adding or editing entries:

```bash
bun dynast-bench/tools/derive-match.ts <app>          # dry run, prints a summary
bun dynast-bench/tools/derive-match.ts --all --write
bun dynast-bench/tools/derive-match.ts --all --check  # CI: fail if any anchor is stale
```

It derives the path/params from `route:`, the file from `variant_paths:`, markers
from the PoC, and the line range from the vuln↔safe diff plus the `symbol` -
preferring a `// VULN <ID>` comment where the app writes them (nextjs, rails and
wordpress do; **write them in new apps**, it is by far the most reliable anchor).
Two anchors in one file are never allowed to overlap, so an ambiguous range is
emitted as no range at all. It splices text, so comments and formatting survive,
and re-running is idempotent.

Then confirm the key is scoreable:

```bash
dynast-bench check <app>     # schema · anchors on disk · diff scope · PoCs · binds
make test                    # the scorer suite, including per-app invariants
```

Give a near-miss that lives at its OWN endpoint a `route:` - without one, a
black-box tool can never be charged for flagging it, which quietly makes
`discrimination` a source-scanner-only metric. `check` warns about each one.

`check` fails if the twins differ in a file no entry names - which is the invariant
"the diff touches only the lines named in the answer key", enforced. It is graded:
plumbing (compose/package files) and a second file in a bug's own fix are warnings;
a twin that fixes an **unrecorded** bug is an error, because a tool that finds it
would be scored as a false positive.

## `SURFACE.yaml` - the endpoint-coverage denominator

`VULNERABILITIES.yaml` says what is wrong. `SURFACE.yaml` says what is *there*:
every deliberate operation the app exposes, **vulnerable and benign**. It exists
so a run can be scored on how much of the app it reached, which is what tells the
two kinds of failure apart:

```
discovery miss   never reached the operation carrying the bug   -> the crawler
analysis miss    reached the operation, did not report the bug  -> the analysis
```

```bash
bun dynast-bench/tools/derive-surface.ts <app> --write   # draft it
dynast-bench surface <app>                               # read it back
dynast-bench coverage <app> endpoints.json               # grade a crawl
```

The tool drafts the vulnerable half from `VULNERABILITIES.yaml` (already tiered,
already mapped to bug ids) and the benign half from a per-stack pass over the
source; hand review lives in its `TIER_REVIEW` / `EXTRA_OPS` tables so a
regenerate cannot lose it. **Never rewrite an existing entry and never delete
one to fix a score** - a catalog that shrinks makes every tool look better
without anyone touching a tool.

Rules `check` enforces, and the reasoning behind each:

- **Transport is not operation.** `POST /graphql` is one entry; every GraphQL op
  behind it is its own. Same for a WS handshake vs its events and an agent-run
  route vs its tools. Otherwise one request scores as exercising the whole app.
- **Every reachable bug maps to an operation** (`vulns:`), or it drops out of the
  miss split silently. Source-only entries are exempt - there is no endpoint.
- **Nothing unreachable in the denominator.** No `/api/_verify/*`, no static
  assets, and nothing behind an `expose:`-only service (swagger's `partner-api`,
  every app's `internal-sink`). A cataloged endpoint no tool can reach caps
  coverage below 100% forever.
- **Tiering is all-or-nothing**, same as the answer key.
- **A fix that removes an operation** declares `variant: vuln`, so the safe twin
  is not graded against an endpoint that is no longer there.

Not every app has benign surface: `wordpress` and `weirdproxy` plant a bug on
every route they serve, and `network` is ports. That is a real property, not a
gap - do not invent benign routes to pad it.

### PoC contract (`ground-truth/verify/<id>.sh`)

- Reads base URL from `$TARGET` (default `http://127.0.0.1:13311`) so it runs
  unchanged against either variant.
- **Exit `0` = target is vulnerable.** So it PASSes on `vuln/`, FAILs on `safe/`.
- Self-contained; source the shared `_lib.sh` for login/id-resolution helpers.
- **Non-destructive / order-independent:** a PoC that pollutes global state must
  self-clean (see nextjs `proto_001` / `settings/import`), and a PoC that mutates
  shared counters must restore them (see nextjs `billing_001`) or be safe to run in
  any order. `make verify` runs on fresh state (`reset` first) - don't rely on that
  for cross-PoC ordering.
- **Exit `2` if the PoC cannot run at all** (a tool it needs is missing, the
  browser image failed). Never `exit 1` for that - see below.

### The runner tells "fixed" apart from "the harness broke"

`ground-truth/run.sh` is a thin wrapper; the logic is shared in
**`dynast-bench/tools/poc-runner.sh`**. Copy the wrapper from `_template`.

Exit status alone cannot carry this: curl exits `1` for "no match" and `7` for
"could not connect", and a PoC ending in `grep -q` passes either through. Point
the suite at a dead port and 5 of gin's 11 PoCs exit `1` - exactly what a
genuinely fixed bug looks like. So the runner keeps an independent oracle:

| result | meaning |
|---|---|
| `0` | the exploit worked |
| `2` | the PoC says it could not run |
| `124` | the runner's deadline expired |
| `126`/`127` | not executable / missing command |
| anything else **and the target still answers health** | cleanly rejected = fixed |
| anything else **and it does not** | harness failure |

**"answers health" means 2xx**, nothing looser. It used to mean "anything that
was not empty, `000` or 5xx", so a 404 satisfied the oracle - and a wrong
`POC_HEALTH`, a stale proxy, or some other service on the port could license
every PoC's nonzero exit to be recorded as "cleanly rejected". Every app's own
compose healthcheck already requires 2xx (`curl -sf`, `r.ok`, a JSON parse), so
no app is on a non-2xx health route.

A harness result fails **both** legs. "The suite could not run" must never be
recorded as "the vulnerability is fixed". The runner health-probes before it
starts (so a dead app fails once, not as N false "fixed" verdicts), applies a
portable per-PoC deadline, prints per-PoC timing, and shows captured stderr for
anything it could not run.

App hooks, set in `run.sh` before sourcing the runner - see `llmagent` (per-PoC
budgets via a `poc_timeout` function), `llmchat` (`POC_SKIP` for fixtures that
are not PoCs) and `php` (`POC_HEALTH` for a non-standard health path).

### Browser PoCs (`dynast-bench/tools/browser/`)

Most PoCs are curl and **must stay that way** - a bug is gated on how a tool
*discovers* it, never on how it is exploited. The exception is a bug whose sink
only exists once the page's JS has run (DOM XSS, `postMessage`, client-side
routing): a request/response transcript cannot tell you whether anything
executed, so those get a real browser.

```sh
. "$(dirname "$0")/_lib.sh"                 # already sources browser.sh
browser_dialog "$TARGET/p#<payload>" MARKER # exit 0 if a JS dialog carrying MARKER fired
browser_requested "$TARGET/" /api/hidden    # exit 0 if the page requested that URL
browser "$TARGET/x" --click '#btn' --eval 'return document.title'
```

- One shared image (`make browser-image`, or built on first use), Debian chromium
  + `puppeteer-core` so it is native on arm64 as well as amd64. Chrome for Testing
  publishes no linux-arm64 build, which is why this is not the stock puppeteer image.
- The runner builds it **once up front** when any PoC mentions `browser_`, for
  every app. A missing image fails as "the harness could not run", never as
  "NOT exploitable" - the latter is a wrong answer about the app.
- **`drive.mjs`'s exit code is about the probe, never about the app.** `0` = the
  page loaded and the JSON below it is real; `2` = the probe observed nothing
  (chromium never started, or navigation threw). A *page*-level failure - a
  `pageerror`, a selector that never appeared, an `--eval` that threw - still
  exits `0` and lands in `errors`, because a PoC may be asserting on it. A failed
  navigation used to exit `0` too: the helper then found no marker, returned 1,
  and the runner - seeing a nonzero PoC against a host that still answers health
  - wrote it down as "fixed". `browser()` collapses every nonzero (including
  `docker run`'s own 125) to `2` for the same reason.
- The settle waits are a ceiling, not the normal path: `browser_dialog` and
  `browser_requested` pass `--until` so the probe returns the moment its oracle
  fires. On the safe twin nothing fires and it waits the full budget, which is
  the point - you cannot short-circuit proving that nothing executed.
- The apps bind `127.0.0.1` only, so the container reaches the host by joining its
  namespace on Linux (`--network=host`) and via `host.docker.internal` elsewhere.
  `browser.sh` picks per platform; PoCs still just pass `$TARGET`.
- A fired dialog is the XSS oracle: reflection alone never produces one.

## Shared domain + seed (keep IDENTICAL across apps for comparability)

- Orgs (tenants): **Acme**, **Globex**. Roles: `guest/user/editor/admin/service`.
- Seed users: `admin@bench.local/Admin123!` (admin, Acme), `editor@bench.local/Editor123!`
  (editor, Acme), `user1@bench.local/User123!` (user, Acme), `user2@bench.local/User123!`
  (user, **Globex** - the cross-tenant account for IDOR), plus a weak `admin/admin`
  service credential.
- A **Globex DRAFT** post whose body contains `GLOBEX-CONFIDENTIAL-MARKER-7f3a` - a
  correct published-only, org-scoped query never returns it, so SQLi/IDOR PoCs grep
  for that marker.

## Host ports (keep IDENTICAL across apps)

The suite lives at **13311+**, away from the 3000/8000/8080/5432 crowd. Container-side
ports never change - only what gets published on the machine.

Every publish in a compose file MUST be written as an env var with a default, so
the CLI can move it when the default is busy:

```yaml
services:
  app:
    ports: ["127.0.0.1:${DYNAST_PORT:-13311}:3000"]        # the app under test
  mailpit:
    ports: ["127.0.0.1:${DYNAST_PORT_MAILPIT_8025:-13312}:8025",
            "127.0.0.1:${DYNAST_PORT_MAILPIT_1025:-13313}:1025"]
```

- `DYNAST_PORT` (13311) is reserved for **the app under test** - the CLI keys off
  that exact name to know which service a scanner should be pointed at.
- Sidecars: `DYNAST_PORT_<SERVICE>_<CONTAINERPORT>`, defaults `13312`, `13313`, …
  assigned in file order.
- **The compose defaults are what `make` publishes** (one app at a time). The CLI
  instead gives every app a **fixed port of its own** and passes it in via those
  same env vars, so a URL always means the same app and a batch never shuffles:
  `13311 + <index in \`dynast-bench list\`>` for the app, `13340 + 5 * index` for
  its sidecar block. Adding an app shifts the ones after it - `list` is the map.
- `13311`–`13339` are the app ports, `13340`–`13484` the sidecar blocks and
  `13500`–`13599` the relocation pool the CLI draws from when something else is
  already holding a port. Don't hardcode anything in those ranges.
- Each app `Makefile` takes `DYNAST_PORT ?= 13311` and exports it, so a bare
  `make up` still publishes the compose defaults; `dynast-bench start` prints
  (and `--json`-reports) the port it actually used.
- PoCs still read `$TARGET` and must never hardcode a host port. A URL that the
  *container* dials (an SSRF target, a healthcheck) keeps its container port.

## Resource limits (every service, both twins)

Every compose service carries `mem_limit` / `cpus` / `pids_limit`. **Keep them
when you add a service or a new app.** They are not tuning - they are what stops
one app's planted bug from taking the machine down with it:

```yaml
services:
  app:
    mem_limit: 1g      # 2g for JVM/.NET/LLM stacks (aspnet springboot jsp llm*)
    cpus: 2.0
    pids_limit: 1024   # a fork bomb out of an RCE sink stays a container problem
```

Several apps plant resource-exhaustion bugs on purpose (`gin` DOS-001 is an
uncapped gzip bomb; `graphql` and `websocket` carry `CWE-770`s), and several
more spawn a process per request (`gin`'s `renderPDF` starts a headless chrome
with no concurrency cap). Uncapped, a scanner fuzzing any of those exhausts the
Docker VM and every *other* app on the daemon dies with it - which reads as
"the benchmark is flaky", not "gin has a DoS". Capped, the same event is one
container hitting its ceiling, with `OOMKilled=true` naming the culprit.

Caps are ceilings, not reservations, so a generous number costs nothing until
something runs away. `dynast-bench stress <app>` is what checks they hold.

The same ceiling follows the app out of compose, derived rather than written
twice:

- **Solo** gets the **sum** of that app's compose limits, because one standalone
  container does all the work the whole stack did - `dynast-bench/tools/solo-run.sh`
  (for `make solo`) and `soloLimits()` (for the CLI) do the same arithmetic over
  the same compose file. Both clamp to what the docker VM actually has: docker
  *refuses* a `--cpus` above `NCPU`, and a `--memory` above the VM's RAM is not a
  ceiling at all. Both also add `--init` (solo entrypoints background their
  datastores and `wait`, so PID 1 has to reap) and bounded json-file logs.
- **The browser container** is capped in `tools/browser/browser.sh`. It is the one
  container that is *not* the app under test, and a DOM-XSS PoC feeds a renderer
  a hostile page by design.
- **`start`** refuses a compose selection whose ceilings exceed the VM (`--force`
  overrides, `--solo` is the way out); `--solo` warns and proceeds. `doctor`
  prints the VM's size, the fleet's total, and roughly how many apps fit.

## Verification API (harness-only, in every app)

Guarded by header `X-Verify-Token: benchsecret`. Used by the compose healthcheck
and by PoCs to resolve seeded ids:

```
GET /api/_verify/health            -> { status, db, redis?, ... }   (no token needed)
GET /api/_verify/user?email=...    -> { exists, id, role, isAdmin, verified, orgSlug }
GET /api/_verify/post?slug=...     -> { exists, id, status, authorEmail, orgSlug, ... }
```

## Standalone single-image (`make solo`)

Every app must also run from ONE image with no compose. Provide
`Dockerfile.standalone` + `entrypoint.standalone.sh` + `internal-sink.mjs`. The
trick that keeps behavior + PoCs identical: the standalone entrypoint aliases the
compose service names to localhost so config/env/PoCs are unchanged:

```sh
for h in postgres redis mailpit; do echo "127.0.0.1 $h" >> /etc/hosts; done
```

Start the datastores locally (Postgres with trust auth, Redis), start
`internal-sink.mjs` (the internal-only SSRF target, e.g. a fake mailpit on
`127.0.0.1:8025`), then the app. Runs as root so it can edit `/etc/hosts` and
start services; Postgres runs under its own user via `su postgres`. See
`vulnerable-apps/nextjs/vuln/{Dockerfile.standalone,entrypoint.standalone.sh,internal-sink.mjs}`.

**`EXPOSE` is the contract.** Both `make solo` and `dynast-bench start --solo`
read the standalone image's `EXPOSE` line to know what to publish - **first port
is the app under test**, the rest get slots in the app's own sidecar block. So an
image that serves more than one port must EXPOSE all of them (`weirdproxy` runs
nginx/Apache/Traefik in the one image and 11 of its 16 PoCs live on the second
and third). Nothing else declares this: there is no per-app metadata file, and
inferring it from the Makefile is what used to silently publish the wrong port.

A PoC that needs a non-app solo port reads `DYNAST_SOLO_PORT_<containerPort>`,
which the CLI exports next to the compose-shaped `DYNAST_PORT_<SERVICE>_<PORT>`
(a solo container is a plain `docker run`, so it carries no compose service label
to name the publish after). See weirdproxy's `_lib.sh` for the three-layer
fallback.

## Building a new app - recipe

1. `cp -r vulnerable-apps/_template vulnerable-apps/<app>` (then remove the example `VULNERABILITIES.yaml` entries).
2. Read `benchmark-plans/<app>.md` - that's your vulnerability catalog and stack choices.
3. Build `vuln/` (app + compose + seed with the shared domain). Get it healthy:
   `make run APP=<app>` → `curl /api/_verify/health`.
4. Plant bugs one at a time. For each: write the sink in `vuln/`, a PoC in
   `verify/`, confirm it exploits, add the `VULNERABILITIES.yaml` entry, add a
   near-miss when natural.
5. `cp -r vuln/* safe/` then fix ONLY the bug lines in `safe/`. Keep the diff minimal.
6. Add `Dockerfile.standalone` + `entrypoint.standalone.sh` + `internal-sink.mjs`
   (copy nextjs, adapt).
7. `make validate APP=<app>` (vuln all-exploitable → safe all-fixed) and
   `make solo APP=<app>` (single image, PoCs still exploitable). Both must be green.
8. `bun dynast-bench/tools/derive-surface.ts <app> --write`, then review the
   benign half by hand - it is the part a regex cannot get right.
9. Update `vulnerable-apps/<app>/README.md` and note any deferred catalog items in `VULNERABILITIES.yaml`.

## Gotchas learned building nextjs (apply the spirit to any stack)

- **Run in production mode** if a dev-mode watcher/type-checker could interfere
  (Next dev's type-checker broke on prototype pollution). Prod also gives realistic
  error handling; deliberately code any "verbose error" leak rather than relying on
  a framework dev overlay.
- **Framework routing quirks matter** - e.g. Next treats `_`-prefixed folders as
  private, so the verification API folder is `%5Fverify` on disk to keep the
  `/api/_verify/*` URL. Learn your stack's equivalents.
- **Datastore column quoting** in raw SQL/PoCs (Postgres folds unquoted identifiers
  to lowercase; Prisma camelCase columns need `"seatsUsed"`).
- **No bind-mounts in the images** - code is baked in, so re-run `make up`/`make solo`
  after source edits (not a hot reload).

## Tooling notes

- Apps **self-validate** via `ground-truth/run.sh` (used by `make verify`).
- **`dynast-bench/dynast-bench.ts`** is the built CLI (single-file Bun/TypeScript, zero
  runtime deps): `list · info · vulns · surface · doctor · start · stop · stop-all ·
  restart · reset · clean · status · target · logs · verify · validate · stress ·
  run · score · coverage`. `vulns <app>`
  prints the answer key as a checklist (titles; `--full`/`--near`/`--ids`), which
  is how you check what a scan was supposed to find. It derives everything from
  the apps themselves - compose ports + healthcheck path + resource limits, the
  standalone image's `EXPOSE` ports, and `VULNERABILITIES.yaml` - so **a new app
  appears automatically**; keep those conventions intact and there's nothing to
  register. `--json` on every command.
- **`run <app> -- <cmd>` hands the command target metadata and nothing else.** The
  answer key path and the verify token are behind `--trusted`, because a scanner
  that can read the expected findings - or ask `/api/_verify/*` for the seeded ids
  instead of discovering them - is not a scanner you can score.
- **Destructive commands require ownership**, not just a matching name: compose
  stamps every container with the directory it was launched from, so a user's own
  `vuln-api` project elsewhere on the machine is never a `stop-all` candidate.
- **`validate` builds both twins first**, then starts each with no rebuild, and
  tears down in a `finally` unless `--keep`. Keeps the safe build off the critical
  path and stops a heavy build running while race/rate-limit PoCs execute. **Both**
  legs get a `down -v` first: PoCs are documented to run on fresh state, and a
  safe stack left over from an earlier run was being validated against old volumes.
- **A start that never goes healthy is rolled back** - diagnostics are dumped
  first, then the stack comes down, because a half-started stack still holds its
  ports and its memory and `--count 10` used to leave one behind per failure.
  `--keep-failed` leaves it up to poke at.
- **`run` tears down in a `finally`.** The command under it is somebody else's
  program: it can throw, be Ctrl-C'd, or exec a binary that is not there.
- **Starting a batch**: `start --count N` boots N apps (the ones named, else the
  first N of the catalog) and `--parallel[=M]` overlaps them - port planning is
  serialized behind a lock and a planned port stays reserved until docker binds
  it, so concurrent starts never pick the same one. A batch reports per app: the
  ports of the apps that came up in a summary table (`{started, failed}` in
  `--json`), exit `1` if any failed. Before any of that it prices the **resolved
  selection** against the docker VM (see "Resource limits") - the old guard only
  refused the literal `--all`, which `--count 19` walked straight past.
- **`stress` reports pass / FAIL / INCONCLUSIVE.** Containment and recovery are
  read off `docker stats`; when there is nothing to sample that is not a pass, and
  it used to be recorded as one - the same rule the PoC runner applies to a
  harness failure. Its numeric flags are bounded too, since the command whose job
  is to prove the suite contains a runaway must not be the runaway.
- **Stopping**: `stop` with no app stops everything running (it prompts past one
  stack); `stop-all` (= `stop --all`) finds stacks from docker rather than from the
  apps directory, so it also reclaims one whose app was renamed or deleted out from
  under it; `--force` removes containers directly instead of a `compose down` per
  stack. All three are scoped to the `vuln-`/`safe-` naming, so unrelated stacks on
  the same daemon are never touched.
- `make install` = `bun build --compile` + symlink into `~/.bun/bin` (override
  `BIN_DIR=`), so `dynast-bench` is a normal native binary. It's a snapshot -
  **re-run `make install` after editing the CLI**. `make build` compiles only;
  `make uninstall` removes both. Running `./dynast-bench/dynast-bench.ts`
  directly always uses the current source.
- A compiled binary can't find the repo by walking up from itself, so
  `repoRoot()` falls back to `$DYNAST_BENCH_ROOT` → script dir → cwd → the
  checkout baked in at build time (`--define DYNAST_REPO_ROOT`).
- `dynast-bench clean` deletes each stack's docker **volumes** too - `compose down -v`
  plus a sweep of anything still labelled with that compose project, which is how
  orphaned anonymous volumes get reclaimed. Add `--images` to drop built images.
- `VULNERABILITIES.yaml` must be **machine-parseable YAML** (the CLI reads it with
  `Bun.YAML`). Quote values starting with a YAML indicator, e.g. `symbol: "@c.Body"`.
- PoCs must be **portable shell** - they run on the host, so no GNU-only flags
  (`mktemp --suffix`, `base64 -w`, `grep -P`, `date -d`); macOS ships BSD userland.
  The browser helpers are the one place that branches on `uname`, and only for
  container→host networking.
- The **`dynast-bench/src/` scorer** is built: `score` (findings →
  precision/recall/F1 + per-difficulty recall + a discrimination score over the
  near-misses), `coverage` (reported endpoints → how much of the app was reached,
  plus `detection_given_touch` and the discovery-vs-analysis miss split),
  `diff` (the twin delta vs the answer key) and `check` (the CI gate).
  It reads `findings/v1` or native ZAP / SARIF / nuclei / Burp / nmap output.
  Full reference: `dynast-bench/README.md#scoring`. Tests: `make test`
  (`dynast-bench/test/` - `apps.test.ts` asserts the invariants for EVERY answer key,
  so a new app is covered automatically).
- **A finding the scorer cannot place is a finding a tool gets no credit for.** When
  you plant a bug that shares an endpoint with another, give the entry something
  that separates them: a distinct query value in `route:` (`?action=x`), a distinct
  `symbol`, `graphql_op`, `transport`, `tool`/`injection_channel`, or a `// VULN <ID>`
  comment so the line range is exact. `make test` fails if two bugs end up
  indistinguishable.
- Bun 1.2+, Node 22+, Docker + compose v2 are assumed available.

## Don't

- Don't fix bugs in `vuln/`. Don't sanitize/parameterize/authorize in `vuln/`.
- Don't let `safe/` diverge from `vuln/` beyond the fixed lines.
- Don't bake `ground-truth/` into any image, and don't reference the answer key
  from app code.
- Don't bind ports to `0.0.0.0`. 127.0.0.1 only.
- Don't hardcode a host port in a compose file - publishes are
  `${DYNAST_PORT*:-133xx}` so the CLI can relocate them (see "Host ports").
- Don't drop a service's `mem_limit`/`cpus`/`pids_limit`, and don't add a service
  without them (see "Resource limits").
- Don't invent new domain/seed/verification-API conventions - reuse the shared ones
  so cross-app scanner scores stay comparable.
- **Don't leave a file the image builds from untracked.** A stock framework
  `.gitignore` inside `vuln/` is a landmine: laravel's ignored `/.env` *is*
  DEBUG-001 and `public/.env.backup` *is* SECRET-001, and rails' `bin/rails` (hit
  by an unanchored `bin/` rule meant for .NET) is what `entrypoint.sh` boots. All
  of it worked locally and none of it survived a clone. `dynast-bench/test/tracked.test.ts`
  fails on anything present-but-ignored under `vuln/` or `safe/` that the image
  does not itself regenerate - add a negation, don't reach for `git add -f`.
