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

**`vulnerable-apps/nextjs/` is fully built and validated (33 vulns + 13 near-misses,
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
    ├── verify/           # one PoC per bug + _lib.sh helper
    ├── run.sh            # runs all PoCs: expect-vuln (all exploitable) | expect-safe (all fixed)
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
- `run.sh` builds it **once up front** when any PoC mentions `browser_`. A missing
  image must fail as "the harness could not run", never as "NOT exploitable" -
  the latter is a wrong answer about the app.
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
8. Update `vulnerable-apps/<app>/README.md` and note any deferred catalog items in `VULNERABILITIES.yaml`.

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
  runtime deps): `list · info · vulns · doctor · start · stop · stop-all · restart ·
  reset · clean · status · target · logs · verify · validate · run`. `vulns <app>`
  prints the answer key as a checklist (titles; `--full`/`--near`/`--ids`), which
  is how you check what a scan was supposed to find. It derives everything from
  the apps themselves - compose ports + healthcheck path, the app `Makefile`'s standalone
  port, and `VULNERABILITIES.yaml` - so **a new app appears automatically**; keep those
  conventions intact and there's nothing to register. `--json` on every command.
- **Starting a batch**: `start --count N` boots N apps (the ones named, else the
  first N of the catalog) and `--parallel[=M]` overlaps them - port planning is
  serialized behind a lock and a planned port stays reserved until docker binds
  it, so concurrent starts never pick the same one. A batch reports per app: the
  ports of the apps that came up in a summary table (`{started, failed}` in
  `--json`), exit `1` if any failed.
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
  near-misses), `diff` (the twin delta vs the answer key) and `check` (the CI gate).
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
- Don't invent new domain/seed/verification-API conventions - reuse the shared ones
  so cross-app scanner scores stay comparable.
