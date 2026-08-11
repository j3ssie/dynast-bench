# `dynast-bench/` - the CLI + shared benchmark tooling

One toolchain used by every app, so cross-stack results are comparable. Nothing
here is app-specific; per-app data lives in `vulnerable-apps/<stack>/ground-truth/`.

- **`dynast-bench.ts`** - ✅ built. Single-file Bun/TypeScript CLI that runs the
  apps: start / stop / reset / clean, health-gated boots, PoC verification, and
  a `run` wrapper for pointing a real scanner at a target.
- **`src/{schema,normalize,scorer}/`** - ✅ built. The scoring pipeline: scanner
  output → normalized findings → precision/recall/F1 and per-dimension recall.
  See [Scoring](#scoring).

## Install

Requires [Bun](https://bun.sh) 1.2+ and Docker with compose v2. No `npm install`
needed to run it - the CLI has zero runtime dependencies.

```bash
make install          # from the repo root: compile + link onto PATH
dynast-bench list

# or run it straight from source, nothing to install
./dynast-bench/dynast-bench.ts list
```

`make install` runs `bun build --compile` and symlinks the result into
`~/.bun/bin` (override with `BIN_DIR=`), so `dynast-bench` is a normal ~59MB
native binary - no bun needed at runtime, ~15ms startup. `make build` compiles
without linking; `make uninstall` removes both.

The binary lives on `$PATH`, away from the apps, so it finds the suite by:

1. `DYNAST_BENCH_ROOT` if set - always wins;
2. walking up from the script (when run from source);
3. walking up from the current directory (when you're inside a checkout);
4. the checkout it was compiled from, baked in at build time.

**Re-run `make install` after editing the CLI** - the binary is a snapshot, not a
link to the source.

Optional dev extras (`bun install` in this folder) add `@types/bun` +
`typescript` so `bun x tsc --noEmit` typechecks the CLI.

## Commands

```
CATALOG
  list                     apps with vuln/PoC counts and what's running
  info <app>               ground-truth summary (severity, CWE, difficulty)  [--full]
  vulns <app...>           every planted bug, one title per line — the checklist
                           a scan gets compared against  [--full] [--near] [--ids]
  doctor                   docker/bun checks + which ports are taken

LIFECYCLE
  start <app...>           build + boot, wait for health, print the target URL
  start --count N          the same for N apps at once, one port each
                           [--parallel[=N]]
  stop [app...]            stop stacks; with no app, everything that is running
  stop-all                 stop every stack, orphans included (= stop --all)
  restart <app>            stop, then start the same variant/mode
  reset <app>              drop volumes and boot fresh (re-seeded state)
  clean [app...|--all]     remove containers + volumes + networks, reclaiming the
                           disk they held  [--images] [--orphan-volumes]

INSPECT
  status [app...]          running stacks: variant, mode, target, health
  target <app>             print just the base URL (for scripts)
  logs <app>               container logs  [--follow] [--tail N]

BENCHMARK
  verify <app>             run the ground-truth PoCs against the running app
  validate <app>           twin loop: vuln all-exploitable → safe all-fixed
  run <app> -- <cmd...>    start, run <cmd> with $TARGET set, stop afterwards

SCORE
  score <app> <file...>    findings → precision/recall/F1  [--safe f.json] [--full]
  diff <app>               the vuln↔safe delta, cross-checked against the answer key
  check [app...|--all]     CI gate: schema · anchors · diff scope · PoCs · binds
```

Aliases: `ls`/`apps` → `list`, `up` → `start`, `down` → `stop`, `ps` → `status`,
`url` → `target`.

### Flags

| Flag | Meaning |
|------|---------|
| `--variant vuln\|safe` | which twin (default `vuln`; `safe` = false-positive run) |
| `--solo` | one self-contained image instead of compose |
| `--port N` | pin the app's host port (default `13311`, else the next free one) |
| `--count N`, `-c N` | `start` N apps: the ones named, else the first N of the catalog |
| `--parallel[=N]` | bring them up 3 at a time, or N (`start`) |
| `--near` | also list the near-misses (`vulns`) |
| `--ids` | bare ids, one per line, for a coverage diff (`vulns`) |
| `--all` | every app (`stop`/`clean`; `start` also needs `--solo`) |
| `--force` | remove containers directly instead of a `compose down` per stack (`stop`) |
| `--no-build` | skip the docker build (reuse the existing image) |
| `--timeout S` | health-wait budget, default 300s (cold JVM/.NET builds are slow) |
| `--no-takeover` | relocate rather than stop this app's other twin for its port |
| `--volumes` | also drop volumes (`stop`, `run`) |
| `--images` | also drop the images this repo built (`clean`) |
| `--orphan-volumes` | also drop anonymous volumes left by earlier runs (`clean`) |
| `--keep` | leave the app running (`run`, `validate`) |
| `--json` | machine-readable output on stdout |
| `--yes` | skip the confirmation prompt (`clean`) |
| `--safe FILE` | findings from the patched twin (`score`) - all false alarms |
| `--format F` | force an input format (`score`): findings/v1 zap sarif nuclei burp nmap |
| `--full` | every match/miss/false-positive row (`score`, `diff`, `check`); route + PoC + full notes (`vulns`) |
| `--limit N` | detail rows per section (`score`, default 10) |
| `--lenient-cwe` | accept a match whose CWE is unrelated (`score`) |

Exit codes: `0` ok · `1` operation failed (incl. PoCs off-expectation) · `2` usage error.

### Reclaiming disk

These apps carry seeded Postgres/MySQL/SQL-Server data, so a few runs is a few
GB. `clean` accounts for all of it:

```bash
dynast-bench clean nextjs                  # that app's containers, volumes, networks
dynast-bench clean --all --images --yes    # everything, including images the repo built
```

Most of the disk sits in *anonymous* volumes - the ones the datastore images
declare themselves. Docker gives those no project label, so `clean` reads each
stack's container mounts **before** tearing it down; that's the only moment the
link exists. `compose down -v` runs first, then anything still standing is
removed by name, and the total is reported (`bytes_reclaimed` in `--json`).

A stack torn down some other way (`docker rm` without `-v`, a `make down` from an
older checkout) leaves volumes nothing can attribute any more. `clean` counts
those and says so; `--orphan-volumes` deletes them - same set `docker volume
prune` would take (unused **anonymous** volumes only, never named ones).

## Several apps at once

Under `make` every app publishes the same compose defaults, so only one runs at a
time. The CLI gives each app [a port of its own](#ports), which is what lets a
batch coexist - and lets the same app keep its URL run after run:

```bash
dynast-bench start --count 5 --parallel          # 5 apps, one port each
dynast-bench start nextjs golang gin --parallel  # or name them
```

`--count N` takes the apps you name, or the first N of the catalog when you name
none - catalog order, so the same machine picks the same N twice. `--parallel`
brings 3 up at a time (`--parallel=6` for more); without it they boot one after
another, streaming their build output. Either way the batch ends in a table:

```
APP      VARIANT  MODE     PORT   TARGET                  HEALTH
fastapi  vuln     compose  13312  http://127.0.0.1:13312  ok
gin      vuln     compose  13313  http://127.0.0.1:13313  ok
golang   vuln     compose  13314  http://127.0.0.1:13314  ok
```

An app that never comes up is reported and the rest still start - the batch exits
`1` with `{ started: [...], failed: [...] }` under `--json`, so a harness always
gets the ports it did win:

```bash
dynast-bench start --count 3 --parallel --json | jq -r '.started[] | "\(.app) \(.target)"'
```

Solo mode (`--solo`) runs the app's `Dockerfile.standalone` - one image with the
datastores embedded, no sidecar ports at all - which is the cheapest way to hold
the whole fleet open:

```bash
dynast-bench start --all --solo --parallel --json   # every app, one image + port each
```

## Ports

**Every app owns a fixed port.** It is the app's index in `dynast-bench list`,
counted from 13311, so `nextjs` is `:13322` whether it booted on its own, inside
a batch of five, or in solo mode - and two runs of the same batch hand back the
same URLs.

| range | what |
|-------|------|
| `13311`–`13339` | the app under test - the URL a scanner gets. aspnet `13311`, fastapi `13312`, gin `13313`, … nextjs `13322`, … wordpress `13329` |
| `13340`–`13484` | that app's sidecars (mailpit, phpMyAdmin, Jenkins, Prometheus, …) - a block of 5 per app, `13340 + 5 × index`, filled in compose-file order |
| `13500`–`13599` | relocation pool |

`dynast-bench list` prints the map (the `TARGET` column), `doctor` shows which of
those ports are free right now. Adding an app to the suite shifts the ports of
the apps after it alphabetically.

Compose files still declare `127.0.0.1:${DYNAST_PORT:-13311}:3000`, so their
defaults are what a bare `make up` publishes; the CLI passes each app's own port
in through those env vars. At `start` it checks every port it is about to take:

- free → takes it, so the URL is the same every run;
- held by this app's **other twin** (or the same app in the other mode) → stops
  that one and takes the port, which is what the vuln→safe loop wants (pass
  `--no-takeover` to relocate instead);
- held by **anything else** - another benchmark app, an unrelated container, a
  stray process → left strictly alone; that one publish moves into the relocation
  pool and the real URL is printed and reported in `--json`.

So a machine already running something on 3000, 8080 or 5432 needs no
arrangement, the whole suite can be up at once, and `--port N` pins the app port
explicitly (compose or solo); `DYNAST_PORT=N make up` does the same for the
`make` targets, which don't relocate.

The port check deliberately combines a bind test, docker's published ports and
`lsof`: Docker Desktop publishes on the IPv6 wildcard, which leaves IPv4
`127.0.0.1:13311` bindable even while something already answers there.

## What is planted in an app

`vulns <app>` prints the answer key as a checklist - one title per bug, which is
what a scan run gets measured against:

```
$ dynast-bench vulns gin
gin  11 vulns · 11 PoCs · 6 near-misses

ID                 CWE       SEV       TITLE
INFO-001           CWE-200   medium    The debug endpoint dumps the full process environment…
DEFAULT-CREDS-001  CWE-1392  medium    Seeded service account uses the weak default credential admin/admin.
IDOR-001           CWE-639   high      Multi-step IDOR: POST /api/posts/{id}/grant mints an access grant…
...
```

- `--full` - route, PoC path and the whole note per bug, as a block per entry.
- `--near` - also the near-misses, i.e. the safe lookalikes that cost precision
  when a tool flags them.
- `--ids` - bare ids, one per line, which is the form a coverage diff wants:

  ```bash
  dynast-bench vulns gin --ids | sort > expected.txt
  jq -r '.findings[].id' my-run.json | sort > reported.txt
  comm -23 expected.txt reported.txt          # what the scanner missed
  ```

`--json` carries every field of the entry (cwe, owasp, severity, difficulty,
reachability, discovery, route, symbol, poc, notes). `info <app>` stays the
aggregate view - counts by severity/difficulty/discovery - and `score` is the
one that actually grades a findings file.

## Driving a scanner

`start --json` gives you the target; `run` does start → scan → stop in one shot
and passes the context through the environment.

```bash
# 1. explicit: boot, scan, tear down
TARGET=$(dynast-bench start nextjs --json | jq -r .target)
zap-baseline.py -t "$TARGET" -J findings.json
dynast-bench stop nextjs

# 2. wrapped: same thing, guaranteed teardown
dynast-bench run nextjs -- zap-baseline.py -t '$TARGET' -J findings.json

# 3. sanity-check the app really is exploitable before trusting a 0-finding scan
dynast-bench verify nextjs --json | jq '.ok, .bad'

# 4. false-positive run - every finding on the twin is a false alarm
dynast-bench run nextjs --variant safe -- zap-baseline.py -t '$TARGET' -J fp.json

# 5. the whole suite, sequentially
for app in $(dynast-bench list --json | jq -r '.apps[].app'); do
  dynast-bench run "$app" -- my-scanner --url '$TARGET' --out "out/$app.json"
done
```

Environment handed to the `run` command:

| Variable | Value |
|----------|-------|
| `TARGET` / `DYNAST_BENCH_TARGET` | base URL, e.g. `http://127.0.0.1:13311` |
| `DYNAST_BENCH_APP` | app name |
| `DYNAST_BENCH_VARIANT` | `vuln` or `safe` |
| `DYNAST_BENCH_HEALTH` | full health-check URL |

The command under `run` is the thing being measured, so that is all it gets. The
answer key and the harness token are held back unless you pass `--trusted`:

| Variable (`--trusted` only) | Value |
|----------|-------|
| `DYNAST_BENCH_GROUND_TRUTH` | absolute path to `VULNERABILITIES.yaml` |
| `DYNAST_BENCH_VERIFY_TOKEN` | token for the `/api/_verify/*` harness API |

A scan that can read the answer key, or ask `/api/_verify/*` for the seeded ids
rather than discovering them, is not a scan you can score. Use `--trusted` for
harness tooling only, and treat any run that needed it as unscoreable.

Everything is derived from the apps themselves - compose files (ports,
healthcheck path), each app's `Makefile` (standalone port) and
`ground-truth/VULNERABILITIES.yaml`. There is no config file to keep in sync, so
a new app under `vulnerable-apps/` shows up in `list` automatically.

`DYNAST_BENCH_ROOT` overrides repo-root detection if you need to point the CLI at
a copy of the suite.

## Relationship to `make`

The per-app `Makefile`s still work and remain the contract described in
`CLAUDE.md` (`make run|verify|validate|solo APP=<app>`). The CLI wraps the same
docker commands and adds the cross-app concerns the Makefiles can't express:
port arbitration, health gating, `--json`, and fleet-wide stop/clean.

## Scoring

```
dynast-bench score <app> <findings.json...>   # findings -> precision/recall/F1
dynast-bench diff  <app>                      # the vuln<->safe delta vs the answer key
dynast-bench check [app...|--all]             # CI gate over the answer keys
```

| Module | What it does |
|--------|--------------|
| `src/schema/` | types + hand-written validators for `findings/v1` and `VULNERABILITIES.yaml`, the CWE-family table, and the path/route/file normalizers both sides are compared through |
| `src/normalize/` | adapters: OWASP ZAP, SARIF (Semgrep/CodeQL/Snyk/trivy), nuclei, Burp XML, nmap XML - format is auto-detected |
| `src/scorer/` | the tiered matcher, one-to-one assignment, metrics and breakdowns |
| `src/check/` | the benchmark's own invariants (schema · anchors · diff scope · PoCs · binds), shared by `check` and the tests |
| `src/twin-diff.ts` | the vuln↔safe delta, parsed once for both `check` and `derive-match` |
| `tools/derive-match.ts` | regenerates the `match:` anchors in every answer key (run it after adding an app) |
| `test/` | `bun test` - unit tests plus per-app invariants over all 18 answer keys |

Input can be a `findings/v1` file or a scanner's native output; the format is
sniffed, so no flag is needed (`--format` forces one).

```bash
# grade one run
dynast-bench score nextjs zap.json

# grade the vuln run and the false-positive run together
dynast-bench score nextjs vuln-findings.json --safe safe-findings.json --full

# combine tools - a DAST report and a SAST report score as one tool
dynast-bench score nextjs zap.json semgrep.sarif nuclei.jsonl

# machine-readable, everything the human report shows and more
dynast-bench score nextjs findings.json --json | jq .metrics
```

### The finding schema

One object per distinct vulnerability. At least one `location.*` block is
required - a finding with no location cannot be scored and is rejected.

```jsonc
{
  "schema": "dynast-bench.findings/v1",
  "tool": { "name": "my-agent", "version": "0.3.1", "mode": "dast" },  // dast|sast|hybrid|agent
  "run":  { "app": "nextjs", "variant": "vuln", "target": "http://127.0.0.1:13311" },
  "findings": [{
    "id": "f-001",                       // unique within the file
    "title": "Boolean SQL injection in post search",
    "cwe": "CWE-89",                     // "cwes": [...] for alternates
    "severity": "high",                  // info|low|medium|high|critical
    "confidence": "firm",                // certain|firm|tentative
    "location": {
      "http": { "method": "GET", "url": "http://127.0.0.1:13311/api/posts/search?q=%27+OR+1%3D1--+",
                "path": "/api/posts/search", "param": "q", "param_in": "query" },
      "file": { "path": "vuln/src/app/api/posts/search/route.ts", "line": 21, "symbol": "GET" }
    },
    "evidence": {
      "markers": ["GLOBEX-CONFIDENTIAL-MARKER-7f3a"],   // a seed marker is proof
      "request": "GET /api/posts/search?q=%27%20OR%201%3D1%20--%20 HTTP/1.1",
      "response_excerpt": "{\"posts\":[{\"status\":\"DRAFT\",...}]}",
      "note": "returns a Globex DRAFT row"
    },
    "exploited": true                    // impact proven, vs inferred
  }]
}
```

Other location blocks, mirroring the keys the answer keys carry:

```jsonc
"net":     { "host": "edge-proxy", "port": 443, "proto": "tcp", "service": "https",
             "version": "nginx/1.24.0", "state": "open" }
"graphql": { "op": "posts", "kind": "query", "field": "posts(first:)" }
"ws":      { "transport": "ws", "event": "subscribe", "channel": "org:globex:posts", "endpoint": "/ws" }
"llm":     { "tool": "run_shell", "channel": "user", "run_id": "r-9" }   // user|rag|page|mcp|memory
```

Rules for whatever emits this:

1. **One finding per distinct vulnerability**, not per payload. Ten SQLi payloads
   on `q` are one finding; extra ones are counted as noise, not punished.
2. **Concrete URLs, not templates.** Report `/api/posts/7`; the scorer normalizes
   identifier segments to `{id}` before comparing.
3. **`run.variant` is mandatory in spirit.** A scan of the patched twin that does
   not say `"safe"` has every finding scored as a true positive.
4. **Put the marker in `evidence.markers`.** `GLOBEX-CONFIDENTIAL-MARKER-7f3a` in a
   response is near-conclusive, and it is what resolves bugs that share a route.
5. **`exploited: false` is honest and still scores** - it just earns no proof credit.
   The marker vocabulary comes from the answer key, so a per-app marker in a native
   scanner's evidence text is recognised too, not just the shared seed marker.
6. Unknown fields are ignored; flat `{url, param, file, line}` findings are lifted
   into `location` with a warning.

### How a finding is matched to a bug

Tiers, highest signal first. Ties are broken by a one-to-one assignment
(Kuhn's algorithm) that maximises the number of bugs matched, so one bug can never
pay out twice and a good pairing is not lost to a greedy first choice.

| Tier | Fires when |
|------|-----------|
| `proof` | a seed marker the answer key names appears in the finding's evidence, and no anchor contradicts it |
| `route` | path (templated) + required query pairs + param + port + verb line up |
| `net` | host + port + proto line up, and the port was reported **open** |
| `api` | the GraphQL op / WS transport+event+channel / LLM tool+channel line up |
| `source` | the file matches and either the symbol matches or the line sits in the bug's own range (±2) |
| `weak` | only a case- or slash-folded path match, or a line outside the bug's range |

CWE handling, which is the part that decides whether a match is allowed at all:

- **exact** (or a declared `cwe_aliases` entry) → full classification credit
- **same family** (`CWE-862` for `CWE-639`; see `src/schema/cwe.ts`) → half
- **generic parent** (`CWE-20`, `CWE-707`, …) → a quarter
- **unrelated** → *not a match*. A positive claim that is wrong is a false positive.
- **absent** → still matched if the anchor is precise, at zero credit. Silence is
  not a wrong answer; plenty of DAST tools map CWEs poorly.

### What comes out

Every metric is `0.0`–`1.0`. The arrow is which direction is good:

```
↑ precision        tp / (tp + fp)      of what was reported, how much was real
                                       (duplicates and closed-port reports excluded)
↑ recall           tp / planted bugs   of what was planted, how much was found
↑ f1               2PR / (P + R)       harmonic mean - only high when both are
↑ recall_reachable tp / bugs reachable over http or net (source-only bugs excluded)
↑ recall_exact_cwe share of planted bugs found AND named exactly
↑ cwe_credit       mean classification credit over all planted bugs
↑ discrimination   1 - near-misses flagged / near-misses planted
↓ noise_ratio      duplicate findings / all findings
↑ exploit_rate     share of true positives that carried proof
```

`noise_ratio` is the only one where **lower is better**; every other number here
is "more of the answer key, correctly named, with proof". The false-positive
counts (`near-miss` / `fixed-bug` / `other`, below) are raw counts, not ratios -
lower is better for all three.

Plus recall broken out by `difficulty`, `severity`, `reachability`, `taint`, CWE and
CWE family - all four dimensions are already in every answer key - and the
app-specific splits (`by_injection_channel`, `by_tool`, `by_documented`,
`by_segment`, `by_transport`) wherever a key carries those fields.

### Recall by discovery tier

`difficulty` is how hard a bug is to recognise once you are looking at it.
`discovery` is a separate axis: how much crawling capability it takes to reach
the endpoint at all. An app whose surface is mostly behind JavaScript and user
interaction will tank a request-fuzzer's recall for reasons that have nothing to
do with how subtle its bugs are, and `by_discovery` is what makes that legible
instead of just a bad number.

```
static-html   URL appears in the served HTML of a public page
js-static     URL is a literal string in a bundle - greppable, no execution
js-runtime    URL only exists once JS evaluates (fragments, manifest, lazy chunk)
interaction   request only fires on a click/submit/scroll
flow          only reachable from one state of a multi-step flow
```

The tier is a property of *discovery only*: every planted bug stays exploitable
over plain HTTP once its URL is known, so a tool that learns the route some other
way is never penalised. Tiering is all-or-nothing per app - `check` errors on a
key that labels only some of its entries, because a partial breakdown reports
recall over the labelled subset while looking like it covers everything.

Two extra tracks run alongside the main matcher:

- **discovery** (the `network` fleet): a set-diff on `host:port/proto` giving port
  precision/recall plus a version-match rate, per `benchmark-plans/network.md`.
  A port reported *closed* is an observation, not a false positive.
- **injection channel** (`llmchat`, `llmagent`): recall per channel and per tool.

### False positives

Three kinds, counted separately because they mean different things:

| Kind | What happened |
|------|---------------|
| `near-miss` | flagged safe code planted next to a bug - the discrimination test |
| `fixed-bug` | flagged a bug on the **patched twin**, where it is fixed |
| `other` | flagged something that is not in the answer key at all |

A near-miss only counts when the finding pins it by route, symbol or line. A
file-level finding that could be either sibling is treated as noise against the
real bug instead - and a near-miss that shares its sibling's route *and* file (like
nextjs `NM-SQL-001`) can only be caught when a tool reports a line or the exact
symbol.

### The `match:` anchors

Every `VULNERABILITIES.yaml` entry carries a machine-readable `match:` block next
to its human `route:`. The scorer falls back to parsing `route:` and
`variant_paths:` when one is missing, so an untouched key still scores - the block
just makes it sharper, and it is what separates bugs that share an endpoint.

```yaml
  - id: SQLI-001
    route: "GET /api/posts/search?q="        # unchanged, for humans
    match:                                   # machine-only
      http: { method: GET, path: "/api/posts/search", params: [q] }
      file: { path: vuln/src/app/api/posts/search/route.ts, symbol: GET, lines: [19, 33] }
      markers: [GLOBEX-CONFIDENTIAL-MARKER-7f3a]
```

Regenerate them after adding or editing an app:

```bash
bun dynast-bench/tools/derive-match.ts --all          # dry run, prints a summary
bun dynast-bench/tools/derive-match.ts --all --write
bun dynast-bench/tools/derive-match.ts --all --check  # CI: fail if any anchor is stale
```

`--check` is what `make check` runs: a source edit that shifts line numbers silently
invalidates every `lines:` anchor below it, so freshness is gated rather than trusted.

It derives paths and params from `route:`, the file from `variant_paths:`, markers
from the PoC, and the line range from the vuln↔safe diff plus the bug's `symbol`
(preferring a `VULN <ID>` comment where an app writes them). Two anchors in one
file are never allowed to overlap: an ambiguous range is worse than none, so it
emits none and the matcher falls back to the symbol. Editing is a textual splice,
so comments and formatting survive, and re-running is idempotent.

### Tests

```bash
cd dynast-bench && bun test      # or: make test
```

`test/scorer.test.ts` pins one rule per case. `test/apps.test.ts` runs over **every**
answer key in the suite: it builds a synthetic perfect / DAST-only / SAST-only tool
from the key itself and asserts that the perfect one scores 1.0/1.0, that a
black-box run can reach every route-anchored bug, that a source-only run trips no
near-miss, and that no two bugs are indistinguishable. A new app is covered the
moment it lands. `test/fixtures.test.ts` pins the exact numbers for the two
checked-in fixtures in `vulnerable-apps/nextjs/ground-truth/expected/`.

## Layout

```
dynast-bench/
├── dynast-bench.ts           # the CLI (single file, zero runtime deps)
├── package.json            # `bun link` target; dev-only devDependencies
├── tsconfig.json           # typecheck config (bun x tsc --noEmit)
├── src/schema/             # types + validators + CWE families + key normalizers
├── src/normalize/          # zap · sarif · nuclei · burp · nmap -> findings/v1
├── src/scorer/             # matcher, assignment, metrics, report
├── src/check/              # the benchmark invariants (CI gate)
├── src/{repo,twin-diff}.ts # app enumeration · the twin delta
├── tools/derive-match.ts   # regenerate the answer keys' match: anchors
└── test/                   # bun test: unit + per-app invariants + golden fixtures
```
