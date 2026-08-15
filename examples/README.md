# `examples/` - files you can score right now

Two questions get scored separately, so there are two file formats:

| Format | Answers | Scored by |
|--------|---------|-----------|
| `findings/v1` | what did you find **wrong**? | `dynast-bench score` |
| `endpoints/v1` | how much of the app did you **reach**? | `dynast-bench coverage` |

Everything here targets a real app and produces real numbers - copy one, point it
at your own tool's output, and you have a scoreable run.

```bash
dynast-bench score    nextjs examples/findings.json
dynast-bench coverage nextjs examples/endpoints.json --findings examples/findings.json
```

No app needs to be running: scoring reads files, not a target.

## The files

| File | App | What it shows |
|------|-----|---------------|
| `findings.json` | nextjs | 6 findings, one per scoring behaviour - markers, source-only, CWE alternates |
| `findings-safe.json` | nextjs | a scan of the **patched twin**; every finding here is a false alarm |
| `endpoints.json` | nextjs | a browser-driven crawl that gets the shallow surface and misses the deep flow |
| `endpoints-shorthand.json` | nextjs | the same idea as a bare list of strings - the minimum a tool must emit |
| `endpoints-graphql.json` | graphql | transport vs operation: `POST /graphql` is one entry, each op is its own |
| `template-findings.json` | - | blank skeleton, every field the scorer reads |
| `template-endpoints.json` | - | blank skeleton, every operation kind |

The two `template-*.json` files carry `_comment` keys and an `<app>` placeholder,
so they document the format rather than scoring. Unknown keys are ignored, which
is why the comments are safe to leave in while you fill one out. `dynast-bench
schema` prints the same thing, and `--json` gives you a machine-readable copy.

## What each one scores

Verified by `dynast-bench/test/examples.test.ts`, so these numbers cannot drift
away from the files.

### `findings.json` - a clean partial scan

```
dynast-bench score nextjs examples/findings.json
```

```
precision   100.0%   6 tp / 0 fp
recall       17.1%   6 of 35 planted
discrim.    100.0%   0/15 near-misses flagged
proven       83.3%   of true positives carried proof
```

Six findings, six true positives. Read them for the rules they exercise:

| Finding | Rule |
|---------|------|
| `f-01` | a seed marker in `evidence.markers` is proof - this is what resolves two bugs on one route |
| `f-02` | a concrete id (`/api/posts/7`) is fine; the scorer templates it to `{id}` |
| `f-03` | no marker, but a response excerpt showing an internal-only host was reached |
| `f-04` | **source-only**: no route, just file + line. Still matches, `exploited: false` is honest |
| `f-05` | a served file is an endpoint like any other |
| `f-06` | `cwes: [...]` alternates are scored best-of - `CWE-601` wins full credit |

### `findings-safe.json` - the false-positive run

Pair a scan of the patched twin with the vuln scan. Every finding on `safe/` is
wrong by construction, which is what makes precision mean something:

```bash
dynast-bench score nextjs examples/findings.json --safe examples/findings-safe.json --full
```

```
precision    75.0%   6 tp / 2 fp      (was 100% without the safe run)
discrim.     93.3%   1/15 near-misses flagged
false positives: 2  (near-miss 1 · patched-twin 1 · other 0)
```

Both kinds, deliberately:

- `s-01` flags `SQLI-001` where it is **already fixed** → `fixed-bug`
- `s-02` flags `/api/preview-internal`, a **near-miss** - safe code shaped like
  the SSRF next door → `near-miss`, and the discrimination penalty

### `endpoints.json` - a crawl that ran out of road

```bash
dynast-bench coverage nextjs examples/endpoints.json --findings examples/findings.json
```

```
operations   62.5%   25 of 40
precision    96.2%   26 reported · 1 matched no cataloged operation
detection    25.0%   of the bugs on operations it reached
misses:      11 never reached the operation · 18 reached it and did not report

  static-html    6/6   100.0%
  js-static      5/5   100.0%
  js-runtime    11/19   57.9%
  interaction    3/5    60.0%
  flow           0/5     0.0%
```

That bottom block is the point. This tool reads HTML and runs JS, but never
completes a multi-step flow - so the 5 `flow` operations are unreachable to it,
and the bugs there are **discovery misses**, not analysis failures. The 18
analysis misses are the opposite: it stood on the endpoint and did not notice.

The last entry, `/api/notifications`, is invented. It costs precision and does
not reduce coverage - guessing wide is not a way to score higher.

### `endpoints-graphql.json` - transport is not operation

```bash
dynast-bench coverage graphql examples/endpoints-graphql.json
```

```
operations   48.4%   15 of 31
routes       80.0%    4 of 5     <- reached almost every URL

  graphql   10/25   40.0%
  http       4/5    80.0%
  ws         1/1   100.0%
```

Four URLs out of five, but under half the API. `POST /graphql` is one operation;
sending it does not exercise the 25 GraphQL operations behind it, opening
`/graphql/ws` does not exercise the subscriptions, and on the LLM apps hitting
`POST /api/runs` does not exercise the agent's tools. Name them individually or
they do not count.

## Emitting these from your own tool

Minimum viable `endpoints/v1` - a list of strings is accepted:

```json
{
  "schema": "dynast-bench.endpoints/v1",
  "tool": { "name": "my-agent", "mode": "agent" },
  "run": { "app": "nextjs", "variant": "vuln" },
  "endpoints": ["GET /", "GET /api/posts/search?q=", "ws /ws post.search", "llm run_shell"]
}
```

Three things worth getting right:

1. **`run.variant`.** A scan of the patched twin that does not say `"safe"` has
   every one of its findings scored as a true positive.
2. **Report the verb.** A method-less entry against a pinned one still counts,
   but as a *loose* hit, and the report says so.
3. **One finding per vulnerability, not per payload.** Extra payloads on the same
   bug are counted as duplicates - noise, not false positives.

If you have no endpoint list yet, pass your findings file to `--endpoints`: the
operations it implies are scored instead, labelled `evidence_source: findings`
because it only sees where you filed a bug - a floor, not a measurement. Omit
`--endpoints` entirely and there is simply no coverage track, which is the
honest rendering of "not measured".

## Related

- `dynast-bench/README.md#scoring` - how a finding is matched to a bug
- `dynast-bench/README.md#endpoint-coverage` - the coverage model in full
- `dynast-bench surface <app>` - the operation checklist a crawl is graded against
- `dynast-bench vulns <app>` - the bug checklist a scan is graded against
- `vulnerable-apps/nextjs/ground-truth/expected/` - golden fixtures with asserted
  scores, including a deliberately awful `sloppy.json` that trips every trap
