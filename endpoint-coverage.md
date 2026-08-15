# Endpoint Coverage Scoring Plan

> Status: design exploration only. No implementation has started.

## Goal

Extend DynAST-Bench so a run can be scored not only on vulnerability findings, but also on how much of each application's intended attack surface it actually exercised.

The new measurement should answer three separate questions:

1. **Discovery:** Did the agent discover an application route or protocol operation?
2. **Touch:** Did the agent send traffic to that route or operation?
3. **Exercise:** Did the agent meaningfully invoke the operation behind the transport entry point?

The most important derived question is:

> Did the agent miss a vulnerability because it never reached the operation, or because it reached the operation and failed to recognize the bug?

## Current repository state

The existing scorer cannot calculate true endpoint coverage.

- `findings/v1` records vulnerability findings and optional request evidence, not every request made by an agent.
- Native adapters consume alerts, issues, SARIF results, nuclei matches, Burp issues, or nmap ports. They do not consume complete crawl histories.
- `dynast-bench run` starts an app, exports target metadata to the scanner, runs it, and stops the app. Traffic does not currently pass through an observation layer.
- `by_discovery` is vulnerability recall grouped by the capability needed to discover a vulnerable endpoint. It does not prove that a route was requested.
- The network discovery track already demonstrates the closest useful pattern: compare an expected identity set with an observed identity set independently of vulnerability matching.

Relevant implementation seams:

- Finding and ground-truth types: `dynast-bench/src/schema/types.ts`
- HTTP and route normalization: `dynast-bench/src/schema/keys.ts`
- Comparable protocol anchors: `dynast-bench/src/scorer/anchors.ts`
- Existing set-diff discovery track: `dynast-bench/src/scorer/tracks.ts`
- Score assembly: `dynast-bench/src/scorer/score.ts`
- Human report rendering: `dynast-bench/src/scorer/report.ts`
- Scanner lifecycle: `dynast-bench/dynast-bench.ts`, `cmdRun`

The current answer keys are vulnerability-centric, not complete endpoint inventories. Across the current fleet, 549 vulnerabilities collapse to roughly 480 distinct runtime anchors. This excludes benign routes, pages, login flows, independent near misses, and many protocol operations. Deriving a denominator only from `VULNERABILITIES.yaml` would measure coverage of vulnerable routes, not coverage of the whole application.

## Recommended metric model

Do not compress all coverage into one percentage. Report at least two layers.

### 1. Transport route coverage

Measures whether the agent reached the externally addressable transport entry point.

Examples:

- `GET /api/posts/{id}`
- `POST /graphql`
- WebSocket handshake on `/ws`
- Socket.IO namespace `/rt`
- `edge-proxy:443/tcp`

Formula:

```text
route_coverage = unique cataloged transport routes touched
                 / total cataloged transport routes
```

### 2. Operation coverage

Measures whether the agent exercised the meaningful application operation behind the transport entry point.

Examples:

- HTTP method, path, and required action discriminator
- GraphQL query, mutation, subscription, or security-relevant selected field
- WebSocket message type
- Socket.IO event and namespace
- LLM tool invocation
- Network service handshake

Formula:

```text
operation_coverage = unique cataloged operations exercised
                     / total cataloged operations
```

Operation coverage should be the primary cross-stack signal. Route coverage should remain as a crawler-level diagnostic.

For conventional REST applications, the two values may be close. For GraphQL, WebSocket, and LLM applications, the difference is a useful benchmark result.

## Derived vulnerability metrics

Use operation touch data to divide vulnerability misses into two classes.

### Discovery miss

The agent never touched an operation containing the vulnerability.

### Analysis miss

The agent touched the relevant operation but did not report the vulnerability.

### Detection given touch

```text
detection_given_touch =
  vulnerabilities found on touched operations
  / vulnerabilities planted on touched operations
```

Illustrative report:

```text
vulnerability recall        42%
operation coverage          70%
detection given touch       60%

missed vulnerabilities:
  18 discovery misses
  11 analysis misses
```

This metric must remain alongside precision, recall, and F1. It must not be folded into vulnerability F1.

## Cross-stack operation identities

A single HTTP-path definition is insufficient for the fleet.

### Conventional HTTP applications

Canonical operation identity:

```text
HTTP method + templated path + required action discriminator
```

Examples:

```text
GET /api/posts/{id}
POST /api/settings/import
POST /wp-admin/admin-ajax.php?action=bench_upload
```

Rules:

- Methods are distinct operations.
- Existing path templating should normalize numeric IDs, UUIDs, CUIDs, and placeholders.
- Case, trailing slashes, and percent encoding remain significant in the strict identity because `weirdproxy` intentionally distinguishes them.
- Required action values such as `action=bench_upload` are part of operation identity.
- Ordinary input values are not part of operation identity.
- Declared input names may be retained for exercise-depth diagnostics without multiplying the denominator by payload values.

### GraphQL

`POST /graphql` is only a transport route. GraphQL operation coverage must distinguish operations and, where required, security-relevant fields or paths.

Examples:

```text
query.posts
query.me.organization.posts
mutation.updatePost
subscription.postUpdated
field Post.internalNotes
```

A scanner sending one arbitrary GraphQL request must not receive full GraphQL operation coverage.

### WebSocket and Socket.IO

The handshake endpoint and the message router are separate layers.

Examples:

```text
transport: WS /ws
operation: post.search
operation: admin.userDelete
operation: billing.seats
operation: subscribe + channel org:globex:posts
```

A successful handshake counts toward transport coverage. It does not count as exercising every event.

Socket.IO operation identity may need:

```text
namespace + event
```

### LLM agents

The route that starts an agent run is a transport route. Meaningful operations include the tools made available to or invoked by the agent.

Examples:

```text
run_shell
sql_query
http_fetch
browse
read_file
write_file
send_email
refund_order
delegate
```

A request to `POST /api/runs` must not count as exercising every tool.

### Network

Continue using:

```text
host + port + protocol
```

The existing network discovery track already compares expected and reported sets and separately grades service or version accuracy. Service handshake depth can be reported as an exercise signal.

## Definition of a touch

Initial recommended contract:

- A unique operation counts at most once. Request volume earns no extra coverage credit.
- HTTP method matters.
- Dynamic IDs are templated with the scorer's existing normalization.
- Required action selectors matter.
- Ordinary parameter values do not create separate endpoints.
- Authentication failures count as transport and operation touch when routing reached the intended protected operation. A `401`, `403`, or concealed `404` can still demonstrate reach.
- A WebSocket handshake does not count as touching all message events.
- A GraphQL POST does not count as touching all GraphQL operations.
- Redirect source and destination count separately if both are cataloged.
- Unknown requests are recorded as diagnostics but do not reduce coverage.
- Health probes, verification endpoints, ordinary static assets, framework chunks, and random 404 guesses are excluded unless intentionally declared as benchmark surface.
- Response status and request count are retained as diagnostics but do not independently define coverage.

## Complete surface denominator

Introduce a separate hidden surface catalog rather than overloading vulnerability entries. A conceptual path is:

```text
ground-truth/SURFACE.yaml
```

The exact name and schema remain design decisions.

Example:

```yaml
app: graphql

operations:
  - id: graphql.transport
    kind: http
    method: POST
    path: /graphql
    discovery: static-html
    reachability: pre-auth

  - id: graphql.query.posts
    kind: graphql
    transport: graphql.transport
    graphql_kind: query
    operation: posts
    discovery: static-html
    reachability: user

  - id: graphql.subscription.post-updated
    kind: websocket
    endpoint: /graphql/ws
    event: postUpdated
    discovery: interaction
    reachability: user
```

HTTP example:

```yaml
  - id: posts.search
    kind: http
    method: GET
    path: /api/posts/search
    params: [q]
    discovery: js-runtime
    reachability: user
```

Action-style route example:

```yaml
  - id: wordpress.bench-upload
    kind: http
    method: POST
    path: /wp-admin/admin-ajax.php
    query:
      action: bench_upload
```

The catalog should:

- Include vulnerable and benign application operations.
- Include independent near-miss operations.
- Include authentication and flow operations needed to traverse the application.
- Include hidden, shadow, zombie, debug, source-map, export, and sidecar operations when they are intentional benchmark surface.
- Count alternate routes separately when both are real externally reachable routes.
- Support HTTP, GraphQL, WebSocket, Socket.IO, LLM tool, and network identities.
- Record discovery tier and reachability where applicable.
- Optionally record variant availability if a safe fix intentionally removes an operation.
- Remain outside app images and unavailable to the scanner.
- Map every runtime vulnerability anchor to one or more surface operation IDs.
- Be validated by `dynast-bench check` so denominator drift cannot silently change scores.

### Recommended denominator scope

Use every deliberate application and benchmark attack-surface operation exposed to the agent, including benign operations. Do not limit the denominator to operations containing planted vulnerabilities.

Include by default:

- UI pages and application APIs
- Authentication and multi-step flow routes
- Hidden, shadow, and zombie routes
- GraphQL operations and security-relevant fields
- WebSocket and Socket.IO message operations
- LLM tool operations
- Deliberately exposed sidecar services
- Intentional source maps, debug routes, actuator routes, and static exports

Exclude by default:

- `/api/_verify/*`
- Compose and harness health checks
- Ordinary framework-generated chunks
- Fonts, images, CSS, favicon, and ordinary static assets
- Arbitrary 404 guesses
- Datastore ports outside the network benchmark

## Observation sources

### 1. Agent self-report

The agent reports every operation it believes it touched.

Advantages:

- Easy to add.
- Works with arbitrary agent frameworks.

Limitations:

- Incomplete or inaccurate.
- Easy to overclaim.
- Measures reporting behavior as well as exploration.

Use only as labeled diagnostic or fallback evidence, not the authoritative official metric.

### 2. Scanner-native crawl history

Import ZAP spider history, Burp request history, or equivalent scanner output.

Advantages:

- Rich evidence for supported tools.

Limitations:

- Tool-specific semantics.
- Not available for SARIF, SAST, nuclei, or arbitrary agents.
- Requires separate adapter support.

Use as optional evidence.

### 3. Harness reverse proxy

A coverage-enabled run could provide a recording target that forwards traffic to the app.

Advantages:

- Objective for ordinary HTTP.
- Requires no scanner cooperation.
- Can inspect GraphQL request bodies.
- Fits naturally around the existing `run` lifecycle.

Limitations:

- More difficult for WebSocket frames, direct sidecar connections, and the network app.
- A URL observed at the proxy does not always prove the application matched a handler.
- Browser and absolute-URL behavior must remain correct.

This is the recommended first observation mechanism for HTTP.

### 4. App-side protocol audit collector

Each application records matched route templates or protocol operations for the harness. Retrieval is protected by the verification token.

Advantages:

- Most accurate.
- Can observe framework route matches, GraphQL operations, WebSocket events, Socket.IO events, and LLM tool calls.
- Can distinguish transport touch from actual operation dispatch.

Limitations:

- Requires instrumentation across every stack.
- Instrumentation must be identical in `vuln/` and `safe/` except where variant behavior is intentionally declared.
- It must not expose the endpoint inventory or answer key to the scanner.

This is the recommended eventual authoritative mechanism.

## Recommended observation architecture

Use a hybrid model:

1. Harness reverse proxy for ordinary HTTP traffic.
2. Protocol-aware collection for GraphQL operations and selected fields.
3. Protocol-aware collection for WebSocket and Socket.IO events.
4. Harness-only run audit for LLM tool invocations. The LLM agent app already has verification support for retrieving tool calls.
5. Reuse the network app's existing discovery track.
6. Permit native and self-reported traces only as explicitly labeled fallback sources.

Collection must begin after startup and health gating, and stop before scanner teardown. Harness health probes and PoCs must not contaminate the trace.

## Proposed score output

Add a separate coverage track instead of changing existing vulnerability matching semantics.

Conceptual JSON shape:

```json
{
  "tracks": {
    "coverage": {
      "evidence_source": "harness",
      "routes": {
        "expected": 42,
        "touched": 31,
        "coverage": 0.7381
      },
      "operations": {
        "expected": 57,
        "touched": 34,
        "coverage": 0.5965
      },
      "vulnerable_operations": {
        "expected": 35,
        "touched": 24,
        "coverage": 0.6857
      },
      "benign_operations": {
        "expected": 22,
        "touched": 10,
        "coverage": 0.4545
      },
      "detection_given_touch": 0.5833,
      "discovery_misses": [],
      "analysis_misses": [],
      "touched": [],
      "untouched": [],
      "unknown_observations": []
    }
  }
}
```

Human report sections should include:

- Transport route coverage
- Operation coverage
- Vulnerable-operation coverage
- Benign-operation coverage
- Detection given touch
- Discovery misses versus analysis misses
- Coverage by discovery tier
- Coverage by reachability
- Coverage by protocol
- Touched operations without findings
- Findings without recorded runtime touch
- Unknown observed operations
- Evidence source and telemetry completeness warnings

## Aggregation across applications

Use macro averaging per application for fleet-level coverage.

A micro average across operations would let large applications such as Spring Boot or FastAPI dominate smaller specialized applications. Report both only if the macro average is the headline.

Potential fleet summary:

```text
macro route coverage
macro operation coverage
macro detection given touch
per-app route coverage
per-app operation coverage
per-protocol operation coverage
```

## Invariants and validation

The future `check` path should enforce at least:

- Every surface operation has a unique stable ID.
- Every operation has a valid protocol-specific identity.
- Every runtime vulnerability maps to at least one surface operation.
- Vulnerability mappings do not point to excluded harness-only operations.
- Alternate routes are declared intentionally.
- GraphQL operations sharing `POST /graphql` remain distinguishable.
- WebSocket events sharing one handshake endpoint remain distinguishable.
- LLM tools sharing one run endpoint remain distinguishable.
- No duplicate canonical operation identities exist unless explicitly aliased.
- Every app either has a complete surface catalog or is explicitly not coverage-scoreable.
- Safe and vulnerable twins expose equivalent catalogs unless a declared variant difference explains the change.
- Generated or extracted catalogs are checked for staleness.

## Rollout plan

### Phase 1: lock semantics with representative applications

Model four applications before changing the whole fleet:

1. `fastapi` for conventional HTTP APIs.
2. `nextjs` for browser discovery tiers and multi-step flows.
3. `graphql` for transport route versus operation coverage.
4. `websocket` for handshake versus message-event coverage.

Use the existing `network` discovery track as the fifth protocol reference.

Deliverables:

- Agreed definitions of route, operation, touch, and exercise.
- Draft surface schema.
- Draft normalized observation schema.
- Hand-reviewed surface catalogs for the representative apps.
- Examples of expected coverage reports.

### Phase 2: HTTP observation prototype

Prototype objective HTTP traffic collection around `dynast-bench run` without changing vulnerability scoring.

Questions to validate:

- Whether a local reverse proxy preserves browser and scanner behavior.
- How to avoid recording harness health checks.
- How to normalize host ports, IDs, redirects, and action query values.
- Whether response routing information is sufficient or app-side route templates are needed immediately.
- How coverage traces are passed to `score` without leaking the denominator to the scanner.

### Phase 3: protocol-aware operation telemetry

Add operation-level observation for:

- GraphQL operation names and selected security-relevant fields.
- Raw WebSocket message types and channels.
- Socket.IO namespaces and events.
- LLM tool calls.
- Network service handshakes where the current track does not already provide the signal.

### Phase 4: scorer track and reporting

Add a coverage track alongside vulnerability scoring.

Requirements:

- Existing findings and score output remain compatible.
- Missing coverage telemetry yields `null` or an absent track, never zero coverage.
- Evidence source is explicit.
- Incomplete or self-reported telemetry is labeled.
- Discovery and analysis misses are derived only when mappings and telemetry are complete.

### Phase 5: fleet catalog and CI invariants

- Catalog all deliberate operations across every app.
- Add per-app completeness tests.
- Add canonicalization and collision tests.
- Add perfect, partial, and empty coverage fixtures.
- Extend `check` to reject stale or ambiguous catalogs.
- Document how contributors update the surface catalog when adding a route or protocol operation.

## Test strategy

Add tests at four levels.

### Identity normalization tests

- Method separation
- Numeric, UUID, CUID, and placeholder path templating
- Case, slash, and percent-encoding preservation
- Required query discriminator matching
- Sidecar port identity
- GraphQL operation and field identity
- WebSocket endpoint, event, and channel identity
- Socket.IO namespace and event identity
- LLM tool identity
- Network host, port, and protocol identity

### Coverage arithmetic tests

- Empty expected set returns `null`, not division by zero.
- Missing telemetry returns no official score.
- Duplicate observations count once.
- Unknown observations do not reduce coverage.
- Route touch does not imply all child operations were exercised.
- Findings do not imply touch unless the telemetry contract explicitly permits that fallback.
- Safe and vulnerable traces are kept separate.

### Integration tests

- HTTP proxy records scanner traffic but excludes health probes.
- Dynamic IDs map to catalog templates.
- GraphQL requests map to operations.
- WebSocket frames map to events.
- LLM runs map to tool calls.
- Scanner teardown still occurs on failures.

### Per-app invariants

- Every cataloged operation can be matched by a synthetic perfect trace.
- Every vulnerability maps to an operation.
- A synthetic complete trace scores 100 percent coverage.
- An empty trace scores zero only when telemetry is known to be complete.
- A missing trace scores `null` or absent coverage.

## Open decisions

The following should be settled before implementation:

1. Final file name and schema version for the surface catalog.
2. Whether security-relevant GraphQL fields are first-class operations or attributes under field-containing operations.
3. Whether HTTP parameter coverage is a third metric after route and operation coverage.
4. How much app-side instrumentation is acceptable across all stacks.
5. Whether the first release supports only harness-observed coverage or also scanner-native and self-reported traces.
6. How to model operations that are removed entirely in the safe twin.
7. Whether static UI pages count as operations or only as transport routes.
8. Whether authenticated coverage should be reported as separate anonymous and credentialed tracks.
9. Whether multi-step flow completion is a separate flow-depth metric rather than operation coverage.
10. Whether source-only SAST runs should have no coverage track or a separate source-surface coverage model.

## Recommended decisions

Unless further exploration changes them:

- The official denominator should include every deliberate application operation, including benign operations and near misses.
- Operation coverage should be the primary metric.
- Route coverage should be a separate crawler diagnostic.
- Coverage should be a separate track, not part of vulnerability F1.
- Harness-observed traffic should be authoritative.
- Self-reported coverage should be diagnostic only.
- Missing telemetry should produce `null`, not zero.
- Fleet summaries should use macro averaging by app.
- The first implementation should prove the model on FastAPI, Next.js, GraphQL, and WebSocket before cataloging the full fleet.
