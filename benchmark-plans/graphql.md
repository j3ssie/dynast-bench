# GraphQL Version - Vulnerable App Plan

> ⚠️ **Intentionally vulnerable. Local only.** Binds `127.0.0.1`, ships a LOUD
> banner, carries no real data. Built to benchmark DAST/SAST/LLM security tools.

**Angle:** the **pure-API, single-endpoint** app. There is no HTML UI and no REST
CRUD surface to crawl - almost everything lives behind one `POST /graphql`. A
crawler-only scanner sees a single route and scores near zero; a scanner that
introspects the schema, walks the type graph, and mutates *variables* rather than
query strings finds ~30 bugs. Signature bugs are the ones that only exist in
GraphQL: **field-level authorization holes** (object authorized, field isn't),
**nested-path authz bypass** (`me → organization → posts` skips the filter the
root `posts` query applies), **alias/batch amplification** that defeats
rate limiting, and **APQ cache poisoning**.

## Services (4 containers) - independent `docker-compose.yml`

| Service     | Image                    | Host port | Purpose                                    |
|-------------|--------------------------|-----------|--------------------------------------------|
| app         | build ./ (node:22-slim)  | 3000      | Apollo Server 4 - `/graphql` + `/graphql/ws` |
| postgres    | postgres:16.4            | 5432      | Data                                       |
| redis       | redis:7.4.0              | 6379      | APQ cache, rate-limit counters, sub pub/sub |
| billing-svc | build ./billing (node)   | *internal only* | Internal REST API - SSRF target + cross-service taint |

`billing-svc` publishes **no host port**. It is only reachable from inside the
compose network, which is exactly what makes the SSRF chain worth something.

## Stack choices (bugs live inside these idioms)

- **Apollo Server 4** (`@apollo/server` standalone over `node:http`), TypeScript,
  schema-first SDL, resolvers split per type - so field resolvers are separate
  functions from the root query resolvers (that separation *is* the field-authz
  bug)
- DB: **Prisma**; typed queries in most resolvers, `$queryRawUnsafe` behind the
  `filter`/`orderBy` arguments and the report runner
- Auth: `context()` builds the viewer from a `Authorization: Bearer <jwt>`
  header (`jsonwebtoken`, hardcoded secret) **or** a session cookie; a
  `@auth(requires: Role)` schema directive exists and is applied inconsistently
- **Subscriptions**: `graphql-ws` over `/graphql/ws`, fan-out via Redis pub/sub
- **APQ** (automatic persisted queries) enabled with the Redis cache backend
- Uploads: `graphql-upload` `Upload` scalar for avatars/attachments
- Pagination: Relay-style connections + a `node(id: ID!)` root field that decodes
  opaque base64 global IDs (`UG9zdDoz` → `Post:3`)
- **Verification API stays REST** (`GET /api/_verify/health|user|post`, header
  `X-Verify-Token: benchsecret`) per the shared repo convention - it is the only
  non-GraphQL surface besides an `/auth/callback` shim

## Domain model

Standard shared domain (`Org → Team → Project → Post → Comment/Attachment`,
`Users` with roles, `Invitations`, `Webhooks`, `Reports`) expressed as a GraphQL
schema. Cross-tenant `user2` in org Globex; the Globex DRAFT carrying
`GLOBEX-CONFIDENTIAL-MARKER-7f3a` is reachable only through SQLi, the `node()`
IDOR, or the nested-path authz bypass.

## Vulnerability catalog (~31 planted bugs)

| Service · Feature | Planted bug | CWE | OWASP | Sev | Diff | Taint |
|---|---|---|---|---|---|---|
| app · server config | **Introspection enabled** in production | 200 | A05 | M | E | config |
| app · server config | Field **suggestions** leak type/field names even with introspection off | 200 | A05 | L | M | in-file |
| app · server config | No **query depth limit** → recursive nesting DoS | 770/674 | A04 | M | E-M | in-file |
| app · server config | No **cost/complexity limit**; `first:` unbounded | 770/400 | A04 | M | M | in-file |
| app · login | **Alias amplification** - 500 aliased `login` in one doc beats the rate limiter | 307/770 | A07 | H | H | cross-file |
| app · transport | **Array batching** (`[{q},{q}]`) bypasses per-request throttle | 770 | A04 | M | M-H | in-file |
| app · transport | Auth context built **once per batch** → op #1's viewer applied to op #2 | 863 | A01 | H | H | cross-file |
| app · APQ | Client `sha256Hash` never verified against the query → **cache poisoning** | 345/349 | A08 | H | H | cross-service |
| app · transport | GET queries + `csrfPrevention: false` → **CSRF** on mutations | 352 | A01 | M | M | in-file |
| app · errors | `formatError` returns stack + SQL + `originalError` | 209 | A05 | L | E | in-file |
| app · landing page | Local landing page + tracing extension enabled in prod | 489/200 | A05 | L | E | config |
| app · `node(id:)` | **Global-ID IDOR** - base64 `Post:3` decoded, no org check | 639/863 | A01 | H | E-M | in-file |
| app · `User` fields | **Field-level authz gap** - `passwordHash`/`resetToken`/`email` resolvable | 863/200 | A01 | H | M-H | cross-file |
| app · `Organization.posts` | **Nested-path bypass** - root `posts` filters by org, the field resolver doesn't | 863 | A01 | H | H | cross-file |
| app · `deleteOrganization` | Missing `@auth(requires: ADMIN)` on one mutation (BFLA) | 862 | A01 | H | M | in-file |
| app · `updateProfile` | **Mass assignment** - input spread into `prisma.user.update` | 915 | A01 | M | M | in-file |
| app · subscriptions | `postUpdated(orgId:)` authorizes in `resolve`, not `subscribe` | 863 | A01 | H | H | cross-service |
| app · `posts(filter:)` | **SQLi** via `orderBy`/`filter` string into `$queryRawUnsafe` | 89 | A03 | H | E | in-file |
| app · `reportRun` | **Second-order SQLi** via stored report name | 89 | A03 | H | H | cross-file |
| app · `JSONObject` scalar | Custom scalar skips validation → operator/`where` injection | 943/20 | A03 | M | M-H | cross-file |
| app · `exportReport` | Command injection (`exec("sh -c …")` on `format`) | 78 | A03 | C | M | in-file |
| app · `/api/export?format=html` | Stored **XSS** - comment body returned as `text/html`, unescaped | 79 | A03 | M | M | cross-file |
| app · JWT | Hardcoded secret; `alg:none` accepted; `exp` unchecked | 321/347 | A07 | H | M | in-file |
| app · `login` | No rate limit; user enumeration via `extensions.code` | 307/204 | A07 | M | E | in-file |
| app · `linkPreview(url:)` | **SSRF** → `billing-svc` / `169.254.169.254` | 918 | A10 | H | M-H | cross-service |
| app · `Upload` scalar | Unrestricted type + traversal in `filename` | 434/22 | A05 | M | M | in-file |
| app · `/auth/callback` | Open redirect via `?next=` | 601 | A01 | L | E | in-file |
| app · CORS | Reflects `Origin` + `Allow-Credentials: true` on `/graphql` | 942 | A05 | M | M | in-file |
| app · `purchaseSeats` | Negative/huge `quantity` accepted | 840 | A04 | M | M | in-file |
| app · `inviteUser` | **Race condition** exceeds seat limit | 362 | A04 | H | H | in-file |
| seed data | Default `admin/admin` service creds | 798 | A07 | M | E | in-file |

Roughly 8 Easy smoke-test rows, a thick Medium core, and ~7 Hard bugs (batch
auth carry-over, APQ poisoning, alias amplification, nested-path bypass,
subscription authz, second-order SQLi, invite race) that set the ceiling.

## Stack-specific highlights (only make sense in GraphQL)

- **Field-level authz gap.** `Query.user(id:)` correctly checks org membership,
  so the *object* is authorized - but `User.passwordHash` and `User.resetToken`
  are plain field resolvers with no check. Reach them sideways:
  `{ posts { author { passwordHash resetToken } } }`. Object-level scanners pass;
  field-level ones catch it. The near-miss is `Viewer.email`, which carries
  `@auth`.
- **Nested-path bypass.** `Query.posts` filters `where: { orgId: viewer.orgId }`.
  `Organization.posts` does not. `{ me { organization { posts { body } } } }`
  reads Globex's DRAFT and returns the marker. Same data, two paths, one
  filtered - this is the canonical GraphQL authz failure and needs graph
  traversal, not route enumeration, to find.
- **Alias amplification + array batching.** The rate limiter counts *HTTP
  requests*. One document with 500 aliased `login` fields is one request, so
  brute-forcing the weak `admin/admin` cred takes a single POST. Array batching
  is the same trick at the transport layer.
- **Batched auth carry-over.** `context()` runs once per HTTP request, but the
  batch's second operation carries an `Authorization` header the server already
  consumed - the viewer resolved for operation #1 is reused, so an anonymous op
  batched behind an authenticated one inherits its session. Pure logic; no
  pattern to grep.
- **APQ cache poisoning.** The server stores `sha256Hash → query` without
  verifying the hash actually digests the query. An attacker registers a
  malicious document under the hash of a benign one; every later client sending
  that hash executes the attacker's query. Cross-service (the poison lives in
  Redis).
- **Introspection vs. suggestions.** Even with `introspection: false`, GraphQL's
  "Did you mean `passwordHash`?" error suggestions reconstruct the schema. Plant
  both so a scanner gets credit for the subtle one.

## Near-misses (safe beside vulnerable)

- `Query.posts` (org-filtered) beside `Organization.posts` (unfiltered field resolver).
- `Viewer.email` (`@auth` directive) beside `User.email` (no directive).
- `listPosts` (`$queryRaw` tagged template) beside `searchPosts` (`$queryRawUnsafe`).
- `/graphql/public` - same schema, depth + cost limited, introspection off -
  beside the unlimited `/graphql`.
- `fetchInternal(url)` (allowlist + private-IP block) beside `linkPreview(url)`.
- `Mutation.updateEmail` (explicit field copy) beside `Mutation.updateProfile`
  (input spread).

## Logic-only bugs (no pattern to grep)

- **Batch auth carry-over (CWE-863):** PoC posts `[{anonymous op}, {authed op}]`
  in both orders and asserts the anonymous op returns admin-only data.
- **Invite race (CWE-362):** N concurrent `inviteUser` mutations beat the seat
  limit; check-then-insert is not transactional.
- **Alias amplification (CWE-307):** one document, 500 aliased logins, asserts
  the rate limiter never fires and one alias returns a token.
- **Seats (CWE-840):** `purchaseSeats(quantity: -5)` flips the balance.

## Ground truth & scoring

- `ground-truth/VULNERABILITIES.yaml` - one entry per row, standard schema. The
  `route` field carries the operation instead of a path, e.g.
  `"POST /graphql {query Organization.posts}"`, so the scorer can still match on
  a string. Optional additive keys for this app: `graphql_op` (root field) and
  `graphql_kind` (`query|mutation|subscription`) - the shared scorer ignores
  unknown keys.
- `ground-truth/verify/*.sh` - plain `curl` with a JSON body is enough for
  everything except subscriptions; those use a tiny `gqlws.mjs` helper built on
  Node 22's global `WebSocket` (no dependency). Examples: `introspect_001.sh`
  greps `__schema` from the response; `fieldauthz_001.sh` walks
  `posts→author→passwordHash`; `nested_authz_001.sh` greps the Globex marker;
  `apq_001.sh` registers a poisoned hash then replays it; `batchauth_001.sh`
  posts a two-op array. Exit `0` = exploitable.
- `make verify` on `vuln/` → all exploitable; `make validate` → all fixed on
  `safe/`. `ground-truth/` never enters a build context.

## Patched twin (`safe/`)

Introspection + suggestions off in production, depth (10) and cost limits,
operation-count cap per document and per batch, per-operation rate limiting keyed
on client + operation, APQ hash verified against the document, `csrfPrevention`
on and GET restricted to queries, generic `formatError`, landing page and tracing
removed, `node()` re-checks org after decoding, `@auth` on every sensitive field,
`Organization.posts` filtered like the root query, admin directive on
`deleteOrganization`, explicit field copy in `updateProfile`, subscription authz
moved into `subscribe`, `$queryRaw` tagged templates, validated scalar, arg-array
`execFile`, escaped HTML export, verified JWT with an env secret, SSRF allowlist +
metadata block, MIME/size/filename checks on upload, redirect allowlist, locked
CORS, validated seat math, atomic seat reservation, rotated seed cred.

## Compose sketch (independent; 127.0.0.1 only)

```yaml
name: vuln-graphql
services:
  app:
    build: ./
    ports: ["127.0.0.1:${DYNAST_PORT:-13311}:3000"]
    environment:
      DATABASE_URL: postgresql://bench:bench@postgres:5432/bench
      REDIS_URL: redis://redis:6379
      BILLING_URL: http://billing-svc:9099        # internal-only SSRF target
      JWT_SECRET: "hardcoded-weak-secret"          # planted CWE-798
      GRAPHQL_INTROSPECTION: "true"                # planted CWE-200
      APQ_VERIFY_HASH: "false"                     # planted CWE-345
    depends_on:
      postgres: { condition: service_healthy }
      redis:    { condition: service_healthy }
  postgres:
    image: postgres:16.4
    environment: { POSTGRES_USER: bench, POSTGRES_PASSWORD: bench, POSTGRES_DB: bench }
    healthcheck: { test: ["CMD-SHELL", "pg_isready -U bench"] }
  redis:
    image: redis:7.4.0
    healthcheck: { test: ["CMD", "redis-cli", "ping"] }
  billing-svc:
    build: ./billing            # NO host port - reachable only via SSRF
    expose: ["9099"]
```

Standalone (`make solo`) collapses this into one image: `internal-sink.mjs`
impersonates `billing-svc` on `127.0.0.1:9099`, and the entrypoint aliases
`postgres`/`redis`/`billing-svc` to localhost in `/etc/hosts` so config and PoCs
are byte-identical to compose mode.

## Build milestones

1. Compose + healthchecks + Makefile; Prisma schema + seed (cross-tenant Globex
   draft with the marker, weak service cred); REST `/api/_verify/*` green.
2. Schema + resolvers + auth context (JWT/session), subscriptions over
   `graphql-ws`, APQ on Redis. Plant the transport-layer bugs (introspection,
   suggestions, no depth/cost limit, batching, CSRF, APQ) with the
   `/graphql/public` near-miss endpoint.
3. Posts/users/orgs resolvers: `node()` IDOR, field-authz gap, nested-path
   bypass, mass assignment - each beside its filtered/`@auth`ed twin.
4. Injection seam: `filter`/`orderBy` SQLi, second-order report SQLi, scalar
   injection, `exec` export, HTML export XSS.
5. Logic bugs: batch auth carry-over, alias amplification, invite race, seat
   math. SSRF `linkPreview` → `billing-svc`; upload, redirect, CORS.
6. `VULNERABILITIES.yaml` + every `verify/` PoC exploitable on `vuln/`; copy to
   `safe/`, fix only the named lines, `make validate` + `make solo` green.
