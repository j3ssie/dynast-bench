# WebSocket / Realtime Version - Vulnerable App Plan

> ⚠️ **Intentionally vulnerable. Local only.** Binds `127.0.0.1`, ships a LOUD
> banner, carries no real data. Built to benchmark DAST/SAST/LLM security tools.

**Angle:** the **protocol-coverage** app. Nearly every sink sits behind a
WebSocket frame, not an HTTP request - so a scanner that can't speak WS finds
the three HTTP bugs and misses the other ~27. Signature bugs are the ones that
only exist on this transport: **Cross-Site WebSocket Hijacking** (no `Origin`
check on the handshake), **auth bypass by transport downgrade** (Socket.IO's
HTTP long-polling path skips the auth run on the upgrade path),
**message-type BFLA** (a JSON `type` field is the real router, and one type has
no role check), and **channel-subscribe BOLA** (subscribe to another tenant's
room and read its stream).

Two WS surfaces on purpose: a **raw `ws` JSON-protocol endpoint** and a
**Socket.IO 4** namespace pair. They give natural near-miss pairs (one validates
`Origin`, one doesn't) and they exercise the two protocols a realtime-aware
scanner has to handle.

## Services (4 containers) - independent `docker-compose.yml`

| Service      | Image                   | Host port | Purpose                                     |
|--------------|-------------------------|-----------|---------------------------------------------|
| app          | build ./ (node:22-slim) | 3000      | `node:http` + `ws` (`/ws`) + Socket.IO (`/socket.io`) |
| postgres     | postgres:16.4           | 5432      | Data                                        |
| redis        | redis:7.4.0             | 6379      | Pub/sub fan-out across rooms + presence     |
| internal-svc | build ./internal (node) | *internal only* | Internal REST API - SSRF target + cross-service taint |

## Stack choices (bugs live inside these idioms)

- **Bare Node 22 + TypeScript** - no web framework. `node:http` serves a thin
  HTTP surface; `ws` handles `/ws`; **Socket.IO 4** mounts `/rt` (user) and
  `/admin` (privileged) namespaces on the same server
- **Protocol:** JSON frames `{ "id": 1, "type": "post.search", "data": {…} }`,
  dispatched through a `handlers` map keyed on `type` - the map *is* the route
  table, and it is invisible to an HTTP crawler
- DB: **`pg`** directly; parameterized in most handlers, string-concatenated in
  the search handler
- Auth: `POST /api/auth/login` (HTTP) mints a **WS ticket**; the ticket is
  accepted from `?token=`, from `Sec-WebSocket-Protocol`, or from a cookie -
  three intake paths, differently validated
- Fan-out: Redis pub/sub; channel names are built from a client-supplied string
- HTTP surface is deliberately tiny: `/api/auth/login`, `/api/health`,
  `/api/rooms/:id/transcript` (the stored-XSS sink), and the shared REST
  verification API `GET /api/_verify/health|user|post` behind
  `X-Verify-Token: benchsecret`

## Domain model

Standard shared domain, mapped onto realtime concepts: an `Organization` owns
`rooms` (`org:acme:posts`, `org:globex:posts`), posts/comments stream as events,
presence carries user profile state. Cross-tenant `user2` lives in Globex; the
Globex DRAFT carrying `GLOBEX-CONFIDENTIAL-MARKER-7f3a` is reachable by
subscribing to Globex's channel, by the WS SQLi, or by the `post.get` IDOR.

## Vulnerability catalog (~32 planted bugs)

| Service · Feature | Planted bug | CWE | OWASP | Sev | Diff | Taint |
|---|---|---|---|---|---|---|
| app · `/ws` handshake | **CSWSH** - no `Origin` validation on upgrade | 1385/352 | A01 | H | M | in-file |
| app · socket.io | Auth in `allowRequest` runs only on `transport=websocket`; **polling bypasses it** | 287/288 | A07 | C | H | cross-file |
| app · ticket | Ticket is `base64(userId:timestamp)` - forgeable, no signature | 330/798 | A07 | H | M | in-file |
| app · ticket | Accepted from `?token=` → leaks into access logs / `Referer` | 598/532 | A09 | M | E-M | in-file |
| app · session | Authenticated at handshake only; `exp` never re-checked on a live socket | 613 | A07 | M | M-H | in-file |
| app · reconnect | `sid` resume restores a privileged session without re-auth | 384 | A07 | H | H | cross-file |
| app · subprotocol | `Sec-WebSocket-Protocol: admin-v1` selects the privileged handler map | 290/862 | A01 | H | M-H | in-file |
| app · socket.io `/admin` | Namespace has no connection-level authz | 306/862 | A01 | H | M | in-file |
| app · `subscribe` | **Channel BOLA** - `org:globex:posts` accepted with no membership check | 863 | A01 | H | M-H | in-file |
| app · `subscribe` | Wildcard `org:*` accepted → firehose across tenants | 863 | A01 | H | H | in-file |
| app · `subscribe` | Client-controlled Redis channel reaches `internal:billing` | 863/441 | A01 | H | H | cross-service |
| app · `chat.send` | Client-supplied `from`/`userId` trusted → impersonation | 290 | A01 | M | M | in-file |
| app · `admin.userDelete` | Message-type handler with no role check (BFLA) | 862 | A01 | H | M-H | in-file |
| app · `post.get` | IDOR - no org check on the id | 639 | A01 | H | M | in-file |
| app · `post.search` | **SQLi** over WS (string-concat into `pg`) | 89 | A03 | H | M-H | in-file |
| app · `sub.filter` | `new Function(expr)` on a subscription filter → **RCE** | 94/95 | A03 | C | H | cross-file |
| app · `presence.update` | **Prototype pollution** - deep-merge payload into shared session state | 1321 | A08 | H | H | cross-file |
| app · `webhook.test` | **SSRF** → `internal-svc` / `169.254.169.254` | 918 | A10 | H | M-H | cross-service |
| app · `file.get` | Path traversal via `name` | 22 | A01 | M | M | in-file |
| app · transcript | Stored **XSS** - WS message body served as `text/html`, unescaped | 79 | A03 | M | M | cross-file |
| app · audit log | CRLF/log injection via `presence.name` | 117 | A09 | L | M | cross-file |
| app · `ws` server | `maxPayload` disabled → unbounded frame, memory exhaustion | 400/770 | A04 | M | E-M | in-file |
| app · `ws` server | No per-connection message rate limit | 770 | A04 | M | M | in-file |
| app · `ws` server | No ping/pong idle timeout; unbounded connections per IP | 400 | A04 | M | M | in-file |
| app · rooms | Unbounded room creation on `subscribe` → memory growth | 770 | A04 | L | M | in-file |
| app · fan-out | Sockets never leave rooms → broadcast amplification | 400 | A04 | M | H | cross-file |
| app · errors | Stack traces + SQL echoed in the error frame | 209 | A05 | L | E-M | in-file |
| app · socket.io CORS | `cors: { origin: true, credentials: true }` | 942 | A05 | M | M | in-file |
| app · cookie | Session cookie without `Secure`/`SameSite`; `ws://` accepted with creds | 319/1275 | A02 | M | E-M | config |
| app · `billing.seats` | Negative/huge `quantity` accepted | 840 | A04 | M | M | in-file |
| app · `invite.create` | **Race condition** exceeds seat limit across two sockets | 362 | A04 | H | H | in-file |
| seed data | Default `admin/admin` service creds | 798 | A07 | M | E | in-file |

## Stack-specific highlights (only make sense over WebSockets)

- **CSWSH (CWE-1385).** The `/ws` upgrade handler never inspects `Origin`, and
  the session cookie is `SameSite=None`. Any page the victim visits can open
  `new WebSocket("ws://127.0.0.1:13311/ws")`, inherit the cookie, and read the
  victim's stream. It is the WebSocket answer to CSRF and it is invisible to a
  same-origin crawler. The near-miss `/ws/secure` checks `Origin` against an
  allowlist *and* binds the ticket to the session.
- **Transport-downgrade auth bypass.** Socket.IO's Engine.IO layer speaks HTTP
  long-polling before it upgrades. Auth is implemented in a `wsServer.on("upgrade")`
  hook, so `GET /socket.io/?EIO=4&transport=polling` establishes an
  authenticated-by-default session with plain `curl` - no WebSocket client
  required. Highest-severity row in the app, and the one bug here a purely
  HTTP scanner *can* find if it is looking.
- **The `type` field is the route table.** `admin.userDelete`, `admin.roleSet`,
  and `billing.seats` are endpoints in every sense except that no HTTP crawler
  will ever enumerate them. Finding them requires reading the handler map (SAST)
  or fuzzing the protocol (DAST). Grading which tools do either is the point of
  the app.
- **Subscribe-side authz.** Authorization is applied when a message is
  *published* but not when a client *subscribes*, so a Globex-scoped event
  reaches an Acme socket that asked for it. Same failure shape as GraphQL
  subscriptions, different transport.
- **Filter expressions.** "Only notify me when `post.priority > 3`" is a real
  product feature; implementing it with `new Function` is a real mistake. The
  safe twin parses the expression into a tiny allowlisted AST.
- **Stateful bugs need a stateful scanner.** Session-resume, expiry-never-checked,
  and room-leak amplification only appear across *sequences* of frames on one
  connection. Single-request fuzzers cannot express them.

## Near-misses (safe beside vulnerable)

- `/ws` (no `Origin` check) beside `/ws/secure` (allowlist + ticket bound to session).
- `post.search` (concat) beside `post.list` (`$1` placeholders).
- `mergePresence` (deep merge) beside `applyPresence` (allowlist copy).
- `subscribeChannel` (raw name) beside `subscribeOrgChannel` (membership-checked,
  channel name derived server-side from the viewer's org).
- Socket.IO `/rt` namespace (per-event authz middleware) beside `/admin` (none).
- `evalFilter` (`new Function`) beside `parseFilter` (allowlisted comparison AST).

## Logic-only bugs (no pattern to grep)

- **Invite race (CWE-362):** two sockets fire `invite.create` concurrently; the
  seat check and insert are not atomic. PoC opens N connections and asserts final
  seats > limit.
- **Session never expires (CWE-613):** PoC authenticates, waits past the ticket
  `exp`, and asserts privileged frames still succeed.
- **Room-leak amplification (CWE-400):** join/leave repeatedly, then assert one
  publish delivers N copies.
- **Seats (CWE-840):** `billing.seats` with `quantity: -5`.

## Ground truth, PoC tooling & scoring

Most PoCs need a WebSocket client, so `ground-truth/verify/_lib.sh` gains a
`ws.mjs` helper built on **Node 22's global `WebSocket`** - no npm dependency,
no `websocat` assumption:

```sh
# connect, send frames, print every frame received, exit after N or on timeout
node ground-truth/verify/ws.mjs "$TARGET_WS/ws" --token "$TICKET" \
     --send '{"id":1,"type":"post.search","data":{"q":"'"'"' OR 1=1--"}}'
```

Three PoCs stay pure `curl`, which is deliberate - they are the bugs an
HTTP-only scanner *should* still catch:

- `cswsh_001.sh` - raw handshake with `Origin: http://evil.local` and a
  `Sec-WebSocket-Key`, asserts `101 Switching Protocols`.
- `downgrade_001.sh` - `GET /socket.io/?EIO=4&transport=polling`, asserts an
  authenticated `sid` comes back without a ticket.
- `xss_stored_001.sh` - posts through WS, then greps the raw payload out of
  `GET /api/rooms/:id/transcript`.

`VULNERABILITIES.yaml` uses the standard schema; `route` carries the frame, e.g.
`"WS /ws {type: admin.userDelete}"`. Optional additive key for this app:
`transport: http | ws | socketio-polling | socketio-ws` - useful for reporting
detection rate by protocol, and ignored by the shared scorer. PoCs are
order-independent; the prototype-pollution PoC self-cleans, and the seat PoCs
restore counters.

## Patched twin (`safe/`)

`Origin` allowlist + signed, single-use, session-bound tickets on every intake
path; auth moved into Socket.IO middleware so it runs on **both** transports;
ticket `exp` re-validated per frame; resume requires re-auth; subprotocol no
longer selects a handler map; `/admin` namespace gated on role; server-derived
channel names + membership checks; wildcard subscribe rejected; `from` taken from
the session, never the frame; role check on every `admin.*` handler; org check in
`post.get`; `$1` placeholders; allowlisted filter AST; allowlist-copy presence
merge; SSRF allowlist + metadata block; `path.resolve` containment; escaped
transcript; sanitized log fields; `maxPayload` 64 KB; per-connection token
bucket; ping/pong timeout + per-IP connection cap; room cap and leave-on-unsub;
generic error frames; locked CORS; `Secure`+`SameSite=Lax` cookie; validated seat
math; atomic seat reservation; rotated seed cred.

## Compose sketch (independent; 127.0.0.1 only)

```yaml
name: vuln-websocket
services:
  app:
    build: ./
    ports: ["127.0.0.1:${DYNAST_PORT:-13311}:3000"]
    environment:
      DATABASE_URL: postgres://bench:bench@postgres:5432/bench
      REDIS_URL: redis://redis:6379
      INTERNAL_URL: http://internal-svc:9099       # internal-only SSRF target
      TICKET_SECRET: "hardcoded-ticket-secret"      # planted CWE-798
      WS_CHECK_ORIGIN: "false"                      # planted CWE-1385
      WS_MAX_PAYLOAD: "0"                           # planted CWE-400
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
  internal-svc:
    build: ./internal          # NO host port - reachable only via SSRF
    expose: ["9099"]
```

`make solo` folds all four into one image; `internal-sink.mjs` stands in for
`internal-svc` on `127.0.0.1:9099` and the entrypoint aliases the service names
to localhost so PoCs and config are unchanged.

## Build milestones

1. Compose + healthchecks + Makefile; schema + seed (Globex marker draft, weak
   service cred); HTTP `/api/health` + `/api/_verify/*` green so the compose
   healthcheck works without a WS client.
2. Transport layer: `ws` on `/ws`, Socket.IO `/rt` + `/admin`, ticket mint/verify
   with all three intake paths. Plant CSWSH, transport downgrade, forgeable
   ticket, subprotocol handler swap - with `/ws/secure` as the near-miss.
3. Handler map + Redis fan-out: subscribe BOLA, wildcard, internal-channel reach,
   `post.get` IDOR, `admin.*` BFLA, impersonation.
4. Injection seam over WS: `post.search` SQLi, `new Function` filter RCE,
   presence prototype pollution, `webhook.test` SSRF, `file.get` traversal,
   transcript XSS, log injection.
5. Resource limits removed deliberately (payload/rate/idle/rooms/amplification);
   logic bugs (session expiry, resume, invite race, seat math); CORS + cookie
   flags.
6. `ws.mjs` helper + `VULNERABILITIES.yaml` + every PoC exploitable on `vuln/`;
   copy to `safe/`, fix only the named lines, `make validate` + `make solo` green.
